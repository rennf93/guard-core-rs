#![cfg(feature = "redis-support")]
//! Redis connection manager implementing
//! [`crate::protocols::redis::RedisHandlerProtocol`].

use std::sync::Arc;

use async_trait::async_trait;
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::error::{GuardCoreError, GuardRedisError, Result};
use crate::models::SecurityConfig;
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::RedisHandlerProtocol;

/// Concrete Redis handler wrapping a
/// [`redis::aio::MultiplexedConnection`] and implementing
/// [`crate::protocols::redis::RedisHandlerProtocol`].
///
/// Construct with [`crate::handlers::redis::RedisManager::new`] and wire it
/// into the framework adapter's middleware.
pub struct RedisManager {
    config: Arc<SecurityConfig>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
    connection: Mutex<Option<MultiplexedConnection>>,
    closed: parking_lot::RwLock<bool>,
}

impl std::fmt::Debug for RedisManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisManager")
            .field("closed", &*self.closed.read())
            .finish_non_exhaustive()
    }
}

impl RedisManager {
    /// Creates a new manager bound to `config`.
    pub fn new(config: Arc<SecurityConfig>) -> Arc<Self> {
        Arc::new(Self {
            config,
            agent_handler: parking_lot::RwLock::new(None),
            connection: Mutex::new(None),
            closed: parking_lot::RwLock::new(false),
        })
    }

    /// Returns the shared [`crate::models::SecurityConfig`] reference.
    pub fn config(&self) -> Arc<SecurityConfig> {
        Arc::clone(&self.config)
    }

    /// Returns `true` when the manager has been closed via
    /// [`crate::protocols::redis::RedisHandlerProtocol::close`].
    pub fn is_closed(&self) -> bool {
        *self.closed.read()
    }

    /// Installs the Guard Agent handler used for Redis-related events.
    pub async fn initialize_agent(&self, agent: DynAgentHandler) {
        *self.agent_handler.write() = Some(agent);
    }

    async fn send_redis_event(&self, event_type: &str, action_taken: &str, reason: &str) {
        let Some(agent) = self.agent_handler.read().clone() else {
            return;
        };
        let event = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": event_type,
            "ip_address": "system",
            "action_taken": action_taken,
            "reason": reason,
            "metadata": {
                "redis_url": self.config.redis_url.clone().unwrap_or_default(),
            },
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send Redis event to agent: {e}");
        }
    }

    async fn acquire_connection(&self) -> Result<MultiplexedConnection> {
        {
            let guard = self.connection.lock().await;
            if let Some(conn) = guard.as_ref() {
                return Ok(conn.clone());
            }
        }
        self.initialize().await?;
        let guard = self.connection.lock().await;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| GuardCoreError::Redis(GuardRedisError::new(503, "Redis connection failed")))
    }

    fn full_key(&self, namespace: &str, key: &str) -> String {
        format!("{}{}:{}", self.config.redis_prefix, namespace, key)
    }

    /// Wraps an arbitrary Redis operation so that connection errors produce
    /// a 503 [`crate::error::GuardRedisError`] and event emission.
    ///
    /// Returns `Ok(None)` when Redis is disabled and the operation was
    /// skipped.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when `func` fails or
    /// the connection cannot be acquired.
    pub async fn safe_operation<F, Fut, T>(&self, func: F) -> Result<Option<T>>
    where
        F: FnOnce(MultiplexedConnection) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        if !self.config.enable_redis {
            return Ok(None);
        }
        match self.acquire_connection().await {
            Ok(conn) => match func(conn).await {
                Ok(v) => Ok(Some(v)),
                Err(e) => {
                    error!("Redis operation failed: {e}");
                    self.send_redis_event(
                        "redis_error",
                        "safe_operation_failed",
                        &format!("Redis safe operation failed: {e}"),
                    )
                    .await;
                    Err(GuardCoreError::Redis(GuardRedisError::new(
                        503,
                        "Redis operation failed",
                    )))
                }
            },
            Err(e) => Err(e),
        }
    }

    /// Atomically increments the counter under `namespace:key`, optionally
    /// setting a TTL in seconds on the first write.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on command failure.
    pub async fn incr(&self, namespace: &str, key: &str, ttl: Option<u64>) -> Result<Option<i64>> {
        if !self.config.enable_redis {
            return Ok(None);
        }
        let full_key = self.full_key(namespace, key);
        self.safe_operation(|mut conn| async move {
            let value: i64 = conn.incr(&full_key, 1).await?;
            if let Some(ttl) = ttl {
                let _: bool = conn.expire(&full_key, ttl as i64).await?;
            }
            Ok::<i64, GuardCoreError>(value)
        })
        .await
    }

    /// Returns [`Some(true)`](Some) when `namespace:key` exists.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on command failure.
    pub async fn exists(&self, namespace: &str, key: &str) -> Result<Option<bool>> {
        if !self.config.enable_redis {
            return Ok(None);
        }
        let full_key = self.full_key(namespace, key);
        self.safe_operation(|mut conn| async move {
            let value: bool = conn.exists(&full_key).await?;
            Ok::<bool, GuardCoreError>(value)
        })
        .await
    }

    /// Deletes every key matching the glob `pattern` (relative to the
    /// configured prefix).
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on command failure.
    pub async fn delete_pattern(&self, pattern: &str) -> Result<Option<u64>> {
        if !self.config.enable_redis {
            return Ok(None);
        }
        let full_pattern = format!("{}{}", self.config.redis_prefix, pattern);
        self.safe_operation(|mut conn| async move {
            let keys: Vec<String> = conn.keys(&full_pattern).await?;
            if keys.is_empty() {
                return Ok(0u64);
            }
            let count: u64 = conn.del(keys).await?;
            Ok::<u64, GuardCoreError>(count)
        })
        .await
    }
}

#[async_trait]
impl RedisHandlerProtocol for RedisManager {
    async fn initialize(&self) -> Result<()> {
        if *self.closed.read() || !self.config.enable_redis {
            let mut conn = self.connection.lock().await;
            *conn = None;
            return Ok(());
        }

        let Some(url) = self.config.redis_url.as_deref() else {
            warn!("Redis URL is None, skipping connection");
            return Ok(());
        };

        let client = redis::Client::open(url).map_err(|e| {
            GuardCoreError::Redis(GuardRedisError::new(503, format!("Redis open failed: {e}")))
        })?;
        match client.get_multiplexed_async_connection().await {
            Ok(mut mcon) => {
                let _: String = redis::cmd("PING")
                    .query_async(&mut mcon)
                    .await
                    .map_err(|e| GuardCoreError::Redis(GuardRedisError::new(503, e.to_string())))?;
                let mut guard = self.connection.lock().await;
                *guard = Some(mcon);
                info!("Redis connection established");
                drop(guard);
                self.send_redis_event(
                    "redis_connection",
                    "connection_established",
                    "Redis connection successfully established",
                )
                .await;
                Ok(())
            }
            Err(e) => {
                error!("Redis connection failed: {e}");
                self.send_redis_event(
                    "redis_error",
                    "connection_failed",
                    &format!("Redis connection failed: {e}"),
                )
                .await;
                {
                    let mut guard = self.connection.lock().await;
                    *guard = None;
                }
                Err(GuardCoreError::Redis(GuardRedisError::new(
                    503,
                    "Redis connection failed",
                )))
            }
        }
    }

    async fn get_key(&self, namespace: &str, key: &str) -> Result<Option<Value>> {
        if !self.config.enable_redis {
            return Ok(None);
        }
        let full_key = self.full_key(namespace, key);
        match self
            .safe_operation(|mut conn| async move {
                let value: Option<String> = conn.get(&full_key).await?;
                Ok::<Option<String>, GuardCoreError>(value)
            })
            .await?
        {
            Some(Some(s)) => Ok(Some(
                serde_json::from_str(&s).unwrap_or(Value::String(s)),
            )),
            _ => Ok(None),
        }
    }

    async fn set_key(
        &self,
        namespace: &str,
        key: &str,
        value: Value,
        ttl: Option<u64>,
    ) -> Result<bool> {
        if !self.config.enable_redis {
            return Ok(false);
        }
        let full_key = self.full_key(namespace, key);
        let serialized = if let Value::String(s) = &value {
            s.clone()
        } else {
            value.to_string()
        };
        let result = self
            .safe_operation(|mut conn| async move {
                let outcome = if let Some(ttl) = ttl {
                    let _: String = conn.set_ex(&full_key, &serialized, ttl).await?;
                    true
                } else {
                    let _: String = conn.set(&full_key, &serialized).await?;
                    true
                };
                Ok::<bool, GuardCoreError>(outcome)
            })
            .await?;
        Ok(result.unwrap_or(false))
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<u64> {
        if !self.config.enable_redis {
            return Ok(0);
        }
        let full_key = self.full_key(namespace, key);
        let result = self
            .safe_operation(|mut conn| async move {
                let count: u64 = conn.del(&full_key).await?;
                Ok::<u64, GuardCoreError>(count)
            })
            .await?;
        Ok(result.unwrap_or(0))
    }

    async fn keys(&self, pattern: &str) -> Result<Vec<String>> {
        if !self.config.enable_redis {
            return Ok(Vec::new());
        }
        let full_pattern = format!("{}{}", self.config.redis_prefix, pattern);
        let result = self
            .safe_operation(|mut conn| async move {
                let keys: Vec<String> = conn.keys(&full_pattern).await?;
                Ok::<Vec<String>, GuardCoreError>(keys)
            })
            .await?;
        Ok(result.unwrap_or_default())
    }

    async fn incr(&self, namespace: &str, key: &str, amount: i64) -> Result<i64> {
        if !self.config.enable_redis {
            return Ok(0);
        }
        let full_key = self.full_key(namespace, key);
        let result = self
            .safe_operation(move |mut conn| async move {
                let value: i64 = conn.incr(&full_key, amount).await?;
                Ok::<i64, GuardCoreError>(value)
            })
            .await?;
        Ok(result.unwrap_or(0))
    }

    async fn expire(&self, namespace: &str, key: &str, ttl: u64) -> Result<bool> {
        if !self.config.enable_redis {
            return Ok(false);
        }
        let full_key = self.full_key(namespace, key);
        let result = self
            .safe_operation(move |mut conn| async move {
                let ok: bool = conn.expire(&full_key, ttl as i64).await?;
                Ok::<bool, GuardCoreError>(ok)
            })
            .await?;
        Ok(result.unwrap_or(false))
    }

    async fn run_script(&self, script: &str, keys: Vec<String>, args: Vec<String>) -> Result<Value> {
        if !self.config.enable_redis {
            return Ok(Value::Null);
        }
        let script_str = script.to_string();
        let result = self
            .safe_operation(move |mut conn| async move {
                let script = redis::Script::new(&script_str);
                let mut cmd = script.prepare_invoke();
                for k in keys {
                    cmd.key(k);
                }
                for a in args {
                    cmd.arg(a);
                }
                let value: redis::Value = cmd.invoke_async(&mut conn).await?;
                Ok::<redis::Value, GuardCoreError>(value)
            })
            .await?;
        Ok(result.map_or(Value::Null, redis_value_to_json))
    }

    async fn close(&self) -> Result<()> {
        let mut guard = self.connection.lock().await;
        if guard.is_some() {
            *guard = None;
            info!("Redis connection closed");
            drop(guard);
            self.send_redis_event(
                "redis_connection",
                "connection_closed",
                "Redis connection closed gracefully",
            )
            .await;
        }
        *self.closed.write() = true;
        Ok(())
    }
}

fn redis_value_to_json(value: redis::Value) -> Value {
    use redis::Value as R;
    match value {
        R::Nil => Value::Null,
        R::Int(i) => Value::Number(serde_json::Number::from(i)),
        R::BulkString(bytes) => match String::from_utf8(bytes) {
            Ok(s) => serde_json::from_str(&s).unwrap_or(Value::String(s)),
            Err(e) => Value::String(String::from_utf8_lossy(e.as_bytes()).into_owned()),
        },
        R::SimpleString(s) => Value::String(s),
        R::Okay => Value::Bool(true),
        R::Array(vs) => Value::Array(vs.into_iter().map(redis_value_to_json).collect()),
        R::Set(vs) => Value::Array(vs.into_iter().map(redis_value_to_json).collect()),
        R::Map(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key = match k {
                    R::BulkString(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                    R::SimpleString(s) => s,
                    other => format!("{other:?}"),
                };
                map.insert(key, redis_value_to_json(v));
            }
            Value::Object(map)
        }
        R::Attribute { data, attributes: _ } => redis_value_to_json(*data),
        R::Push { kind: _, data } => Value::Array(data.into_iter().map(redis_value_to_json).collect()),
        R::Double(f) => serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number),
        R::Boolean(b) => Value::Bool(b),
        R::BigNumber(n) => Value::String(n.to_string()),
        R::VerbatimString { format: _, text } => Value::String(text),
        R::ServerError(err) => Value::String(format!("{err:?}")),
    }
}
