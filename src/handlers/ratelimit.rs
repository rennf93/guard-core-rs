//! Rate-limiting manager with optional Redis-backed distributed enforcement.

use std::collections::VecDeque;
use std::sync::Arc;

use dashmap::DashMap;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::error::Result;
use crate::models::{LogLevel, SecurityConfig};
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::scripts::rate_lua::RATE_LIMIT_SCRIPT;
use crate::utils::{LogType, get_pipeline_response_time, log_activity};

/// Async factory used by
/// [`crate::handlers::ratelimit::RateLimitManager`] to build the `429` response
/// emitted on violation.
pub type CreateErrorResponseFn = Arc<
    dyn Fn(u16, String) -> futures::future::BoxFuture<'static, Result<DynGuardResponse>>
        + Send
        + Sync,
>;

/// Borrowed input to
/// [`crate::handlers::ratelimit::RateLimitManager::check_rate_limit`].
pub struct CheckRateLimitArgs<'a> {
    /// Incoming request being counted.
    pub request: &'a DynGuardRequest,
    /// Resolved client IP used as the counter key.
    pub client_ip: &'a str,
    /// Factory producing the `429` response if the limit is breached.
    pub create_error_response: &'a CreateErrorResponseFn,
    /// Endpoint path component of the counter key (empty for global).
    pub endpoint_path: &'a str,
    /// Optional per-call limit override.
    pub rate_limit: Option<u32>,
    /// Optional per-call window override (seconds).
    pub rate_limit_window: Option<u64>,
}

impl std::fmt::Debug for CheckRateLimitArgs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckRateLimitArgs")
            .field("client_ip", &self.client_ip)
            .field("endpoint_path", &self.endpoint_path)
            .field("rate_limit", &self.rate_limit)
            .field("rate_limit_window", &self.rate_limit_window)
            .finish_non_exhaustive()
    }
}

struct RateLimitExceededArgs<'a> {
    request: &'a DynGuardRequest,
    client_ip: &'a str,
    count: i64,
    create_error_response: &'a CreateErrorResponseFn,
    rate_limit_window: u64,
}

/// Sliding-window rate limiter supporting both in-memory and Redis modes.
///
/// When Redis is configured the manager evaluates counts via the bundled
/// [`crate::scripts::rate_lua::RATE_LIMIT_SCRIPT`] Lua script. Otherwise a
/// per-process [`dashmap::DashMap`] of timestamp queues is used.
pub struct RateLimitManager {
    config: RwLock<Arc<SecurityConfig>>,
    request_timestamps: DashMap<String, VecDeque<f64>>,
    redis_handler: parking_lot::RwLock<Option<DynRedisHandler>>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
    rate_limit_script_loaded: parking_lot::RwLock<bool>,
}

impl std::fmt::Debug for RateLimitManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitManager")
            .field("tracked_clients", &self.request_timestamps.len())
            .finish()
    }
}

impl RateLimitManager {
    /// Creates a new manager bound to `config`.
    pub fn new(config: Arc<SecurityConfig>) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(config),
            request_timestamps: DashMap::new(),
            redis_handler: parking_lot::RwLock::new(None),
            agent_handler: parking_lot::RwLock::new(None),
            rate_limit_script_loaded: parking_lot::RwLock::new(false),
        })
    }

    /// Replaces the stored [`crate::models::SecurityConfig`] reference,
    /// typically after a dynamic-rule update.
    pub async fn update_config(&self, config: Arc<SecurityConfig>) {
        *self.config.write().await = config;
    }

    /// Installs the Redis handler and loads the sliding-window Lua script.
    pub async fn initialize_redis(&self, redis_handler: DynRedisHandler) {
        let redis_enabled = self.config.read().await.enable_redis;
        *self.redis_handler.write() = Some(redis_handler.clone());
        if redis_enabled {
            match redis_handler.run_script(RATE_LIMIT_SCRIPT, Vec::new(), Vec::new()).await {
                Ok(_) => {
                    *self.rate_limit_script_loaded.write() = true;
                    info!("Rate limiting Lua script loaded successfully");
                }
                Err(e) => error!("Failed to load rate limiting Lua script: {e}"),
            }
        }
    }

    /// Installs the Guard Agent handler used to emit rate-limit events.
    pub async fn initialize_agent(&self, agent_handler: DynAgentHandler) {
        *self.agent_handler.write() = Some(agent_handler);
    }

    async fn get_redis_request_count(
        &self,
        client_ip: &str,
        current_time: f64,
        window: u64,
        limit: u32,
        endpoint_path: &str,
    ) -> Option<i64> {
        let redis = self.redis_handler.read().clone()?;
        let cfg = self.config.read().await;
        let rate_key = if endpoint_path.is_empty() {
            format!("rate:{client_ip}")
        } else {
            format!("rate:{client_ip}:{endpoint_path}")
        };
        let key_name = format!("{}rate_limit:{}", cfg.redis_prefix, rate_key);
        drop(cfg);
        let args = vec![current_time.to_string(), window.to_string(), limit.to_string()];
        match redis.run_script(RATE_LIMIT_SCRIPT, vec![key_name], args).await {
            Ok(Value::Number(n)) => n.as_i64(),
            Ok(Value::String(s)) => s.parse::<i64>().ok(),
            Ok(_) => None,
            Err(e) => {
                error!("Redis rate limiting error: {e}");
                None
            }
        }
    }

    fn get_in_memory_request_count(
        &self,
        client_ip: &str,
        window_start: f64,
        current_time: f64,
        endpoint_path: &str,
    ) -> usize {
        let key = if endpoint_path.is_empty() {
            client_ip.to_string()
        } else {
            format!("{client_ip}:{endpoint_path}")
        };
        let mut entry = self.request_timestamps.entry(key).or_default();
        let queue = entry.value_mut();
        while queue.front().is_some_and(|&t| t <= window_start) {
            queue.pop_front();
        }
        let count = queue.len();
        queue.push_back(current_time);
        count
    }

    async fn handle_rate_limit_exceeded(
        &self,
        args: RateLimitExceededArgs<'_>,
    ) -> Result<DynGuardResponse> {
        let RateLimitExceededArgs {
            request,
            client_ip,
            count,
            create_error_response,
            rate_limit_window,
        } = args;
        let cfg = self.config.read().await;
        let passive_mode = cfg.passive_mode;
        let level = cfg.log_suspicious_level;
        drop(cfg);
        let reason = format!(
            "Rate limit exceeded for IP: {client_ip} ({count} requests in {rate_limit_window}s window)"
        );
        log_activity(
            request,
            LogType::Suspicious { reason: &reason, passive_mode, trigger_info: "" },
            level.or(Some(LogLevel::Warning)),
        )
        .await;
        let agent = self.agent_handler.read().clone();
        if let Some(agent) = agent {
            self.send_rate_limit_event(&agent, request, client_ip, count).await;
        }
        create_error_response(429, "Too many requests".into()).await
    }

    async fn send_rate_limit_event(
        &self,
        agent: &DynAgentHandler,
        request: &DynGuardRequest,
        client_ip: &str,
        request_count: i64,
    ) {
        let cfg = self.config.read().await;
        let event = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": "rate_limited",
            "ip_address": client_ip,
            "action_taken": "request_blocked",
            "reason": format!(
                "Rate limit exceeded: {request_count} requests in {}s window",
                cfg.rate_limit_window
            ),
            "endpoint": request.url_path(),
            "method": request.method(),
            "response_time": get_pipeline_response_time(Some(request)),
            "metadata": {
                "request_count": request_count,
                "rate_limit": cfg.rate_limit,
                "window": cfg.rate_limit_window,
            },
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send rate limit event to agent: {e}");
        }
    }

    /// Counts the request and returns a `429`
    /// [`crate::protocols::response::DynGuardResponse`] when the configured
    /// limit is breached.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when Redis is enabled
    /// and the script cannot be executed, or the error raised by the
    /// response factory.
    pub async fn check_rate_limit(
        &self,
        args: CheckRateLimitArgs<'_>,
    ) -> Result<Option<DynGuardResponse>> {
        let CheckRateLimitArgs {
            request,
            client_ip,
            create_error_response,
            endpoint_path,
            rate_limit,
            rate_limit_window,
        } = args;
        let cfg = self.config.read().await;
        if !cfg.enable_rate_limiting {
            return Ok(None);
        }
        let effective_limit = rate_limit.unwrap_or(cfg.rate_limit);
        let effective_window = rate_limit_window.unwrap_or(cfg.rate_limit_window);
        let enable_redis = cfg.enable_redis;
        drop(cfg);
        let current_time = epoch_secs();
        let window_start = current_time - effective_window as f64;

        if enable_redis && self.redis_handler.read().is_some() {
            let count = self
                .get_redis_request_count(
                    client_ip,
                    current_time,
                    effective_window,
                    effective_limit,
                    endpoint_path,
                )
                .await;
            if let Some(count) = count {
                if count > effective_limit as i64 {
                    return Ok(Some(
                        self.handle_rate_limit_exceeded(RateLimitExceededArgs {
                            request,
                            client_ip,
                            count,
                            create_error_response,
                            rate_limit_window: effective_window,
                        })
                        .await?,
                    ));
                }
                return Ok(None);
            }
        }

        let request_count = self.get_in_memory_request_count(
            client_ip,
            window_start,
            current_time,
            endpoint_path,
        );

        if request_count >= effective_limit as usize {
            return Ok(Some(
                self.handle_rate_limit_exceeded(RateLimitExceededArgs {
                    request,
                    client_ip,
                    count: (request_count + 1) as i64,
                    create_error_response,
                    rate_limit_window: effective_window,
                })
                .await?,
            ));
        }

        Ok(None)
    }

    /// Clears every counter (in-memory and Redis).
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on Redis failure.
    pub async fn reset(&self) -> Result<()> {
        self.request_timestamps.clear();
        let enable_redis = self.config.read().await.enable_redis;
        let redis = self.redis_handler.read().clone();
        if enable_redis
            && let Some(redis) = redis
        {
            let keys = redis.keys("rate_limit:rate:*").await.unwrap_or_default();
            if !keys.is_empty() {
                for k in keys {
                    let _ = redis.delete("", &k).await;
                }
            }
        }
        Ok(())
    }
}

fn epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
