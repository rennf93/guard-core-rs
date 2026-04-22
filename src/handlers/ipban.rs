//! IP-ban manager backing the auto-ban and dynamic-rule features.

use std::sync::Arc;

use moka::future::Cache;
use serde_json::{Value, json};
use tracing::error;

use crate::error::Result;
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;

/// Tracks banned IPs across in-memory LRU cache and optional Redis backend.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::handlers::ipban::IPBanManager;
///
/// # async fn run() {
/// let manager = Arc::new(IPBanManager::new());
/// let _ = manager.ban_ip("203.0.113.42", 3600, "manual").await;
/// # }
/// ```
pub struct IPBanManager {
    banned_ips: Cache<String, f64>,
    redis_handler: parking_lot::RwLock<Option<DynRedisHandler>>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
}

impl std::fmt::Debug for IPBanManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IPBanManager")
            .field("size", &self.banned_ips.entry_count())
            .finish()
    }
}

impl Default for IPBanManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IPBanManager {
    /// Creates a fresh manager with a 10k-entry LRU and a 1-hour TTL.
    pub fn new() -> Self {
        Self {
            banned_ips: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(std::time::Duration::from_secs(3600))
                .build(),
            redis_handler: parking_lot::RwLock::new(None),
            agent_handler: parking_lot::RwLock::new(None),
        }
    }

    /// Wires in the shared [`crate::protocols::redis::DynRedisHandler`] so
    /// bans survive restarts and are shared across replicas.
    pub async fn initialize_redis(&self, redis: DynRedisHandler) {
        *self.redis_handler.write() = Some(redis);
    }

    /// Wires in the [`crate::protocols::agent::DynAgentHandler`] used to
    /// emit ban/unban events.
    pub async fn initialize_agent(&self, agent: DynAgentHandler) {
        *self.agent_handler.write() = Some(agent);
    }

    /// Bans `ip` for `duration` seconds, recording `reason` on the emitted
    /// agent event.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when the optional
    /// Redis backend cannot be written to.
    pub async fn ban_ip(self: &Arc<Self>, ip: &str, duration: u64, reason: &str) -> Result<()> {
        let expiry = epoch_secs() + duration as f64;
        self.banned_ips.insert(ip.to_string(), expiry).await;

        let redis = self.redis_handler.read().clone();
        if let Some(redis) = redis {
            redis
                .set_key(
                    "banned_ips",
                    ip,
                    Value::String(expiry.to_string()),
                    Some(duration),
                )
                .await?;
        }

        let agent = self.agent_handler.read().clone();
        if let Some(agent) = agent {
            self.send_ban_event(&agent, ip, duration, reason).await;
        }
        Ok(())
    }

    async fn send_ban_event(
        &self,
        agent: &DynAgentHandler,
        ip: &str,
        duration: u64,
        reason: &str,
    ) {
        let event = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": "ip_banned",
            "ip_address": ip,
            "action_taken": "banned",
            "reason": reason,
            "metadata": { "duration": duration },
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send ban event to agent: {e}");
        }
    }

    /// Removes the ban for `ip` from every backing store.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when the optional
    /// Redis backend cannot be mutated.
    pub async fn unban_ip(&self, ip: &str) -> Result<()> {
        self.banned_ips.invalidate(ip).await;
        let redis = self.redis_handler.read().clone();
        if let Some(redis) = redis {
            redis.delete("banned_ips", ip).await?;
        }
        let agent = self.agent_handler.read().clone();
        if let Some(agent) = agent {
            let event = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event_type": "ip_unbanned",
                "ip_address": ip,
                "action_taken": "unbanned",
                "reason": "dynamic_rule_whitelist",
                "metadata": { "action": "unban" },
            });
            if let Err(e) = agent.send_event(event).await {
                error!("Failed to send unban event to agent: {e}");
            }
        }
        Ok(())
    }

    /// Returns `Ok(true)` when `ip` currently has an active ban.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when the optional
    /// Redis backend cannot be read.
    pub async fn is_ip_banned(&self, ip: &str) -> Result<bool> {
        let current_time = epoch_secs();

        if let Some(expiry) = self.banned_ips.get(ip).await {
            if current_time > expiry {
                self.banned_ips.invalidate(ip).await;
                return Ok(false);
            }
            return Ok(true);
        }

        let redis = self.redis_handler.read().clone();
        if let Some(redis) = redis {
            let value = redis.get_key("banned_ips", ip).await?;
            if let Some(v) = value {
                let expiry = parse_expiry(&v).unwrap_or(0.0);
                if current_time <= expiry {
                    self.banned_ips.insert(ip.to_string(), expiry).await;
                    return Ok(true);
                }
                redis.delete("banned_ips", ip).await?;
            }
        }

        Ok(false)
    }

    /// Empties every ban entry from the in-memory cache and Redis backend.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on Redis failure.
    pub async fn reset(&self) -> Result<()> {
        self.banned_ips.invalidate_all();
        self.banned_ips.run_pending_tasks().await;
        let redis = self.redis_handler.read().clone();
        if let Some(redis) = redis {
            if let Ok(keys) = redis.keys("banned_ips:*").await {
                for key in keys {
                    let _ = redis.delete("banned_ips", key.split(':').next_back().unwrap_or("")).await;
                }
            }
        }
        Ok(())
    }

    /// Returns the approximate number of currently cached bans.
    pub fn size(&self) -> u64 {
        self.banned_ips.entry_count()
    }
}

fn parse_expiry(value: &Value) -> Option<f64> {
    match value {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

fn epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
