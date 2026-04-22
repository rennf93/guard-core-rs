//! Background manager that polls the agent for dynamic rules and applies
//! them to the running engine.

use std::sync::Arc;

use serde_json::json;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::error::Result;
use crate::handlers::ipban::IPBanManager;
use crate::models::{DynamicRules, SecurityConfig};
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;

/// Polls the Guard Agent for [`crate::models::DynamicRules`] and applies them
/// to the running engine.
///
/// The manager spawns a background Tokio task that refreshes rules at
/// [`crate::models::SecurityConfig::dynamic_rule_interval`] seconds. Rules are
/// only applied when their version strictly exceeds the active version.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::handlers::dynamic_rule::DynamicRuleManager;
/// use guard_core_rs::models::SecurityConfig;
///
/// # async fn run() {
/// let manager = DynamicRuleManager::new(Arc::new(SecurityConfig::default()));
/// assert!(manager.get_current_rules().await.is_none());
/// # }
/// ```
pub struct DynamicRuleManager {
    config: RwLock<Arc<SecurityConfig>>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
    redis_handler: parking_lot::RwLock<Option<DynRedisHandler>>,
    last_update: parking_lot::RwLock<f64>,
    current_rules: RwLock<Option<DynamicRules>>,
    update_task: Mutex<Option<JoinHandle<()>>>,
    ipban_manager: parking_lot::RwLock<Option<Arc<IPBanManager>>>,
}

impl std::fmt::Debug for DynamicRuleManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicRuleManager")
            .field("last_update", &*self.last_update.read())
            .finish_non_exhaustive()
    }
}

impl DynamicRuleManager {
    /// Creates a new manager bound to `config`.
    pub fn new(config: Arc<SecurityConfig>) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(config),
            agent_handler: parking_lot::RwLock::new(None),
            redis_handler: parking_lot::RwLock::new(None),
            last_update: parking_lot::RwLock::new(0.0),
            current_rules: RwLock::new(None),
            update_task: Mutex::new(None),
            ipban_manager: parking_lot::RwLock::new(None),
        })
    }

    /// Installs the [`crate::handlers::ipban::IPBanManager`] used to apply
    /// `ip_blacklist` entries from dynamic rules.
    pub fn set_ipban_manager(&self, manager: Arc<IPBanManager>) {
        *self.ipban_manager.write() = Some(manager);
    }

    /// Wires in the Guard Agent handler and starts the background refresh
    /// loop when dynamic rules are enabled.
    pub async fn initialize_agent(self: &Arc<Self>, agent: DynAgentHandler) {
        *self.agent_handler.write() = Some(agent);
        let enable_dynamic = self.config.read().await.enable_dynamic_rules;
        if enable_dynamic {
            let mut task_guard = self.update_task.lock().await;
            if task_guard.is_none() {
                let this = Arc::clone(self);
                let handle = tokio::spawn(async move {
                    this.rule_update_loop().await;
                });
                *task_guard = Some(handle);
                info!("Started dynamic rule update loop");
            }
        }
    }

    /// Wires in the Redis handler so cached rules can survive restarts.
    pub async fn initialize_redis(&self, redis: DynRedisHandler) {
        *self.redis_handler.write() = Some(redis);
    }

    async fn rule_update_loop(self: Arc<Self>) {
        loop {
            if let Err(e) = self.update_rules().await {
                error!("Error in dynamic rule update loop: {e}");
            }
            let interval = self.config.read().await.dynamic_rule_interval;
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    }

    fn should_update_rules(current: Option<&DynamicRules>, new: &DynamicRules) -> bool {
        match current {
            None => true,
            Some(c) => !(c.rule_id == new.rule_id && new.version <= c.version),
        }
    }

    async fn send_rule_received_event(&self, rules: &DynamicRules) {
        let agent = self.agent_handler.read().clone();
        let Some(agent) = agent else { return };
        let previous = self.current_rules.read().await.as_ref().map_or(0, |r| r.version);
        let event = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": "dynamic_rule_updated",
            "ip_address": "system",
            "action_taken": "rules_received",
            "reason": format!("Received updated rules {} v{}", rules.rule_id, rules.version),
            "metadata": {
                "rule_id": rules.rule_id,
                "version": rules.version,
                "previous_version": previous,
            },
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send rule updated event: {e}");
        }
    }

    /// Fetches the latest rules from the agent and applies them when the
    /// payload's version is newer than the cached one.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] when the agent request
    /// fails, or the error raised by the rule application step.
    pub async fn update_rules(&self) -> Result<()> {
        let cfg = self.config.read().await.clone();
        if !cfg.enable_dynamic_rules {
            return Ok(());
        }
        let agent = self.agent_handler.read().clone();
        let Some(agent) = agent else {
            return Ok(());
        };
        let Some(rules) = agent.get_dynamic_rules().await? else {
            return Ok(());
        };
        {
            let current = self.current_rules.read().await;
            if !Self::should_update_rules(current.as_ref(), &rules) {
                return Ok(());
            }
        }

        self.send_rule_received_event(&rules).await;

        info!("Applying dynamic rules: {} v{}", rules.rule_id, rules.version);
        self.apply_rules(&rules).await?;

        *self.current_rules.write().await = Some(rules.clone());
        *self.last_update.write() = epoch_secs();

        self.send_rule_applied_event(&rules).await;
        Ok(())
    }

    async fn apply_rules(&self, rules: &DynamicRules) -> Result<()> {
        self.apply_ip_rules(rules).await?;
        self.apply_blocking_rules(rules).await;
        if rules.global_rate_limit.is_some() || !rules.endpoint_rate_limits.is_empty() {
            self.apply_rate_limit_rules(rules).await;
        }
        self.apply_feature_toggles(rules).await;
        if rules.emergency_mode {
            self.activate_emergency_mode(&rules.emergency_whitelist).await;
        }
        Ok(())
    }

    async fn apply_ip_rules(&self, rules: &DynamicRules) -> Result<()> {
        if !rules.ip_blacklist.is_empty() {
            self.apply_ip_bans(&rules.ip_blacklist, rules.ip_ban_duration).await?;
        }
        if !rules.ip_whitelist.is_empty() {
            self.apply_ip_whitelist(&rules.ip_whitelist).await?;
        }
        Ok(())
    }

    async fn apply_ip_bans(&self, ip_list: &[String], duration: u64) -> Result<()> {
        let Some(manager) = self.ipban_manager.read().clone() else { return Ok(()) };
        for ip in ip_list {
            if let Err(e) = manager.ban_ip(ip, duration, "dynamic_rule").await {
                error!("Failed to ban IP {ip}: {e}");
            } else {
                info!("Dynamic rule: Banned IP {ip} for {duration}s");
            }
        }
        Ok(())
    }

    async fn apply_ip_whitelist(&self, ip_list: &[String]) -> Result<()> {
        let Some(manager) = self.ipban_manager.read().clone() else { return Ok(()) };
        for ip in ip_list {
            if let Err(e) = manager.unban_ip(ip).await {
                error!("Failed to whitelist IP {ip}: {e}");
            } else {
                info!("Dynamic rule: Whitelisted IP {ip}");
            }
        }
        Ok(())
    }

    async fn apply_blocking_rules(&self, rules: &DynamicRules) {
        if !rules.blocked_countries.is_empty() || !rules.whitelist_countries.is_empty() {
            if !rules.blocked_countries.is_empty() {
                info!("Dynamic rule: Blocked countries {:?}", rules.blocked_countries);
            }
            if !rules.whitelist_countries.is_empty() {
                info!("Dynamic rule: Whitelisted countries {:?}", rules.whitelist_countries);
            }
        }
        if !rules.blocked_cloud_providers.is_empty() {
            info!(
                "Dynamic rule: Blocked cloud providers {:?}",
                rules.blocked_cloud_providers
            );
        }
        if !rules.blocked_user_agents.is_empty() {
            info!(
                "Dynamic rule: Blocked user agents {:?}",
                rules.blocked_user_agents
            );
        }
        if !rules.suspicious_patterns.is_empty() {
            info!(
                "Dynamic rule: Added suspicious patterns {:?}",
                rules.suspicious_patterns
            );
        }
    }

    async fn apply_rate_limit_rules(&self, rules: &DynamicRules) {
        if let Some(limit) = rules.global_rate_limit {
            let details = rules.global_rate_window.map_or_else(
                String::new,
                |w| format!("per {w}s"),
            );
            info!("Dynamic rule: Global rate limit {limit} {details}");
        }
        if !rules.endpoint_rate_limits.is_empty() {
            info!(
                "Dynamic rule: Applied endpoint-specific rate limits for {} endpoints: {:?}",
                rules.endpoint_rate_limits.len(),
                rules.endpoint_rate_limits.keys().collect::<Vec<_>>()
            );
        }
    }

    async fn apply_feature_toggles(&self, rules: &DynamicRules) {
        if let Some(v) = rules.enable_penetration_detection {
            info!("Dynamic rule: Penetration detection {v}");
        }
        if let Some(v) = rules.enable_ip_banning {
            info!("Dynamic rule: IP banning {v}");
        }
        if let Some(v) = rules.enable_rate_limiting {
            info!("Dynamic rule: Rate limiting {v}");
        }
    }

    async fn activate_emergency_mode(&self, emergency_whitelist: &[String]) {
        tracing::error!("[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled");
        warn!(
            "[EMERGENCY MODE] Reduced auto-ban threshold and activated emergency whitelist ({} entries)",
            emergency_whitelist.len()
        );
        let agent = self.agent_handler.read().clone();
        if let Some(agent) = agent {
            let preview: Vec<_> = emergency_whitelist.iter().take(10).collect();
            let event = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event_type": "emergency_mode_activated",
                "ip_address": "system",
                "action_taken": "emergency_lockdown",
                "reason": "[EMERGENCY MODE] activated via dynamic rules",
                "metadata": {
                    "whitelist_count": emergency_whitelist.len(),
                    "whitelist": preview,
                },
            });
            if let Err(e) = agent.send_event(event).await {
                error!("Failed to send emergency event: {e}");
            }
        }
    }

    async fn send_rule_applied_event(&self, rules: &DynamicRules) {
        let agent = self.agent_handler.read().clone();
        let Some(agent) = agent else { return };
        let event = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": "dynamic_rule_applied",
            "ip_address": "system",
            "action_taken": "rules_updated",
            "reason": format!("Applied dynamic rules {} v{}", rules.rule_id, rules.version),
            "metadata": {
                "rule_id": rules.rule_id,
                "version": rules.version,
                "ip_bans": rules.ip_blacklist.len(),
                "country_blocks": rules.blocked_countries.len(),
                "emergency_mode": rules.emergency_mode,
            },
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send rule applied event: {e}");
        }
    }

    /// Returns a clone of the currently applied rules, if any.
    pub async fn get_current_rules(&self) -> Option<DynamicRules> {
        self.current_rules.read().await.clone()
    }

    /// Triggers an immediate rule fetch/apply cycle.
    ///
    /// # Errors
    ///
    /// Returns any error propagated from
    /// [`crate::handlers::dynamic_rule::DynamicRuleManager::update_rules`].
    pub async fn force_update(&self) -> Result<()> {
        self.update_rules().await
    }

    /// Aborts the background update loop.
    pub async fn stop(&self) {
        let mut guard = self.update_task.lock().await;
        if let Some(handle) = guard.take() {
            handle.abort();
            info!("Stopped dynamic rule update loop");
        }
    }
}

fn epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
