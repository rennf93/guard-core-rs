//! Behavioural rule engine that tracks usage, response patterns, and
//! frequency anomalies per endpoint and IP.

use std::sync::Arc;

use dashmap::DashMap;
use regex::RegexBuilder;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::{error, warn};

use crate::error::Result;
use crate::handlers::ipban::IPBanManager;
use crate::models::SecurityConfig;
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;
use crate::protocols::response::DynGuardResponse;

/// Type of behavioural rule evaluated by the tracker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BehaviorRuleType {
    /// Counts endpoint invocations per IP.
    Usage,
    /// Matches a pattern (status / JSON / regex / substring) against the
    /// response.
    ReturnPattern,
    /// Measures call frequency over the configured window.
    Frequency,
}

/// Action to execute when a
/// [`crate::handlers::behavior::BehaviorRule`] is triggered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BehaviorAction {
    /// Ban the offending IP via
    /// [`crate::handlers::ipban::IPBanManager`].
    Ban,
    /// Emit a warning log record.
    Log,
    /// Throttle the offending IP (logged only in this implementation).
    Throttle,
    /// Raise a high-severity alert.
    Alert,
}

impl BehaviorAction {
    /// Returns the canonical lower-case label for the action.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ban => "ban",
            Self::Log => "log",
            Self::Throttle => "throttle",
            Self::Alert => "alert",
        }
    }
}

/// User-supplied async action invoked instead of the built-in
/// [`crate::handlers::behavior::BehaviorAction`] when attached via
/// [`crate::handlers::behavior::BehaviorRule::with_custom_action`].
///
/// Arguments are `(client_ip, endpoint_id, details)`.
pub type CustomBehaviorAction = Arc<
    dyn Fn(String, String, String) -> futures::future::BoxFuture<'static, ()> + Send + Sync,
>;

/// Declarative behavioural rule attached to a
/// [`crate::decorators::base::RouteConfig`].
#[derive(Clone)]
pub struct BehaviorRule {
    /// Discriminator selecting which tracker method evaluates the rule.
    pub rule_type: BehaviorRuleType,
    /// Threshold above which the rule is considered triggered.
    pub threshold: u32,
    /// Time window (in seconds) over which the threshold applies.
    pub window: u64,
    /// Optional pattern used by
    /// [`crate::handlers::behavior::BehaviorRuleType::ReturnPattern`].
    pub pattern: Option<String>,
    /// Built-in action to execute on violation.
    pub action: BehaviorAction,
    /// Optional user-supplied action that replaces
    /// [`crate::handlers::behavior::BehaviorRule::action`] when present.
    pub custom_action: Option<CustomBehaviorAction>,
}

impl std::fmt::Debug for BehaviorRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BehaviorRule")
            .field("rule_type", &self.rule_type)
            .field("threshold", &self.threshold)
            .field("window", &self.window)
            .field("pattern", &self.pattern)
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

impl BehaviorRule {
    /// Creates a new rule without a custom action.
    pub fn new(
        rule_type: BehaviorRuleType,
        threshold: u32,
        window: u64,
        pattern: Option<String>,
        action: BehaviorAction,
    ) -> Self {
        Self { rule_type, threshold, window, pattern, action, custom_action: None }
    }

    /// Attaches a custom async action executed in active mode instead of
    /// [`crate::handlers::behavior::BehaviorRule::action`].
    pub fn with_custom_action(mut self, action: CustomBehaviorAction) -> Self {
        self.custom_action = Some(action);
        self
    }
}

/// In-memory + optional Redis tracker evaluating
/// [`crate::handlers::behavior::BehaviorRule`] entries.
///
/// Shared between the [`crate::decorators::base::SecurityDecorator`] and the
/// behavioural post-processing step. Supports both in-memory counters and a
/// Redis backend for multi-instance deployments.
pub struct BehaviorTracker {
    config: RwLock<Arc<SecurityConfig>>,
    usage_counts: DashMap<String, DashMap<String, Vec<f64>>>,
    return_patterns: DashMap<String, DashMap<String, Vec<f64>>>,
    redis_handler: parking_lot::RwLock<Option<DynRedisHandler>>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
    ipban_manager: parking_lot::RwLock<Option<Arc<IPBanManager>>>,
}

impl std::fmt::Debug for BehaviorTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BehaviorTracker").finish_non_exhaustive()
    }
}

impl BehaviorTracker {
    /// Creates a new tracker bound to `config`.
    pub fn new(config: Arc<SecurityConfig>) -> Self {
        Self {
            config: RwLock::new(config),
            usage_counts: DashMap::new(),
            return_patterns: DashMap::new(),
            redis_handler: parking_lot::RwLock::new(None),
            agent_handler: parking_lot::RwLock::new(None),
            ipban_manager: parking_lot::RwLock::new(None),
        }
    }

    /// Installs a [`crate::protocols::redis::DynRedisHandler`] so counters are
    /// shared across instances.
    pub async fn initialize_redis(&self, redis: DynRedisHandler) {
        *self.redis_handler.write() = Some(redis);
    }

    /// Installs a [`crate::protocols::agent::DynAgentHandler`] used for
    /// forwarding violation events.
    pub async fn initialize_agent(&self, agent: DynAgentHandler) {
        *self.agent_handler.write() = Some(agent);
    }

    /// Provides an [`crate::handlers::ipban::IPBanManager`] used for `Ban`
    /// actions.
    pub fn set_ipban_manager(&self, manager: Arc<IPBanManager>) {
        *self.ipban_manager.write() = Some(manager);
    }

    /// Records a usage event for `(endpoint_id, client_ip)` and returns
    /// `true` when the rule threshold is exceeded within `rule.window`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when the Redis backend
    /// cannot be reached.
    pub async fn track_endpoint_usage(
        &self,
        endpoint_id: &str,
        client_ip: &str,
        rule: &BehaviorRule,
    ) -> Result<bool> {
        let current_time = epoch_secs();
        let window_start = current_time - rule.window as f64;

        let redis = self.redis_handler.read().clone();
        if let Some(redis) = redis {
            let key = format!("behavior:usage:{endpoint_id}:{client_ip}");
            redis
                .set_key(
                    "behavior_usage",
                    &format!("{key}:{current_time}"),
                    Value::String("1".into()),
                    Some(rule.window),
                )
                .await?;
            let pattern = format!("behavior_usage:{key}:*");
            let keys = redis.keys(&pattern).await.unwrap_or_default();
            let valid_count = keys
                .iter()
                .filter_map(|k| k.split(':').next_back().and_then(|s| s.parse::<f64>().ok()))
                .filter(|ts| *ts >= window_start)
                .count();
            return Ok(valid_count > rule.threshold as usize);
        }

        let mut entry = self
            .usage_counts
            .entry(endpoint_id.to_string())
            .or_default();
        let client_map = entry.value_mut();
        let mut timestamps = client_map
            .entry(client_ip.to_string())
            .or_default()
            .value()
            .clone();
        timestamps.retain(|ts| *ts >= window_start);
        timestamps.push(current_time);
        let len = timestamps.len();
        client_map.insert(client_ip.to_string(), timestamps);
        Ok(len > rule.threshold as usize)
    }

    /// Records a response-pattern event and returns `true` when the rule
    /// threshold is exceeded.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when the Redis backend
    /// cannot be reached.
    pub async fn track_return_pattern(
        &self,
        endpoint_id: &str,
        client_ip: &str,
        response: &DynGuardResponse,
        rule: &BehaviorRule,
    ) -> Result<bool> {
        let Some(pattern) = rule.pattern.as_deref() else {
            return Ok(false);
        };
        let current_time = epoch_secs();
        let window_start = current_time - rule.window as f64;

        let matched = self.check_response_pattern(response, pattern).await;
        if !matched {
            return Ok(false);
        }

        let redis = self.redis_handler.read().clone();
        if let Some(redis) = redis {
            let key = format!("behavior:return:{endpoint_id}:{client_ip}:{pattern}");
            redis
                .set_key(
                    "behavior_returns",
                    &format!("{key}:{current_time}"),
                    Value::String("1".into()),
                    Some(rule.window),
                )
                .await?;
            let pattern_key = format!("behavior_returns:{key}:*");
            let keys = redis.keys(&pattern_key).await.unwrap_or_default();
            let valid_count = keys
                .iter()
                .filter_map(|k| k.split(':').next_back().and_then(|s| s.parse::<f64>().ok()))
                .filter(|ts| *ts >= window_start)
                .count();
            return Ok(valid_count > rule.threshold as usize);
        }

        let pattern_key = format!("{endpoint_id}:{pattern}");
        let mut entry = self.return_patterns.entry(pattern_key).or_default();
        let client_map = entry.value_mut();
        let mut timestamps = client_map
            .entry(client_ip.to_string())
            .or_default()
            .value()
            .clone();
        timestamps.retain(|ts| *ts >= window_start);
        timestamps.push(current_time);
        let len = timestamps.len();
        client_map.insert(client_ip.to_string(), timestamps);
        Ok(len > rule.threshold as usize)
    }

    async fn check_response_pattern(
        &self,
        response: &DynGuardResponse,
        pattern: &str,
    ) -> bool {
        if let Some(stripped) = pattern.strip_prefix("status:") {
            return stripped
                .parse::<u16>()
                .ok()
                .is_some_and(|code| response.status_code() == code);
        }

        let Some(body_bytes) = response.body() else {
            return false;
        };
        let Ok(body_str) = std::str::from_utf8(&body_bytes) else {
            return false;
        };

        if let Some(json_pattern) = pattern.strip_prefix("json:") {
            return match serde_json::from_str::<Value>(body_str) {
                Ok(data) => match_json_pattern(&data, json_pattern),
                Err(_) => false,
            };
        }
        if let Some(regex_pattern) = pattern.strip_prefix("regex:") {
            return RegexBuilder::new(regex_pattern)
                .case_insensitive(true)
                .build()
                .map(|re| re.is_match(body_str))
                .unwrap_or(false);
        }
        body_str.to_ascii_lowercase().contains(&pattern.to_ascii_lowercase())
    }

    fn log_passive_mode_action(&self, rule: &BehaviorRule, client_ip: &str, details: &str) {
        match rule.action {
            BehaviorAction::Ban => warn!(
                "[PASSIVE MODE] Would ban IP {client_ip} for behavioral violation: {details}"
            ),
            BehaviorAction::Log => warn!("[PASSIVE MODE] Behavioral anomaly detected: {details}"),
            BehaviorAction::Throttle => warn!("[PASSIVE MODE] Would throttle IP {client_ip}: {details}"),
            BehaviorAction::Alert => tracing::error!("[PASSIVE MODE] ALERT - Behavioral anomaly: {details}"),
        }
    }

    async fn execute_active_mode_action(
        &self,
        rule: &BehaviorRule,
        client_ip: &str,
        endpoint_id: &str,
        details: &str,
    ) -> Result<()> {
        if let Some(custom) = &rule.custom_action {
            custom(client_ip.into(), endpoint_id.into(), details.into()).await;
            return Ok(());
        }
        match rule.action {
            BehaviorAction::Ban => {
                let manager = self.ipban_manager.read().clone();
                if let Some(manager) = manager {
                    manager.ban_ip(client_ip, 3600, "behavioral_violation").await?;
                }
                warn!("IP {client_ip} banned for behavioral violation: {details}");
            }
            BehaviorAction::Log => warn!("Behavioral anomaly detected: {details}"),
            BehaviorAction::Throttle => warn!("Throttling IP {client_ip}: {details}"),
            BehaviorAction::Alert => tracing::error!("ALERT - Behavioral anomaly: {details}"),
        }
        Ok(())
    }

    /// Executes the action associated with a triggered rule.
    ///
    /// In passive mode the action is logged only; otherwise it is dispatched
    /// to the custom handler (if any) or the built-in action.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError`] raised by the underlying
    /// action (e.g. [`crate::error::GuardCoreError::Redis`] from
    /// [`crate::handlers::ipban::IPBanManager::ban_ip`]).
    pub async fn apply_action(
        &self,
        rule: &BehaviorRule,
        client_ip: &str,
        endpoint_id: &str,
        details: &str,
    ) -> Result<()> {
        let cfg = self.config.read().await.clone();
        let agent = self.agent_handler.read().clone();
        if let Some(agent) = agent {
            let action_taken = if cfg.passive_mode {
                "logged_only".into()
            } else {
                rule.action.as_str().to_string()
            };
            let event = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event_type": "behavioral_violation",
                "ip_address": client_ip,
                "action_taken": action_taken,
                "reason": format!("Behavioral rule violated: {details}"),
                "metadata": {
                    "endpoint": endpoint_id,
                    "rule_type": format!("{:?}", rule.rule_type).to_ascii_lowercase(),
                    "threshold": rule.threshold,
                    "window": rule.window,
                },
            });
            if let Err(e) = agent.send_event(event).await {
                error!("Failed to send behavior event to agent: {e}");
            }
        }

        if cfg.passive_mode {
            self.log_passive_mode_action(rule, client_ip, details);
        } else {
            self.execute_active_mode_action(rule, client_ip, endpoint_id, details).await?;
        }
        Ok(())
    }
}

fn match_json_pattern(data: &Value, pattern: &str) -> bool {
    let Some((path, expected)) = pattern.split_once("==") else {
        return false;
    };
    let path = path.trim();
    let expected = expected.trim().trim_matches(|c| c == '\'' || c == '"');
    traverse_json_match(data, path, expected)
}

fn traverse_json_match(data: &Value, path: &str, expected: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = data;
    for part in &parts {
        if let Some(stripped) = part.strip_suffix("[]") {
            let Some(obj) = current.as_object() else { return false };
            let Some(arr) = obj.get(stripped).and_then(Value::as_array) else {
                return false;
            };
            return arr
                .iter()
                .any(|v| json_value_to_str(v).eq_ignore_ascii_case(expected));
        }
        let Some(obj) = current.as_object() else { return false };
        let Some(next) = obj.get(*part) else { return false };
        current = next;
    }
    json_value_to_str(current).eq_ignore_ascii_case(expected)
}

fn json_value_to_str(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}

fn epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
