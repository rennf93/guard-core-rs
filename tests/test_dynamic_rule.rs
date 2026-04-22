#[path = "support/mock_redis.rs"]
mod mock_redis;
#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;

use guard_core_rs::handlers::{DynamicRuleManager, IPBanManager};
use guard_core_rs::models::{DynamicRules, SecurityConfig};
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};

use mock_agent::MockAgent;
use mock_redis::MockRedis;

fn new_redis() -> (Arc<MockRedis>, DynRedisHandler) {
    let mock = Arc::new(MockRedis::default());
    let dyn_handler: DynRedisHandler = mock.clone() as Arc<dyn RedisHandlerProtocol>;
    (mock, dyn_handler)
}

fn new_agent() -> (Arc<MockAgent>, DynAgentHandler) {
    let mock = Arc::new(MockAgent::default());
    let dyn_handler: DynAgentHandler = mock.clone() as Arc<dyn AgentHandlerProtocol>;
    (mock, dyn_handler)
}

fn build_config(enable: bool) -> Arc<SecurityConfig> {
    let mut cfg = SecurityConfig::builder().build().expect("cfg");
    cfg.enable_dynamic_rules = enable;
    cfg.dynamic_rule_interval = 1;
    Arc::new(cfg)
}

fn base_rule(rule_id: &str, version: i64) -> DynamicRules {
    DynamicRules {
        rule_id: rule_id.into(),
        version,
        timestamp: Utc::now(),
        expires_at: None,
        ttl: 300,
        ip_blacklist: vec!["1.1.1.1".into()],
        ip_whitelist: vec!["2.2.2.2".into()],
        ip_ban_duration: 60,
        blocked_countries: vec!["US".into()],
        whitelist_countries: vec!["FR".into()],
        global_rate_limit: Some(100),
        global_rate_window: Some(60),
        endpoint_rate_limits: HashMap::from([(
            "/api".to_string(),
            (10u32, 60u64),
        )]),
        blocked_cloud_providers: HashSet::from(["AWS".to_string()]),
        blocked_user_agents: vec!["badbot".into()],
        suspicious_patterns: vec!["evil".into()],
        enable_penetration_detection: Some(true),
        enable_ip_banning: Some(true),
        enable_rate_limiting: Some(true),
        emergency_mode: false,
        emergency_whitelist: vec!["10.0.0.1".into()],
    }
}

#[tokio::test]
async fn new_creates_arc_manager() {
    let cfg = build_config(false);
    let manager = DynamicRuleManager::new(cfg);
    let debug = format!("{manager:?}");
    assert!(debug.contains("DynamicRuleManager"));
}

#[tokio::test]
async fn update_rules_does_nothing_when_disabled() {
    let cfg = build_config(false);
    let manager = DynamicRuleManager::new(cfg);
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
    assert!(manager.get_current_rules().await.is_none());
}

#[tokio::test]
async fn update_rules_noop_without_agent() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    manager.update_rules().await.expect("update");
    assert!(manager.get_current_rules().await.is_none());
}

#[tokio::test]
async fn update_rules_applies_new_rules_with_bans() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    *agent.dynamic_rules.write() = Some(base_rule("r1", 1));
    let ipban = Arc::new(IPBanManager::new());
    manager.set_ipban_manager(ipban.clone());
    manager.initialize_agent(handler).await;
    let (_redis, rhandler) = new_redis();
    manager.initialize_redis(rhandler).await;

    manager.update_rules().await.expect("update");
    let current = manager.get_current_rules().await.expect("present");
    assert_eq!(current.rule_id, "r1");
    assert!(ipban.is_ip_banned("1.1.1.1").await.expect("check"));
}

#[tokio::test]
async fn update_rules_skips_same_version() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let rule = base_rule("r2", 5);
    *agent.dynamic_rules.write() = Some(rule.clone());
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("first");

    let mut second = rule.clone();
    second.version = 4;
    *agent.dynamic_rules.write() = Some(second);
    manager.update_rules().await.expect("second");
    let current = manager.get_current_rules().await.expect("present");
    assert_eq!(current.version, 5);
}

#[tokio::test]
async fn update_rules_applies_new_version() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let rule = base_rule("r3", 1);
    *agent.dynamic_rules.write() = Some(rule.clone());
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("first");

    let mut second = rule.clone();
    second.version = 2;
    *agent.dynamic_rules.write() = Some(second);
    manager.update_rules().await.expect("second");
    let current = manager.get_current_rules().await.expect("present");
    assert_eq!(current.version, 2);
}

#[tokio::test]
async fn update_rules_sends_events() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    *agent.dynamic_rules.write() = Some(base_rule("r4", 1));
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
    let events: Vec<Value> = agent.events.read().iter().cloned().collect();
    let kinds: Vec<String> = events
        .iter()
        .filter_map(|e| e.get("event_type").and_then(Value::as_str).map(String::from))
        .collect();
    assert!(kinds.contains(&"dynamic_rule_updated".to_string()));
    assert!(kinds.contains(&"dynamic_rule_applied".to_string()));
}

#[tokio::test]
async fn update_rules_emergency_mode_triggers_event() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r5", 1);
    rule.emergency_mode = true;
    *agent.dynamic_rules.write() = Some(rule);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
    let events: Vec<Value> = agent.events.read().iter().cloned().collect();
    let has_emerg = events.iter().any(|e| {
        e.get("event_type").and_then(Value::as_str) == Some("emergency_mode_activated")
    });
    assert!(has_emerg);
}

#[tokio::test]
async fn update_rules_returns_none_when_no_rules_from_agent() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
    assert!(manager.get_current_rules().await.is_none());
}

#[tokio::test]
async fn update_rules_tolerates_agent_error_on_get_rules() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    *agent.fail_rules.write() = true;
    manager.initialize_agent(handler).await;
    assert!(manager.update_rules().await.is_err());
}

#[tokio::test]
async fn update_rules_tolerates_agent_send_event_failure() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    *agent.dynamic_rules.write() = Some(base_rule("r6", 1));
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update tolerates event failure");
}

#[tokio::test]
async fn apply_ip_bans_without_ipban_manager_is_noop() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    *agent.dynamic_rules.write() = Some(base_rule("r7", 1));
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn force_update_delegates_to_update_rules() {
    let cfg = build_config(false);
    let manager = DynamicRuleManager::new(cfg);
    manager.force_update().await.expect("force");
}

#[tokio::test]
async fn stop_with_no_task_is_noop() {
    let cfg = build_config(false);
    let manager = DynamicRuleManager::new(cfg);
    manager.stop().await;
}

#[tokio::test]
async fn initialize_agent_starts_update_loop_when_enabled() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    manager.stop().await;
}

#[tokio::test]
async fn initialize_agent_only_starts_loop_once() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (_agent, handler) = new_agent();
    manager.initialize_agent(handler.clone()).await;
    manager.initialize_agent(handler).await;
    manager.stop().await;
}

#[tokio::test]
async fn initialize_redis_sets_handler() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (_redis, handler) = new_redis();
    manager.initialize_redis(handler).await;
}

#[tokio::test]
async fn apply_ip_bans_handles_invalid_entries() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r8", 1);
    rule.ip_blacklist = vec!["not-an-ip".into(), "10.0.0.1".into()];
    *agent.dynamic_rules.write() = Some(rule);
    let ipban = Arc::new(IPBanManager::new());
    manager.set_ipban_manager(ipban);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn apply_whitelist_handles_invalid_entries() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r9", 1);
    rule.ip_blacklist.clear();
    rule.ip_whitelist = vec!["not-an-ip".into(), "10.0.0.2".into()];
    *agent.dynamic_rules.write() = Some(rule);
    let ipban = Arc::new(IPBanManager::new());
    manager.set_ipban_manager(ipban);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn apply_rules_without_global_rate_limit() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r10", 1);
    rule.global_rate_limit = None;
    rule.endpoint_rate_limits.clear();
    rule.blocked_cloud_providers.clear();
    rule.blocked_countries.clear();
    rule.whitelist_countries.clear();
    rule.blocked_user_agents.clear();
    rule.suspicious_patterns.clear();
    rule.enable_ip_banning = None;
    rule.enable_rate_limiting = None;
    rule.enable_penetration_detection = None;
    *agent.dynamic_rules.write() = Some(rule);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn apply_rules_with_global_rate_limit_but_no_window() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r11", 1);
    rule.global_rate_window = None;
    rule.endpoint_rate_limits.clear();
    *agent.dynamic_rules.write() = Some(rule);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn apply_rules_with_only_endpoint_rate_limits() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r12", 1);
    rule.global_rate_limit = None;
    *agent.dynamic_rules.write() = Some(rule);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn apply_rules_with_only_blocked_countries() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r13", 1);
    rule.whitelist_countries.clear();
    *agent.dynamic_rules.write() = Some(rule);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn apply_rules_with_only_whitelist_countries() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r14", 1);
    rule.blocked_countries.clear();
    *agent.dynamic_rules.write() = Some(rule);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn emergency_mode_tolerates_agent_event_failure() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("r15", 1);
    rule.emergency_mode = true;
    rule.emergency_whitelist = (0..15).map(|i| format!("10.0.0.{i}")).collect();
    *agent.dynamic_rules.write() = Some(rule);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("first succeeds");
    *agent.fail_events.write() = true;
    let mut rule2 = base_rule("r15", 2);
    rule2.emergency_mode = true;
    *agent.dynamic_rules.write() = Some(rule2);
    manager.update_rules().await.ok();
}

#[tokio::test]
async fn apply_ip_bans_with_failing_redis_logs_error() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    *agent.dynamic_rules.write() = Some(base_rule("rb1", 1));
    let ipban = Arc::new(IPBanManager::new());
    let (redis, rhandler) = new_redis();
    ipban.initialize_redis(rhandler).await;
    *redis.fail_mode.write() = Some(mock_redis::MockRedisFailure::SetKey);
    manager.set_ipban_manager(ipban);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.ok();
}

#[tokio::test]
async fn apply_ip_whitelist_with_failing_redis_logs_error() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("rw1", 1);
    rule.ip_blacklist.clear();
    *agent.dynamic_rules.write() = Some(rule);
    let ipban = Arc::new(IPBanManager::new());
    let (redis, rhandler) = new_redis();
    ipban.initialize_redis(rhandler).await;
    *redis.fail_mode.write() = Some(mock_redis::MockRedisFailure::Delete);
    manager.set_ipban_manager(ipban);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.ok();
}

#[tokio::test]
async fn update_rules_with_endpoint_rate_limits_logs_info() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    let mut rule = base_rule("rl1", 1);
    rule.global_rate_limit = None;
    rule.global_rate_window = None;
    rule.endpoint_rate_limits = HashMap::from([
        ("/one".into(), (5u32, 60u64)),
        ("/two".into(), (10u32, 60u64)),
    ]);
    *agent.dynamic_rules.write() = Some(rule);
    manager.initialize_agent(handler).await;
    manager.update_rules().await.expect("update");
}

#[tokio::test]
async fn update_rules_initializes_redis_handler() {
    let cfg = build_config(false);
    let manager = DynamicRuleManager::new(cfg);
    let (_redis, handler) = new_redis();
    manager.initialize_redis(handler).await;
}

#[tokio::test]
async fn loop_executes_at_least_once() {
    let cfg = build_config(true);
    let manager = DynamicRuleManager::new(cfg);
    let (agent, handler) = new_agent();
    *agent.dynamic_rules.write() = Some(base_rule("loop1", 1));
    manager.initialize_agent(handler).await;
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    manager.stop().await;
    assert!(
        manager
            .get_current_rules()
            .await
            .is_some()
    );
}
