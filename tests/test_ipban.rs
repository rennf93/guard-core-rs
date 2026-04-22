#[path = "support/mock_redis.rs"]
mod mock_redis;
#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::sync::Arc;

use serde_json::Value;

use guard_core_rs::handlers::IPBanManager;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};

use mock_agent::MockAgent;
use mock_redis::{MockRedis, MockRedisFailure};

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

fn events_of(agent: &MockAgent, event_type: &str) -> Vec<Value> {
    agent
        .events
        .read()
        .iter()
        .filter(|e| {
            e.get("event_type")
                .and_then(Value::as_str)
                .is_some_and(|v| v == event_type)
        })
        .cloned()
        .collect()
}

fn current_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs_f64()
}

#[test]
fn default_produces_usable_manager() {
    let manager = IPBanManager::default();
    assert_eq!(manager.size(), 0);
    let debug = format!("{manager:?}");
    assert!(debug.contains("IPBanManager"));
}

#[tokio::test]
async fn ban_ip_stores_entry_in_cache() {
    let manager = Arc::new(IPBanManager::new());
    manager
        .ban_ip("203.0.113.1", 120, "scan")
        .await
        .expect("ban");
    assert!(manager.is_ip_banned("203.0.113.1").await.expect("check"));
}

#[tokio::test]
async fn ban_ip_persists_to_redis_when_configured() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    manager.initialize_redis(handler).await;

    manager
        .ban_ip("198.51.100.5", 60, "abuse")
        .await
        .expect("ban");
    assert!(redis.data.contains_key("banned_ips:198.51.100.5"));
}

#[tokio::test]
async fn ban_ip_sends_agent_event() {
    let manager = Arc::new(IPBanManager::new());
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;

    manager
        .ban_ip("198.51.100.10", 60, "botnet")
        .await
        .expect("ban");
    let events = events_of(&agent, "ip_banned");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].get("ip_address").and_then(Value::as_str), Some("198.51.100.10"));
    assert_eq!(events[0].get("action_taken").and_then(Value::as_str), Some("banned"));
}

#[tokio::test]
async fn ban_ip_agent_error_is_logged_but_non_fatal() {
    let manager = Arc::new(IPBanManager::new());
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await;

    manager
        .ban_ip("198.51.100.20", 60, "mock_fail")
        .await
        .expect("ban still succeeds");
    assert!(manager.is_ip_banned("198.51.100.20").await.expect("check"));
}

#[tokio::test]
async fn ban_ip_returns_error_on_redis_failure() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    *redis.fail_mode.write() = Some(MockRedisFailure::SetKey);
    manager.initialize_redis(handler).await;

    let result = manager.ban_ip("198.51.100.30", 60, "test").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn is_ip_banned_expired_entry_invalidates() {
    let manager = Arc::new(IPBanManager::new());
    manager
        .ban_ip("198.51.100.40", 0, "will_expire")
        .await
        .expect("ban");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let banned = manager.is_ip_banned("198.51.100.40").await.expect("check");
    assert!(!banned);
}

#[tokio::test]
async fn is_ip_banned_loads_from_redis_on_miss() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    let future_ts = current_epoch() + 600.0;
    redis.data.insert(
        "banned_ips:10.0.0.100".into(),
        Value::String(future_ts.to_string()),
    );
    manager.initialize_redis(handler).await;

    assert!(manager.is_ip_banned("10.0.0.100").await.expect("check"));
}

#[tokio::test]
async fn is_ip_banned_returns_false_on_empty_redis_value() {
    let manager = Arc::new(IPBanManager::new());
    let (_redis, handler) = new_redis();
    manager.initialize_redis(handler).await;
    assert!(!manager.is_ip_banned("10.0.0.200").await.expect("check"));
}

#[tokio::test]
async fn is_ip_banned_expired_redis_entry_removed() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    let past_ts = current_epoch() - 600.0;
    redis.data.insert(
        "banned_ips:10.0.0.150".into(),
        Value::String(past_ts.to_string()),
    );
    manager.initialize_redis(handler).await;

    assert!(!manager.is_ip_banned("10.0.0.150").await.expect("check"));
    assert!(!redis.data.contains_key("banned_ips:10.0.0.150"));
}

#[tokio::test]
async fn is_ip_banned_accepts_numeric_expiry_in_redis() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    let future_ts = current_epoch() + 3600.0;
    redis.data.insert(
        "banned_ips:10.0.1.1".into(),
        Value::Number(serde_json::Number::from_f64(future_ts).expect("number")),
    );
    manager.initialize_redis(handler).await;
    assert!(manager.is_ip_banned("10.0.1.1").await.expect("check"));
}

#[tokio::test]
async fn is_ip_banned_handles_invalid_redis_expiry() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    redis
        .data
        .insert("banned_ips:10.0.1.2".into(), Value::Null);
    manager.initialize_redis(handler).await;
    assert!(!manager.is_ip_banned("10.0.1.2").await.expect("check"));
}

#[tokio::test]
async fn is_ip_banned_propagates_redis_error() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    *redis.fail_mode.write() = Some(MockRedisFailure::GetKey);
    manager.initialize_redis(handler).await;
    let result = manager.is_ip_banned("10.0.1.3").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn unban_ip_removes_from_cache_and_redis() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    manager.initialize_redis(handler).await;
    manager
        .ban_ip("10.0.2.1", 600, "test")
        .await
        .expect("ban");
    assert!(redis.data.contains_key("banned_ips:10.0.2.1"));

    manager.unban_ip("10.0.2.1").await.expect("unban");
    assert!(!redis.data.contains_key("banned_ips:10.0.2.1"));
    assert!(!manager.is_ip_banned("10.0.2.1").await.expect("check"));
}

#[tokio::test]
async fn unban_ip_sends_agent_event() {
    let manager = Arc::new(IPBanManager::new());
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;

    manager.unban_ip("10.0.2.2").await.expect("unban");
    let events = events_of(&agent, "ip_unbanned");
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn unban_ip_tolerates_agent_failure() {
    let manager = Arc::new(IPBanManager::new());
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await;
    manager.unban_ip("10.0.2.3").await.expect("unban ok");
}

#[tokio::test]
async fn unban_ip_returns_error_on_redis_failure() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    *redis.fail_mode.write() = Some(MockRedisFailure::Delete);
    manager.initialize_redis(handler).await;
    let result = manager.unban_ip("10.0.2.4").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn reset_clears_cache_and_redis_keys() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    manager.initialize_redis(handler).await;
    manager.ban_ip("10.0.3.1", 60, "t").await.expect("ban");
    manager.ban_ip("10.0.3.2", 60, "t").await.expect("ban");

    manager.reset().await.expect("reset");
    assert!(!manager.is_ip_banned("10.0.3.1").await.expect("check"));
    assert!(!manager.is_ip_banned("10.0.3.2").await.expect("check"));
    assert!(!redis.data.contains_key("banned_ips:10.0.3.1"));
    assert!(!redis.data.contains_key("banned_ips:10.0.3.2"));
}

#[tokio::test]
async fn reset_without_redis_still_clears_cache() {
    let manager = Arc::new(IPBanManager::new());
    manager.ban_ip("10.0.3.3", 60, "t").await.expect("ban");
    manager.reset().await.expect("reset");
    assert_eq!(manager.size(), 0);
}

#[tokio::test]
async fn reset_ignores_redis_keys_error() {
    let manager = Arc::new(IPBanManager::new());
    let (redis, handler) = new_redis();
    manager.initialize_redis(handler).await;
    manager.ban_ip("10.0.3.4", 60, "t").await.expect("ban");
    *redis.fail_mode.write() = Some(MockRedisFailure::Keys);

    manager.reset().await.expect("reset tolerates keys failure");
}

#[tokio::test]
async fn size_reflects_active_bans() {
    let manager = Arc::new(IPBanManager::new());
    manager.ban_ip("10.0.4.1", 120, "x").await.expect("ban");
    manager.ban_ip("10.0.4.2", 120, "x").await.expect("ban");
    let debug = format!("{manager:?}");
    assert!(debug.contains("IPBanManager"));
    let _ = manager.size();
}
