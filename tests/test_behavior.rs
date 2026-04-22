#[path = "support/mock_redis.rs"]
mod mock_redis;
#[path = "support/mock_agent.rs"]
mod mock_agent;
#[path = "support/response.rs"]
mod mock_response;

use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::Value;

use guard_core_rs::handlers::behavior::{
    BehaviorAction, BehaviorRule, BehaviorRuleType, BehaviorTracker,
};
use guard_core_rs::handlers::IPBanManager;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};
use guard_core_rs::protocols::response::DynGuardResponse;

use mock_agent::MockAgent;
use mock_redis::MockRedis;
use mock_response::MockResponse;

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

fn base_config() -> Arc<SecurityConfig> {
    Arc::new(SecurityConfig::builder().build().expect("cfg"))
}

fn passive_config() -> Arc<SecurityConfig> {
    let mut cfg = SecurityConfig::builder().build().expect("cfg");
    cfg.passive_mode = true;
    Arc::new(cfg)
}

#[test]
fn behavior_action_as_str_covers_all_variants() {
    assert_eq!(BehaviorAction::Ban.as_str(), "ban");
    assert_eq!(BehaviorAction::Log.as_str(), "log");
    assert_eq!(BehaviorAction::Throttle.as_str(), "throttle");
    assert_eq!(BehaviorAction::Alert.as_str(), "alert");
}

#[test]
fn behavior_rule_new_sets_fields() {
    let rule = BehaviorRule::new(
        BehaviorRuleType::Usage,
        5,
        60,
        Some("regex:error".into()),
        BehaviorAction::Log,
    );
    assert_eq!(rule.threshold, 5);
    assert_eq!(rule.window, 60);
    assert_eq!(rule.rule_type, BehaviorRuleType::Usage);
    assert!(format!("{rule:?}").contains("BehaviorRule"));
}

#[tokio::test]
async fn behavior_rule_with_custom_action_stores_callback() {
    let called = Arc::new(Mutex::new(false));
    let flag = called.clone();
    let rule = BehaviorRule::new(
        BehaviorRuleType::Usage,
        1,
        60,
        None,
        BehaviorAction::Log,
    )
    .with_custom_action(Arc::new(move |_ip, _endpoint, _details| {
        let flag = flag.clone();
        Box::pin(async move {
            *flag.lock() = true;
        })
    }));
    if let Some(action) = rule.custom_action.as_ref() {
        action("1.1.1.1".into(), "/api".into(), "details".into()).await;
    }
    assert!(*called.lock());
}

#[tokio::test]
async fn track_endpoint_usage_in_memory_counts_requests() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 2, 60, None, BehaviorAction::Log);
    assert!(
        !tracker
            .track_endpoint_usage("/api", "1.1.1.1", &rule)
            .await
            .expect("first")
    );
    assert!(
        !tracker
            .track_endpoint_usage("/api", "1.1.1.1", &rule)
            .await
            .expect("second")
    );
    assert!(
        tracker
            .track_endpoint_usage("/api", "1.1.1.1", &rule)
            .await
            .expect("third")
    );
}

#[tokio::test]
async fn track_endpoint_usage_with_redis() {
    let tracker = BehaviorTracker::new(base_config());
    let (_redis, handler) = new_redis();
    tracker.initialize_redis(handler).await;
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 0, 60, None, BehaviorAction::Log);
    let result = tracker
        .track_endpoint_usage("/e", "2.2.2.2", &rule)
        .await
        .expect("track");
    assert!(result);
}

#[tokio::test]
async fn track_return_pattern_status_match() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        1,
        60,
        Some("status:500".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(500, "err");
    assert!(
        !tracker
            .track_return_pattern("/api", "1.1.1.1", &response, &rule)
            .await
            .expect("first")
    );
    assert!(
        tracker
            .track_return_pattern("/api", "1.1.1.1", &response, &rule)
            .await
            .expect("second")
    );
}

#[tokio::test]
async fn track_return_pattern_status_mismatch_returns_false() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        1,
        60,
        Some("status:999".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, "ok");
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_without_pattern_returns_false() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        1,
        60,
        None,
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(500, "err");
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_json_dot_path_match() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:a.b == 'hello'".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, r#"{"a":{"b":"hello"}}"#);
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(result);
}

#[tokio::test]
async fn track_return_pattern_json_array_path_match() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:items[] == 'red'".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, r#"{"items":["blue","RED","green"]}"#);
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(result);
}

#[tokio::test]
async fn track_return_pattern_json_nonexistent_path() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:missing.key == 'x'".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, r#"{"a":"b"}"#);
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_json_malformed_pattern() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:no_equals".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, r#"{"a":"b"}"#);
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_json_invalid_body() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:a == 'b'".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, "not json");
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_regex_pattern_match() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("regex:err\\d+".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(500, "err123 occurred");
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(result);
}

#[tokio::test]
async fn track_return_pattern_regex_invalid_never_matches() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("regex:(unclosed".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(500, "err");
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_substring_case_insensitive() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("ERROR".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(500, "an error happened");
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(result);
}

#[tokio::test]
async fn track_return_pattern_body_not_utf8() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("needle".into()),
        BehaviorAction::Log,
    );
    let raw = bytes::Bytes::from_static(&[0xff, 0xff, 0xff]);
    let response = Arc::new(BinaryResponse { body: raw }) as DynGuardResponse;
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_redis_active() {
    let tracker = BehaviorTracker::new(base_config());
    let (_redis, handler) = new_redis();
    tracker.initialize_redis(handler).await;
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("status:500".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(500, "err");
    let result = tracker
        .track_return_pattern("/e", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(result);
}

#[tokio::test]
async fn apply_action_with_agent_in_active_mode_ban() {
    let tracker = BehaviorTracker::new(base_config());
    let (agent, handler) = new_agent();
    tracker.initialize_agent(handler).await;
    let ipban = Arc::new(IPBanManager::new());
    tracker.set_ipban_manager(ipban.clone());
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Ban);
    tracker
        .apply_action(&rule, "10.0.0.9", "/api", "too many")
        .await
        .expect("apply");
    assert!(ipban.is_ip_banned("10.0.0.9").await.expect("banned"));
    let events: Vec<Value> = agent.events.read().iter().cloned().collect();
    assert!(!events.is_empty());
}

#[tokio::test]
async fn apply_action_ban_without_ipban_manager() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Ban);
    tracker
        .apply_action(&rule, "10.0.0.9", "/api", "test")
        .await
        .expect("apply");
}

#[tokio::test]
async fn apply_action_with_agent_failure_is_logged() {
    let tracker = BehaviorTracker::new(base_config());
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    tracker.initialize_agent(handler).await;
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Log);
    tracker
        .apply_action(&rule, "10.0.0.10", "/api", "test")
        .await
        .expect("apply tolerates agent error");
}

#[tokio::test]
async fn apply_action_passive_mode_logs() {
    let tracker = BehaviorTracker::new(passive_config());
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Ban);
    tracker
        .apply_action(&rule, "10.0.0.11", "/api", "test")
        .await
        .expect("apply");
    let rule2 = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Log);
    tracker
        .apply_action(&rule2, "10.0.0.12", "/api", "test")
        .await
        .expect("apply");
    let rule3 =
        BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Throttle);
    tracker
        .apply_action(&rule3, "10.0.0.13", "/api", "test")
        .await
        .expect("apply");
    let rule4 = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Alert);
    tracker
        .apply_action(&rule4, "10.0.0.14", "/api", "test")
        .await
        .expect("apply");
}

#[tokio::test]
async fn apply_action_active_mode_all_actions() {
    let tracker = BehaviorTracker::new(base_config());
    for action in [BehaviorAction::Log, BehaviorAction::Throttle, BehaviorAction::Alert] {
        let rule = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, action);
        tracker
            .apply_action(&rule, "10.0.0.20", "/api", "details")
            .await
            .expect("apply");
    }
}

#[tokio::test]
async fn apply_action_custom_action_takes_precedence() {
    let tracker = BehaviorTracker::new(base_config());
    let flag = Arc::new(Mutex::new(false));
    let f2 = flag.clone();
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Ban)
        .with_custom_action(Arc::new(move |_ip, _endpoint, _details| {
            let f = f2.clone();
            Box::pin(async move {
                *f.lock() = true;
            })
        }));
    tracker
        .apply_action(&rule, "10.0.0.21", "/api", "custom")
        .await
        .expect("apply");
    assert!(*flag.lock());
}

#[tokio::test]
async fn behavior_tracker_debug_impl() {
    let tracker = BehaviorTracker::new(base_config());
    let s = format!("{tracker:?}");
    assert!(s.contains("BehaviorTracker"));
}

#[tokio::test]
async fn exercise_shared_response_factory() {
    use mock_response::MockResponseFactory;
    let factory = Arc::new(MockResponseFactory::default());
    let _created = factory.created.read().len();
}

#[tokio::test]
async fn track_return_pattern_body_none_returns_false() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("needle".into()),
        BehaviorAction::Log,
    );
    let response = Arc::new(NoBodyResponse) as DynGuardResponse;
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn apply_action_passive_agent_event_uses_logged_only() {
    let tracker = BehaviorTracker::new(passive_config());
    let (agent, handler) = new_agent();
    tracker.initialize_agent(handler).await;
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 1, 60, None, BehaviorAction::Ban);
    tracker
        .apply_action(&rule, "10.0.0.99", "/api", "pass")
        .await
        .expect("apply");
    let events: Vec<Value> = agent.events.read().iter().cloned().collect();
    let first = events.first().expect("event");
    assert_eq!(
        first.get("action_taken").and_then(Value::as_str),
        Some("logged_only")
    );
}

#[tokio::test]
async fn track_return_pattern_json_returns_non_string_types() {
    let tracker = BehaviorTracker::new(base_config());
    let rule_null = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:x == 'null'".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, r#"{"x": null}"#);
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule_null)
        .await
        .expect("null");
    assert!(result);

    let rule_bool = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:x == 'true'".into()),
        BehaviorAction::Log,
    );
    let response_bool: DynGuardResponse = MockResponse::new(200, r#"{"x": true}"#);
    let result_bool = tracker
        .track_return_pattern("/api", "1.1.1.1", &response_bool, &rule_bool)
        .await
        .expect("bool");
    assert!(result_bool);

    let rule_num = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:x == '42'".into()),
        BehaviorAction::Log,
    );
    let response_num: DynGuardResponse = MockResponse::new(200, r#"{"x": 42}"#);
    let result_num = tracker
        .track_return_pattern("/api", "1.1.1.1", &response_num, &rule_num)
        .await
        .expect("num");
    assert!(result_num);

    let rule_arr = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:arr[] == '{\"n\":1}'".into()),
        BehaviorAction::Log,
    );
    let response_arr: DynGuardResponse = MockResponse::new(200, r#"{"arr": [{"n":1}]}"#);
    let _ = tracker
        .track_return_pattern("/api", "1.1.1.1", &response_arr, &rule_arr)
        .await
        .expect("arr");
}

#[tokio::test]
async fn track_return_pattern_array_path_with_non_object_root() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:list[] == 'x'".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, r#"["just","array"]"#);
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_array_missing_key_returns_false() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:missing[] == 'x'".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, r#"{"list":[1]}"#);
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[tokio::test]
async fn track_return_pattern_nested_non_object_returns_false() {
    let tracker = BehaviorTracker::new(base_config());
    let rule = BehaviorRule::new(
        BehaviorRuleType::ReturnPattern,
        0,
        60,
        Some("json:a.b.c == 'v'".into()),
        BehaviorAction::Log,
    );
    let response: DynGuardResponse = MockResponse::new(200, r#"{"a": {"b": "scalar"}}"#);
    let result = tracker
        .track_return_pattern("/api", "1.1.1.1", &response, &rule)
        .await
        .expect("track");
    assert!(!result);
}

#[derive(Debug)]
struct NoBodyResponse;

impl guard_core_rs::protocols::response::GuardResponse for NoBodyResponse {
    fn status_code(&self) -> u16 {
        404
    }
    fn headers(&self) -> std::collections::HashMap<String, String> {
        Default::default()
    }
    fn set_header(&self, _name: &str, _value: &str) {}
    fn remove_header(&self, _name: &str) {}
    fn body(&self) -> Option<bytes::Bytes> {
        None
    }
}

#[derive(Debug)]
struct BinaryResponse {
    body: bytes::Bytes,
}

impl guard_core_rs::protocols::response::GuardResponse for BinaryResponse {
    fn status_code(&self) -> u16 {
        500
    }
    fn headers(&self) -> std::collections::HashMap<String, String> {
        Default::default()
    }
    fn set_header(&self, _name: &str, _value: &str) {}
    fn remove_header(&self, _name: &str) {}
    fn body(&self) -> Option<bytes::Bytes> {
        Some(self.body.clone())
    }
}
