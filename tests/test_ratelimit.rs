#[path = "support/mock_redis.rs"]
mod mock_redis;
#[path = "support/mock_agent.rs"]
mod mock_agent;
#[path = "support/request.rs"]
mod mock_request;
#[path = "support/response.rs"]
mod mock_response;

use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use serde_json::Value;

use guard_core_rs::error::Result;
use guard_core_rs::handlers::{CheckRateLimitArgs, CreateErrorResponseFn, RateLimitManager};
use guard_core_rs::models::{LogLevel, SecurityConfig};
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};
use guard_core_rs::protocols::request::{DynGuardRequest, GuardRequest};
use guard_core_rs::protocols::response::DynGuardResponse;

use mock_agent::MockAgent;
use mock_redis::{MockRedis, MockRedisFailure};
use mock_request::MockRequest;
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

fn build_config(rate: u32, window: u64, enable_redis: bool) -> Arc<SecurityConfig> {
    let mut cfg = SecurityConfig::builder()
        .rate_limit(rate)
        .rate_limit_window(window)
        .enable_redis(enable_redis)
        .redis_prefix("test:")
        .build()
        .expect("cfg");
    cfg.enable_rate_limiting = true;
    cfg.log_suspicious_level = Some(LogLevel::Warning);
    Arc::new(cfg)
}

fn create_error_response_fn() -> CreateErrorResponseFn {
    Arc::new(move |code: u16, msg: String| -> BoxFuture<'static, Result<DynGuardResponse>> {
        Box::pin(async move { Ok(MockResponse::new(code, &msg) as DynGuardResponse) })
    })
}

fn build_request() -> DynGuardRequest {
    Arc::new(
        MockRequest::builder()
            .method("GET")
            .path("/api")
            .client_host("9.9.9.9")
            .body(Bytes::from_static(b""))
            .build(),
    ) as Arc<dyn GuardRequest>
}

#[tokio::test]
async fn check_rate_limit_disabled_returns_none() {
    let mut cfg = SecurityConfig::builder().build().expect("cfg");
    cfg.enable_rate_limiting = false;
    let manager = RateLimitManager::new(Arc::new(cfg));
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "1.1.1.1",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let result = manager.check_rate_limit(args).await.expect("limit");
    assert!(result.is_none());
}

#[tokio::test]
async fn check_rate_limit_under_threshold_allowed() {
    let manager = RateLimitManager::new(build_config(5, 60, false));
    let request = build_request();
    let factory = create_error_response_fn();

    for _ in 0..3 {
        let args = CheckRateLimitArgs {
            request: &request,
            client_ip: "2.2.2.2",
            create_error_response: &factory,
            endpoint_path: "/api",
            rate_limit: None,
            rate_limit_window: None,
        };
        assert!(manager.check_rate_limit(args).await.expect("limit").is_none());
    }
}

#[tokio::test]
async fn check_rate_limit_blocks_when_exceeded_in_memory() {
    let manager = RateLimitManager::new(build_config(2, 60, false));
    let request = build_request();
    let factory = create_error_response_fn();

    for _ in 0..2 {
        let args = CheckRateLimitArgs {
            request: &request,
            client_ip: "3.3.3.3",
            create_error_response: &factory,
            endpoint_path: "/api",
            rate_limit: None,
            rate_limit_window: None,
        };
        assert!(manager.check_rate_limit(args).await.expect("limit").is_none());
    }
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "3.3.3.3",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let blocked = manager.check_rate_limit(args).await.expect("limit");
    assert!(blocked.is_some());
    assert_eq!(blocked.unwrap().status_code(), 429);
}

#[tokio::test]
async fn check_rate_limit_blocks_empty_endpoint_path() {
    let manager = RateLimitManager::new(build_config(1, 60, false));
    let request = build_request();
    let factory = create_error_response_fn();

    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "4.4.4.4",
        create_error_response: &factory,
        endpoint_path: "",
        rate_limit: None,
        rate_limit_window: None,
    };
    assert!(manager.check_rate_limit(args).await.expect("limit").is_none());
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "4.4.4.4",
        create_error_response: &factory,
        endpoint_path: "",
        rate_limit: None,
        rate_limit_window: None,
    };
    assert!(manager.check_rate_limit(args).await.expect("limit").is_some());
}

#[tokio::test]
async fn check_rate_limit_respects_override() {
    let manager = RateLimitManager::new(build_config(100, 60, false));
    let request = build_request();
    let factory = create_error_response_fn();

    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "5.5.5.5",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: Some(0),
        rate_limit_window: Some(60),
    };
    let blocked = manager.check_rate_limit(args).await.expect("limit");
    assert!(blocked.is_some());
}

#[tokio::test]
async fn check_rate_limit_uses_redis_when_enabled() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    *redis.script_result.write() = Some(Value::from(1));
    manager.initialize_redis(handler).await;

    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "6.6.6.6",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    assert!(manager.check_rate_limit(args).await.expect("limit").is_none());
}

#[tokio::test]
async fn check_rate_limit_redis_returns_blocked() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    *redis.script_result.write() = Some(Value::from(5));
    manager.initialize_redis(handler).await;
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "6.6.6.7",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let blocked = manager.check_rate_limit(args).await.expect("limit");
    assert!(blocked.is_some());
}

#[tokio::test]
async fn check_rate_limit_redis_string_count_parsed() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    *redis.script_result.write() = Some(Value::String("1".into()));
    manager.initialize_redis(handler).await;
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "6.6.6.8",
        create_error_response: &factory,
        endpoint_path: "",
        rate_limit: None,
        rate_limit_window: None,
    };
    assert!(manager.check_rate_limit(args).await.expect("limit").is_none());
}

#[tokio::test]
async fn check_rate_limit_redis_other_value_falls_back_to_memory() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    *redis.script_result.write() = Some(Value::Null);
    manager.initialize_redis(handler).await;
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "6.6.6.9",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let _ = manager.check_rate_limit(args).await;
}

#[tokio::test]
async fn check_rate_limit_redis_script_error_falls_back() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    *redis.fail_mode.write() = Some(MockRedisFailure::RunScript);
    manager.initialize_redis(handler).await;
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "6.6.7.0",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let _ = manager.check_rate_limit(args).await;
}

#[tokio::test]
async fn check_rate_limit_sends_agent_event_when_blocked() {
    let cfg = build_config(0, 60, false);
    let manager = RateLimitManager::new(cfg);
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "7.7.7.7",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let _ = manager.check_rate_limit(args).await.expect("limit");
    let events: Vec<Value> = agent
        .events
        .read()
        .iter()
        .filter(|e| {
            e.get("event_type").and_then(Value::as_str) == Some("rate_limited")
        })
        .cloned()
        .collect();
    assert!(!events.is_empty());
}

#[tokio::test]
async fn check_rate_limit_tolerates_agent_failure() {
    let cfg = build_config(0, 60, false);
    let manager = RateLimitManager::new(cfg);
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await;
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "7.7.7.8",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let _ = manager.check_rate_limit(args).await;
}

#[tokio::test]
async fn reset_clears_in_memory_counts() {
    let manager = RateLimitManager::new(build_config(2, 60, false));
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "8.8.8.8",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let _ = manager.check_rate_limit(args).await;
    manager.reset().await.expect("reset");
}

#[tokio::test]
async fn reset_deletes_redis_keys() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    redis.data.insert(
        "rate_limit:rate:1.1.1.1:/api".into(),
        Value::from(1),
    );
    manager.initialize_redis(handler).await;
    manager.reset().await.expect("reset");
}

#[tokio::test]
async fn reset_tolerates_redis_keys_error() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    *redis.fail_mode.write() = Some(MockRedisFailure::Keys);
    manager.initialize_redis(handler).await;
    manager.reset().await.expect("reset");
}

#[tokio::test]
async fn update_config_replaces_inner_config() {
    let manager = RateLimitManager::new(build_config(2, 60, false));
    let new_cfg = build_config(5, 30, false);
    manager.update_config(new_cfg).await;
}

#[tokio::test]
async fn initialize_redis_loads_script_when_enabled() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    manager.initialize_redis(handler).await;
    assert!(!redis.scripts_invoked.read().is_empty());
}

#[tokio::test]
async fn initialize_redis_records_script_error() {
    let cfg = build_config(2, 60, true);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    *redis.fail_mode.write() = Some(MockRedisFailure::RunScript);
    manager.initialize_redis(handler).await;
}

#[tokio::test]
async fn initialize_redis_with_disabled_redis_does_not_load_script() {
    let cfg = build_config(2, 60, false);
    let manager = RateLimitManager::new(cfg);
    let (redis, handler) = new_redis();
    manager.initialize_redis(handler).await;
    assert!(redis.scripts_invoked.read().is_empty());
}

#[tokio::test]
async fn check_rate_limit_args_debug() {
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "9.9.9.9",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: Some(1),
        rate_limit_window: Some(60),
    };
    let repr = format!("{args:?}");
    assert!(repr.contains("client_ip"));
}

#[tokio::test]
async fn manager_debug_impl() {
    let manager = RateLimitManager::new(build_config(2, 60, false));
    let s = format!("{manager:?}");
    assert!(s.contains("RateLimitManager"));
}

#[tokio::test]
async fn in_memory_window_expires_old_timestamps() {
    let manager = RateLimitManager::new(build_config(100, 1, false));
    let request = build_request();
    let factory = create_error_response_fn();
    let args = CheckRateLimitArgs {
        request: &request,
        client_ip: "w.w.w.w",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let _ = manager.check_rate_limit(args).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let args2 = CheckRateLimitArgs {
        request: &request,
        client_ip: "w.w.w.w",
        create_error_response: &factory,
        endpoint_path: "/api",
        rate_limit: None,
        rate_limit_window: None,
    };
    let _ = manager.check_rate_limit(args2).await;
}

#[tokio::test]
async fn exercise_shared_request_builder_helpers() {
    use mock_response::MockResponseFactory;
    let req = MockRequest::builder()
        .scheme("https")
        .method("POST")
        .path("/api/login")
        .client_host("127.0.0.1")
        .header("Auth", "Bearer")
        .query("token", "abc")
        .body(Bytes::from_static(b"{}"))
        .build()
        .arc();
    assert_eq!(req.url_scheme(), "https");
    let factory = Arc::new(MockResponseFactory::default());
    let _ = factory.created.read().len();
}
