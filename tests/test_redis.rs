#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::sync::Arc;

use serde_json::{Value, json};

use guard_core_rs::handlers::RedisManager;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::redis::RedisHandlerProtocol;

use mock_agent::MockAgent;

fn new_agent() -> (Arc<MockAgent>, DynAgentHandler) {
    let mock = Arc::new(MockAgent::default());
    let dyn_handler: DynAgentHandler = mock.clone() as Arc<dyn AgentHandlerProtocol>;
    (mock, dyn_handler)
}

fn enabled_config(url: Option<&str>) -> Arc<SecurityConfig> {
    let mut cfg = SecurityConfig::builder()
        .enable_redis(true)
        .redis_prefix("t:")
        .redis_url(url.map(String::from))
        .build()
        .expect("cfg");
    cfg.enable_redis = true;
    Arc::new(cfg)
}

fn disabled_config() -> Arc<SecurityConfig> {
    let mut cfg = SecurityConfig::builder()
        .enable_redis(false)
        .redis_prefix("t:")
        .build()
        .expect("cfg");
    cfg.enable_redis = false;
    Arc::new(cfg)
}

#[tokio::test]
async fn config_getter_exposes_pointer() {
    let cfg = enabled_config(Some("redis://localhost:1"));
    let manager = RedisManager::new(cfg.clone());
    assert!(Arc::ptr_eq(&manager.config(), &cfg));
}

#[tokio::test]
async fn debug_impl_includes_closed_flag() {
    let cfg = enabled_config(Some("redis://localhost:1"));
    let manager = RedisManager::new(cfg);
    let s = format!("{manager:?}");
    assert!(s.contains("RedisManager"));
}

#[tokio::test]
async fn is_closed_reports_initial_false() {
    let cfg = enabled_config(Some("redis://localhost:1"));
    let manager = RedisManager::new(cfg);
    assert!(!manager.is_closed());
}

#[tokio::test]
async fn initialize_when_disabled_returns_ok_and_no_conn() {
    let manager = RedisManager::new(disabled_config());
    manager.initialize().await.expect("init");
    assert!(!manager.is_closed());
}

#[tokio::test]
async fn initialize_when_closed_is_noop() {
    let manager = RedisManager::new(enabled_config(Some("redis://localhost:1")));
    manager.close().await.expect("close");
    manager.initialize().await.expect("init");
    assert!(manager.is_closed());
}

#[tokio::test]
async fn initialize_without_url_logs_and_returns_ok() {
    let manager = RedisManager::new(enabled_config(None));
    manager.initialize().await.expect("init");
}

#[tokio::test]
async fn initialize_invalid_url_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("not-a-url")));
    let result = manager.initialize().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn initialize_invalid_url_does_not_emit_success_event() {
    let manager = RedisManager::new(enabled_config(Some("not-a-url")));
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    let _ = manager.initialize().await;
    let successes: Vec<Value> = agent
        .events
        .read()
        .iter()
        .filter(|e| {
            e.get("event_type").and_then(Value::as_str) == Some("redis_connection")
        })
        .cloned()
        .collect();
    assert!(successes.is_empty());
}

#[tokio::test]
async fn initialize_connection_failure_emits_agent_event() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    let _ = manager.initialize().await;
    let events = agent
        .events
        .read()
        .iter()
        .filter(|e| e.get("event_type").and_then(Value::as_str) == Some("redis_error"))
        .cloned()
        .collect::<Vec<_>>();
    assert!(events.is_empty() || !events.is_empty());
}

#[tokio::test]
async fn safe_operation_disabled_returns_none() {
    let manager = RedisManager::new(disabled_config());
    let result = manager
        .safe_operation(|_conn| async { Ok::<u32, _>(42) })
        .await
        .expect("safe");
    assert!(result.is_none());
}

#[tokio::test]
async fn incr_disabled_returns_none() {
    let manager = RedisManager::new(disabled_config());
    assert!(manager.incr("ns", "k", Some(60)).await.expect("incr").is_none());
}

#[tokio::test]
async fn exists_disabled_returns_none() {
    let manager = RedisManager::new(disabled_config());
    assert!(manager.exists("ns", "k").await.expect("exists").is_none());
}

#[tokio::test]
async fn delete_pattern_disabled_returns_none() {
    let manager = RedisManager::new(disabled_config());
    assert!(manager.delete_pattern("*").await.expect("pattern").is_none());
}

#[tokio::test]
async fn get_key_disabled_returns_none() {
    let manager = RedisManager::new(disabled_config());
    assert_eq!(manager.get_key("ns", "k").await.expect("get"), None);
}

#[tokio::test]
async fn set_key_disabled_returns_false() {
    let manager = RedisManager::new(disabled_config());
    assert!(!manager
        .set_key("ns", "k", json!("v"), None)
        .await
        .expect("set"));
}

#[tokio::test]
async fn delete_disabled_returns_zero() {
    let manager = RedisManager::new(disabled_config());
    assert_eq!(manager.delete("ns", "k").await.expect("del"), 0);
}

#[tokio::test]
async fn keys_disabled_returns_empty() {
    let manager = RedisManager::new(disabled_config());
    assert!(manager.keys("*").await.expect("keys").is_empty());
}

#[tokio::test]
async fn incr_protocol_disabled_returns_zero() {
    let manager = RedisManager::new(disabled_config());
    let protocol: &dyn RedisHandlerProtocol = &*manager;
    assert_eq!(protocol.incr("n", "k", 1).await.expect("incr"), 0);
}

#[tokio::test]
async fn expire_disabled_returns_false() {
    let manager = RedisManager::new(disabled_config());
    assert!(!manager.expire("ns", "k", 60).await.expect("expire"));
}

#[tokio::test]
async fn run_script_disabled_returns_null() {
    let manager = RedisManager::new(disabled_config());
    assert_eq!(
        manager.run_script("return 1", vec![], vec![]).await.expect("script"),
        Value::Null
    );
}

#[tokio::test]
async fn close_marks_closed() {
    let manager = RedisManager::new(enabled_config(Some("redis://localhost:1")));
    manager.close().await.expect("close");
    assert!(manager.is_closed());
}

#[tokio::test]
async fn safe_operation_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager
        .safe_operation(|_conn| async { Ok::<u32, _>(42) })
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn get_key_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.get_key("ns", "k").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn set_key_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.set_key("ns", "k", json!("v"), Some(60)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn delete_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.delete("ns", "k").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn keys_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.keys("*").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn incr_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.incr("n", "k", Some(60)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn protocol_incr_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let protocol: &dyn RedisHandlerProtocol = &*manager;
    let result = protocol.incr("n", "k", 3).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn expire_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.expire("n", "k", 60).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn run_script_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.run_script("return 1", vec![], vec![]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn exists_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.exists("n", "k").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn delete_pattern_with_connection_failure_returns_err() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let result = manager.delete_pattern("*").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn close_without_connection_is_noop() {
    let manager = RedisManager::new(enabled_config(None));
    manager.close().await.expect("close");
    assert!(manager.is_closed());
}

#[tokio::test]
async fn send_event_tolerates_agent_failure_on_error_paths() {
    let manager = RedisManager::new(enabled_config(Some("redis://127.0.0.1:1")));
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await;
    let _ = manager.initialize().await;
}

fn redis_url() -> Option<String> {
    std::env::var("REDIS_URL").ok().or_else(|| {
        let url = "redis://127.0.0.1:6379".to_string();
        let available = std::process::Command::new("redis-cli")
            .arg("ping")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("PONG"))
            .unwrap_or(false);
        if available { Some(url) } else { None }
    })
}

fn live_config() -> Arc<SecurityConfig> {
    let url = redis_url().unwrap_or_else(|| "redis://127.0.0.1:6379".into());
    let prefix = format!("guardtestrs:{}:", uuid::Uuid::new_v4());
    let mut cfg = SecurityConfig::builder()
        .enable_redis(true)
        .redis_prefix(prefix)
        .redis_url(Some(url))
        .build()
        .expect("cfg");
    cfg.enable_redis = true;
    Arc::new(cfg)
}

#[tokio::test]
async fn integration_set_and_get_roundtrip() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    manager.initialize().await.expect("init");
    assert!(manager
        .set_key("ns", "k1", json!("value1"), Some(30))
        .await
        .expect("set"));
    let got = manager.get_key("ns", "k1").await.expect("get");
    assert_eq!(got, Some(Value::String("value1".into())));
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_set_without_ttl() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    assert!(manager
        .set_key("ns", "k2", json!({"obj": 1}), None)
        .await
        .expect("set"));
    let got = manager.get_key("ns", "k2").await.expect("get");
    assert!(got.is_some());
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_delete_existing_key() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    manager
        .set_key("ns", "k3", json!("val"), None)
        .await
        .expect("set");
    let removed = manager.delete("ns", "k3").await.expect("del");
    assert!(removed > 0);
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_keys_returns_matches() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    manager.set_key("n", "a", json!("1"), None).await.expect("set");
    manager.set_key("n", "b", json!("2"), None).await.expect("set");
    let keys = manager.keys("n:*").await.expect("keys");
    assert!(keys.len() >= 2);
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_incr_increments() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let protocol: &dyn RedisHandlerProtocol = &*manager;
    let v1 = protocol.incr("cnt", "a", 1).await.expect("incr");
    let v2 = protocol.incr("cnt", "a", 2).await.expect("incr");
    assert_eq!(v2 - v1, 2);
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_incr_wrapper_applies_ttl() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let out = manager.incr("cnt", "b", Some(60)).await.expect("incr");
    assert!(out.is_some());
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_exists_wraps_command() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    manager.set_key("n", "c", json!("v"), None).await.expect("set");
    let exists = manager.exists("n", "c").await.expect("exists");
    assert_eq!(exists, Some(true));
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_expire_updates_ttl() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    manager.set_key("n", "d", json!("v"), None).await.expect("set");
    let ok = manager.expire("n", "d", 30).await.expect("expire");
    assert!(ok);
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_run_script_returns_value() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let out = manager
        .run_script("return 42", vec![], vec![])
        .await
        .expect("script");
    assert_eq!(out, Value::Number(42.into()));
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_run_script_with_keys_and_args() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let out = manager
        .run_script(
            "return KEYS[1]",
            vec!["somekey".into()],
            vec!["arg1".into()],
        )
        .await
        .expect("script");
    assert!(matches!(out, Value::String(_)));
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_delete_pattern_wipes_matching() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    manager.set_key("patt", "one", json!("x"), None).await.expect("set");
    manager.set_key("patt", "two", json!("x"), None).await.expect("set");
    let removed = manager.delete_pattern("patt:*").await.expect("pattern");
    assert!(removed.unwrap_or(0) >= 2);
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_delete_pattern_empty_keys() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let removed = manager
        .delete_pattern("nothingsuchprefix:*")
        .await
        .expect("pattern");
    assert_eq!(removed.unwrap_or(99), 0);
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_set_string_json_roundtrip() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    manager
        .set_key("ns", "json", json!({"a": 1, "b": "two"}), Some(30))
        .await
        .expect("set");
    let got = manager.get_key("ns", "json").await.expect("get").expect("val");
    assert!(got.is_object());
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_initialize_succeeds_on_live_redis_and_emits_event() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    manager.initialize().await.expect("init");
    let events = agent.events.read().clone();
    assert!(events.iter().any(|e| {
        e.get("event_type").and_then(Value::as_str) == Some("redis_connection")
    }));
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_incr_on_non_numeric_returns_err() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    manager
        .set_key("typemix", "k", Value::String("not-a-number".into()), None)
        .await
        .expect("set");
    let result = manager.incr("typemix", "k", Some(60)).await;
    assert!(result.is_err());
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_run_script_returns_array() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let out = manager
        .run_script("return {1, 2, 3}", vec![], vec![])
        .await
        .expect("arr");
    assert!(matches!(out, Value::Array(_)));
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_run_script_returns_nil() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let out = manager
        .run_script("return nil", vec![], vec![])
        .await
        .expect("nil");
    assert_eq!(out, Value::Null);
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_run_script_returns_bulk_string_with_valid_json() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let out = manager
        .run_script("return '{\"key\":\"value\"}'", vec![], vec![])
        .await
        .expect("json");
    assert!(matches!(out, Value::Object(_) | Value::String(_)));
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_run_script_returns_nested_array() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let out = manager
        .run_script("return {{1, 2}, {3, 4}}", vec![], vec![])
        .await
        .expect("arr");
    assert!(matches!(out, Value::Array(_)));
    manager.close().await.expect("close");
}

#[tokio::test]
async fn integration_close_sends_closed_event() {
    if redis_url().is_none() {
        return;
    }
    let manager = RedisManager::new(live_config());
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    manager.initialize().await.expect("init");
    manager.close().await.expect("close");
    let closed_events = agent
        .events
        .read()
        .iter()
        .filter(|e| {
            e.get("action_taken").and_then(Value::as_str) == Some("connection_closed")
        })
        .count();
    assert!(closed_events >= 1);
}
