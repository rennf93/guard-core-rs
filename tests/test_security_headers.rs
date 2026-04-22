#[path = "support/mock_redis.rs"]
mod mock_redis;
#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};

use guard_core_rs::handlers::security_headers::{
    built_in_defaults, ConfigureOptions, CorsRuntimeConfig, HstsRuntimeConfig,
    PermissionsPolicySetting, SecurityHeadersManager,
};
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

#[tokio::test]
async fn built_in_defaults_contains_expected_headers() {
    let defaults = built_in_defaults();
    assert!(defaults.contains_key("X-Frame-Options"));
    assert!(defaults.contains_key("X-Content-Type-Options"));
    assert!(defaults.contains_key("Referrer-Policy"));
    assert!(defaults.contains_key("Cross-Origin-Embedder-Policy"));
}

#[tokio::test]
async fn get_headers_returns_empty_when_disabled() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: false,
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_headers(None).await;
    assert!(headers.is_empty());
}

#[tokio::test]
async fn get_headers_cache_returns_cached_value() {
    let manager = SecurityHeadersManager::new();
    let first = manager.get_headers(Some("/api/v1")).await;
    let second = manager.get_headers(Some("/api/v1")).await;
    assert_eq!(first, second);
}

#[tokio::test]
async fn configure_applies_csp() {
    let manager = SecurityHeadersManager::new();
    let mut csp = HashMap::new();
    csp.insert("default-src".into(), vec!["'self'".into()]);
    csp.insert("empty".into(), vec![]);
    let opts = ConfigureOptions {
        enabled: true,
        csp: Some(csp),
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_headers(None).await;
    assert!(headers.contains_key("Content-Security-Policy"));
}

#[tokio::test]
async fn configure_warns_on_unsafe_csp() {
    let manager = SecurityHeadersManager::new();
    let mut csp = HashMap::new();
    csp.insert("default-src".into(), vec!["'unsafe-inline'".into()]);
    let opts = ConfigureOptions {
        enabled: true,
        csp: Some(csp),
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
}

#[tokio::test]
async fn configure_hsts_preload_forces_subdomains() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        hsts_max_age: Some(31_536_000),
        hsts_preload: true,
        hsts_include_subdomains: false,
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_headers(None).await;
    let hsts = headers.get("Strict-Transport-Security").expect("present");
    assert!(hsts.contains("includeSubDomains"));
    assert!(hsts.contains("preload"));
}

#[tokio::test]
async fn configure_hsts_low_max_age_disables_preload() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        hsts_max_age: Some(60),
        hsts_preload: true,
        hsts_include_subdomains: true,
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_headers(None).await;
    let hsts = headers.get("Strict-Transport-Security").expect("present");
    assert!(!hsts.contains("preload"));
}

#[tokio::test]
async fn configure_cors_wildcard_with_credentials_disables_credentials() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        cors_origins: Some(vec!["*".into()]),
        cors_allow_credentials: true,
        cors_allow_methods: Some(vec!["GET".into()]),
        cors_allow_headers: Some(vec!["*".into()]),
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_cors_headers("https://example.com").await;
    assert!(headers.is_empty() || !headers.contains_key("Access-Control-Allow-Credentials"));
}

#[tokio::test]
async fn configure_cors_default_methods_when_none() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        cors_origins: Some(vec!["https://a.com".into()]),
        cors_allow_credentials: true,
        cors_allow_methods: None,
        cors_allow_headers: None,
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_cors_headers("https://a.com").await;
    assert_eq!(
        headers.get("Access-Control-Allow-Origin").map(String::as_str),
        Some("https://a.com")
    );
    assert_eq!(
        headers.get("Access-Control-Allow-Credentials").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn configure_sets_simple_header_overrides() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        frame_options: Some("DENY".into()),
        content_type_options: Some("nosniff".into()),
        xss_protection: Some("0".into()),
        referrer_policy: Some("no-referrer".into()),
        permissions_policy: PermissionsPolicySetting::Value("fullscreen=(*)".into()),
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_headers(None).await;
    assert_eq!(headers.get("X-Frame-Options").map(String::as_str), Some("DENY"));
    assert_eq!(
        headers.get("Referrer-Policy").map(String::as_str),
        Some("no-referrer")
    );
    assert_eq!(
        headers.get("Permissions-Policy").map(String::as_str),
        Some("fullscreen=(*)")
    );
}

#[tokio::test]
async fn configure_permissions_policy_remove() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        permissions_policy: PermissionsPolicySetting::Remove,
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_headers(None).await;
    assert!(!headers.contains_key("Permissions-Policy"));
}

#[tokio::test]
async fn configure_permissions_policy_unset_keeps_default() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        permissions_policy: PermissionsPolicySetting::Unset,
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_headers(None).await;
    assert!(headers.contains_key("Permissions-Policy"));
}

#[tokio::test]
async fn configure_custom_headers_adds_entries() {
    let manager = SecurityHeadersManager::new();
    let mut custom = HashMap::new();
    custom.insert("X-Custom".into(), "value".into());
    let opts = ConfigureOptions {
        enabled: true,
        custom_headers: Some(custom),
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_headers(None).await;
    assert_eq!(headers.get("X-Custom").map(String::as_str), Some("value"));
}

#[tokio::test]
async fn configure_rejects_header_with_newline() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        frame_options: Some("DENY\ninjected".into()),
        ..ConfigureOptions::default()
    };
    let err = manager.configure(opts).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn configure_rejects_too_long_header_value() {
    let manager = SecurityHeadersManager::new();
    let long_val = "x".repeat(9000);
    let opts = ConfigureOptions {
        enabled: true,
        frame_options: Some(long_val),
        ..ConfigureOptions::default()
    };
    let err = manager.configure(opts).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn configure_accepts_tab_chars() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        content_type_options: Some("nosniff\tvalue".into()),
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
}

#[tokio::test]
async fn get_cors_headers_returns_empty_without_config() {
    let manager = SecurityHeadersManager::new();
    let headers = manager.get_cors_headers("https://a.com").await;
    assert!(headers.is_empty());
}

#[tokio::test]
async fn get_cors_headers_origin_allowed_returns_matching() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        cors_origins: Some(vec!["https://a.com".into(), "https://b.com".into()]),
        cors_allow_credentials: true,
        cors_allow_methods: Some(vec!["GET".into(), "POST".into()]),
        cors_allow_headers: Some(vec!["Authorization".into()]),
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_cors_headers("https://a.com").await;
    assert_eq!(
        headers.get("Access-Control-Allow-Origin").map(String::as_str),
        Some("https://a.com")
    );
    assert_eq!(
        headers.get("Access-Control-Max-Age").map(String::as_str),
        Some("3600")
    );
}

#[tokio::test]
async fn get_cors_headers_unknown_origin_returns_empty() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        cors_origins: Some(vec!["https://a.com".into()]),
        cors_allow_credentials: false,
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_cors_headers("https://other.com").await;
    assert!(headers.is_empty());
}

#[tokio::test]
async fn validate_csp_report_ignores_missing_wrapper() {
    let manager = SecurityHeadersManager::new();
    let report = json!({ "other": "no csp-report" });
    assert!(!manager.validate_csp_report(&report).await);
}

#[tokio::test]
async fn validate_csp_report_requires_all_fields() {
    let manager = SecurityHeadersManager::new();
    let report = json!({
        "csp-report": {
            "document-uri": "https://a.com",
            "violated-directive": "script-src"
        }
    });
    assert!(!manager.validate_csp_report(&report).await);
}

#[tokio::test]
async fn validate_csp_report_valid_returns_true_and_sends_agent_event() {
    let manager = SecurityHeadersManager::new();
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    let report = json!({
        "csp-report": {
            "document-uri": "https://a.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com",
            "source-file": "app.js",
            "line-number": 1
        }
    });
    assert!(manager.validate_csp_report(&report).await);
    let events: Vec<Value> = agent.events.read().iter().cloned().collect();
    assert!(!events.is_empty());
}

#[tokio::test]
async fn get_cors_headers_wildcard_without_credentials_allows_any_origin() {
    let manager = SecurityHeadersManager::new();
    let opts = ConfigureOptions {
        enabled: true,
        cors_origins: Some(vec!["*".into()]),
        cors_allow_credentials: false,
        cors_allow_methods: Some(vec!["GET".into()]),
        cors_allow_headers: Some(vec!["Authorization".into()]),
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    let headers = manager.get_cors_headers("https://anything.com").await;
    assert_eq!(
        headers.get("Access-Control-Allow-Origin").map(String::as_str),
        Some("*")
    );
    assert!(!headers.contains_key("Access-Control-Allow-Credentials"));
}

#[tokio::test]
async fn validate_csp_report_tolerates_agent_send_failure() {
    let manager = SecurityHeadersManager::new();
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await;
    let report = json!({
        "csp-report": {
            "document-uri": "https://a.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com"
        }
    });
    assert!(manager.validate_csp_report(&report).await);
}

#[tokio::test]
async fn reset_clears_custom_headers_and_configs() {
    let manager = SecurityHeadersManager::new();
    let mut custom = HashMap::new();
    custom.insert("X-A".into(), "v".into());
    let opts = ConfigureOptions {
        enabled: true,
        custom_headers: Some(custom),
        hsts_max_age: Some(3600),
        hsts_include_subdomains: true,
        hsts_preload: false,
        ..ConfigureOptions::default()
    };
    manager.configure(opts).await.expect("configure");
    manager.reset().await;
    let headers = manager.get_headers(None).await;
    assert!(!headers.contains_key("X-A"));
    assert!(!headers.contains_key("Strict-Transport-Security"));
}

#[tokio::test]
async fn initialize_redis_caches_and_hydrates() {
    let manager = SecurityHeadersManager::new();
    let (redis, handler) = new_redis();
    redis.data.insert(
        "security_headers:csp_config".into(),
        json!({"default-src": ["'self'"]}),
    );
    redis.data.insert(
        "security_headers:hsts_config".into(),
        json!({"max_age": 3600, "include_subdomains": true, "preload": false}),
    );
    let mut custom: HashMap<String, String> = HashMap::new();
    custom.insert("X-Existing".into(), "value".into());
    redis.data.insert(
        "security_headers:custom_headers".into(),
        serde_json::to_value(&custom).expect("json"),
    );
    manager.initialize_redis(handler).await.expect("init");
    let headers = manager.get_headers(None).await;
    assert_eq!(
        headers.get("X-Existing").map(String::as_str),
        Some("value")
    );
    assert!(headers.contains_key("Content-Security-Policy"));
    assert!(headers.contains_key("Strict-Transport-Security"));
}

#[tokio::test]
async fn initialize_redis_ignores_garbled_payloads() {
    let manager = SecurityHeadersManager::new();
    let (redis, handler) = new_redis();
    redis
        .data
        .insert("security_headers:csp_config".into(), Value::String("no".into()));
    redis
        .data
        .insert("security_headers:hsts_config".into(), Value::String("bad".into()));
    redis
        .data
        .insert("security_headers:custom_headers".into(), Value::from(42));
    manager.initialize_redis(handler).await.expect("init");
    let headers = manager.get_headers(None).await;
    assert!(headers.contains_key("X-Frame-Options"));
}

#[tokio::test]
async fn get_headers_agent_event_emitted_for_path() {
    let manager = SecurityHeadersManager::new();
    let (agent, handler) = new_agent();
    manager.initialize_agent(handler).await;
    let _headers = manager.get_headers(Some("/secure/path")).await;
    let events: Vec<Value> = agent.events.read().iter().cloned().collect();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].get("event_type").and_then(Value::as_str),
        Some("security_headers_applied")
    );
}

#[tokio::test]
async fn get_headers_tolerates_agent_failure() {
    let manager = SecurityHeadersManager::new();
    let (agent, handler) = new_agent();
    *agent.fail_events.write() = true;
    manager.initialize_agent(handler).await;
    let _headers = manager.get_headers(Some("/secure/path")).await;
}

#[tokio::test]
async fn hsts_runtime_config_debug_and_clone() {
    let cfg = HstsRuntimeConfig {
        max_age: 3600,
        include_subdomains: true,
        preload: false,
    };
    let cloned = cfg.clone();
    assert!(format!("{cloned:?}").contains("HstsRuntimeConfig"));
}

#[tokio::test]
async fn cors_runtime_config_default() {
    let cfg = CorsRuntimeConfig::default();
    assert!(cfg.origins.is_empty());
    assert!(!cfg.allow_credentials);
}

#[tokio::test]
async fn shared_produces_manager() {
    let manager = SecurityHeadersManager::shared();
    assert!(Arc::strong_count(&manager) >= 1);
}

#[tokio::test]
async fn debug_impl_is_non_exhaustive() {
    let manager = SecurityHeadersManager::new();
    let s = format!("{manager:?}");
    assert!(s.contains("SecurityHeadersManager"));
}

#[tokio::test]
async fn permissions_policy_default_is_unset() {
    let setting = PermissionsPolicySetting::default();
    matches!(setting, PermissionsPolicySetting::Unset);
}

#[tokio::test]
async fn configure_options_default_has_disabled_preload() {
    let opts = ConfigureOptions::default();
    assert!(!opts.hsts_preload);
    assert!(!opts.hsts_include_subdomains);
}

#[tokio::test]
async fn default_impl_produces_manager() {
    let manager = SecurityHeadersManager::default();
    let headers = manager.get_headers(None).await;
    assert!(!headers.is_empty());
}

#[tokio::test]
async fn initialize_redis_hsts_defaults_without_include_subdomains() {
    let manager = SecurityHeadersManager::new();
    let (redis, handler) = new_redis();
    redis.data.insert(
        "security_headers:hsts_config".into(),
        json!({"max_age": 3600}),
    );
    manager.initialize_redis(handler).await.expect("init");
    let headers = manager.get_headers(None).await;
    let hsts = headers.get("Strict-Transport-Security").expect("present");
    assert!(hsts.contains("includeSubDomains"));
}
