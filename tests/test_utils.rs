#[path = "support/request.rs"]
mod mock_request;
#[path = "support/agent.rs"]
mod agent;

use std::sync::Arc;

use async_trait::async_trait;
use guard_core_rs::error::Result;
use guard_core_rs::models::{LogLevel, SecurityConfig};
use guard_core_rs::protocols::agent::DynAgentHandler;
use guard_core_rs::protocols::geo_ip::{DynGeoIpHandler, GeoIpHandler};
use guard_core_rs::protocols::redis::DynRedisHandler;
use guard_core_rs::protocols::request::{GuardRequest, StateValue};
use guard_core_rs::utils::{
    CLIENT_IP_KEY, LOGGER_NAME, LogType, PIPELINE_START_KEY, check_ip_country, extract_client_ip,
    extract_from_forwarded_header, extract_request_context, get_pipeline_response_time,
    is_ip_allowed, is_trusted_proxy, is_user_agent_allowed, log_activity, log_at_level,
    new_correlation_id, new_state_start, sanitize_for_log, send_agent_event,
};
use mock_request::MockRequest;
use parking_lot::Mutex;

use agent::MockAgent;

#[test]
fn sanitize_control_characters() {
    let out = sanitize_for_log("hello\nworld\r\t\x1b");
    assert_eq!(out, "hello\\nworld\\r\\t\\x1b");
}

#[test]
fn sanitize_empty_is_empty() {
    assert!(sanitize_for_log("").is_empty());
}

#[test]
fn is_trusted_proxy_matches_cidr() {
    let proxies = vec!["10.0.0.0/8".into(), "192.168.1.1".into()];
    assert!(is_trusted_proxy("10.0.0.5", &proxies));
    assert!(is_trusted_proxy("192.168.1.1", &proxies));
    assert!(!is_trusted_proxy("8.8.8.8", &proxies));
}

#[test]
fn is_trusted_proxy_rejects_invalid() {
    let proxies = vec!["10.0.0.0/8".into()];
    assert!(!is_trusted_proxy("not-an-ip", &proxies));
}

#[test]
fn extract_forwarded_takes_first() {
    let out = extract_from_forwarded_header("10.0.0.1, 10.0.0.2, 10.0.0.3", 2);
    assert_eq!(out.as_deref(), Some("10.0.0.1"));
}

#[test]
fn extract_forwarded_respects_depth() {
    let out = extract_from_forwarded_header("10.0.0.1", 3);
    assert_eq!(out, None);
}

#[tokio::test]
async fn extract_client_ip_without_trusted_proxies() {
    let cfg = SecurityConfig::builder().build().expect("valid");
    let req: Arc<dyn GuardRequest> = Arc::new(
        MockRequest::builder()
            .client_host("1.2.3.4")
            .header("X-Forwarded-For", "10.0.0.1")
            .build(),
    );
    let ip = extract_client_ip(&req, &cfg, None).await;
    assert_eq!(ip, "1.2.3.4");
}

#[tokio::test]
async fn extract_client_ip_with_trusted_proxy() {
    let cfg = SecurityConfig::builder()
        .trusted_proxies(vec!["1.2.3.4".into()])
        .trusted_proxy_depth(1)
        .build()
        .expect("valid");
    let req: Arc<dyn GuardRequest> = Arc::new(
        MockRequest::builder()
            .client_host("1.2.3.4")
            .header("X-Forwarded-For", "10.0.0.1")
            .build(),
    );
    let ip = extract_client_ip(&req, &cfg, None).await;
    assert_eq!(ip, "10.0.0.1");
}

#[tokio::test]
async fn extract_client_ip_falls_back_to_unknown() {
    let cfg = SecurityConfig::builder().build().expect("valid");
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::builder().build());
    let ip = extract_client_ip(&req, &cfg, None).await;
    assert_eq!(ip, "unknown");
}

#[test]
fn user_agent_blocked_via_pattern() {
    let cfg = SecurityConfig {
        blocked_user_agents: vec!["bot".into(), "curl/.*".into()],
        ..SecurityConfig::builder().build().expect("valid")
    };
    assert!(!is_user_agent_allowed("some-bot-crawler", &cfg));
    assert!(!is_user_agent_allowed("curl/7.81", &cfg));
    assert!(is_user_agent_allowed("Mozilla/5.0", &cfg));
}

#[tokio::test]
async fn is_ip_allowed_rejects_blacklisted() {
    let cfg = SecurityConfig::builder()
        .blacklist(vec!["10.0.0.0/8".into()])
        .build()
        .expect("valid");
    assert!(!is_ip_allowed("10.0.0.1", &cfg, None).await);
    assert!(is_ip_allowed("8.8.8.8", &cfg, None).await);
}

#[tokio::test]
async fn is_ip_allowed_enforces_whitelist() {
    let cfg = SecurityConfig::builder()
        .whitelist(Some(vec!["192.168.1.0/24".into()]))
        .build()
        .expect("valid");
    assert!(is_ip_allowed("192.168.1.5", &cfg, None).await);
    assert!(!is_ip_allowed("10.0.0.1", &cfg, None).await);
}

#[test]
fn public_constants_match_expected() {
    assert_eq!(PIPELINE_START_KEY, "_guard_pipeline_start");
    assert_eq!(CLIENT_IP_KEY, "client_ip");
    assert_eq!(LOGGER_NAME, "guard_core");
}

#[test]
fn sanitize_preserves_normal_chars() {
    let out = sanitize_for_log("hello world");
    assert_eq!(out, "hello world");
}

#[test]
fn sanitize_handles_various_control_chars() {
    let input = "\x00\x01\x1f";
    let out = sanitize_for_log(input);
    assert_eq!(out, "\\x00\\x01\\x1f");
}

#[test]
fn new_correlation_id_is_unique() {
    let a = new_correlation_id();
    let b = new_correlation_id();
    assert_ne!(a, b);
    assert!(a.len() >= 32);
}

#[test]
fn new_state_start_is_float_variant() {
    match new_state_start() {
        StateValue::Float(_) => {}
        _ => panic!("expected Float variant"),
    }
}

#[test]
fn state_value_as_str_variants() {
    assert_eq!(StateValue::String("abc".into()).as_str(), Some("abc"));
    assert_eq!(StateValue::Int(42).as_str(), None);
    assert_eq!(StateValue::Bool(true).as_str(), None);
    assert_eq!(StateValue::Float(1.0).as_str(), None);
    assert_eq!(StateValue::Bytes(bytes::Bytes::new()).as_str(), None);
    assert_eq!(StateValue::Json(serde_json::Value::Null).as_str(), None);
}

#[test]
fn state_value_as_f64_variants() {
    assert_eq!(StateValue::Float(1.5).as_f64(), Some(1.5));
    assert_eq!(StateValue::Int(3).as_f64(), Some(3.0));
    assert!(StateValue::String("x".into()).as_f64().is_none());
    assert!(StateValue::Bool(true).as_f64().is_none());
}

#[test]
fn state_value_as_bool_variants() {
    assert_eq!(StateValue::Bool(false).as_bool(), Some(false));
    assert_eq!(StateValue::Int(1).as_bool(), None);
    assert_eq!(StateValue::String("t".into()).as_bool(), None);
}

#[test]
fn state_value_as_int_variants() {
    assert_eq!(StateValue::Int(7).as_int(), Some(7));
    assert_eq!(StateValue::Float(3.9).as_int(), Some(3));
    assert!(StateValue::String("x".into()).as_int().is_none());
    assert!(StateValue::Bool(true).as_int().is_none());
}

#[test]
fn is_trusted_proxy_cidr_miss_continues() {
    let proxies = vec!["192.168.1.0/24".into(), "10.0.0.5".into()];
    assert!(!is_trusted_proxy("172.16.0.1", &proxies));
    assert!(is_trusted_proxy("10.0.0.5", &proxies));
}

#[test]
fn is_trusted_proxy_ignores_malformed_cidr_entry() {
    let proxies = vec!["not-cidr/zz".into(), "10.0.0.1".into()];
    assert!(is_trusted_proxy("10.0.0.1", &proxies));
}

#[test]
fn extract_forwarded_empty_returns_none() {
    assert_eq!(extract_from_forwarded_header("", 1), None);
}

#[test]
fn extract_forwarded_equal_depth_matches() {
    let out = extract_from_forwarded_header("10.0.0.1, 10.0.0.2", 2);
    assert_eq!(out.as_deref(), Some("10.0.0.1"));
}

#[tokio::test]
async fn extract_client_ip_reads_cached_state() {
    let cfg = SecurityConfig::builder().build().expect("valid");
    let req = MockRequest::builder().client_host("1.2.3.4").build();
    let arc: Arc<dyn GuardRequest> = Arc::new(req);
    arc.state().set_str(CLIENT_IP_KEY, "9.9.9.9");
    let ip = extract_client_ip(&arc, &cfg, None).await;
    assert_eq!(ip, "9.9.9.9");
}

#[tokio::test]
async fn extract_client_ip_warns_on_untrusted_forwarded_for() {
    let cfg = SecurityConfig::builder()
        .trusted_proxies(vec!["10.0.0.1".into()])
        .build()
        .expect("valid");
    let req: Arc<dyn GuardRequest> = Arc::new(
        MockRequest::builder()
            .client_host("8.8.8.8")
            .header("X-Forwarded-For", "1.2.3.4")
            .build(),
    );
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    let ip = extract_client_ip(&req, &cfg, Some(&handler)).await;
    assert_eq!(ip, "8.8.8.8");
    assert!(!agent.events.lock().is_empty());
}

#[tokio::test]
async fn extract_client_ip_trusted_without_forwarded_for_uses_connecting() {
    let cfg = SecurityConfig::builder()
        .trusted_proxies(vec!["1.2.3.4".into()])
        .build()
        .expect("valid");
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::builder().client_host("1.2.3.4").build());
    let ip = extract_client_ip(&req, &cfg, None).await;
    assert_eq!(ip, "1.2.3.4");
}

#[tokio::test]
async fn extract_client_ip_trusted_proxy_depth_enforced() {
    let cfg = SecurityConfig::builder()
        .trusted_proxies(vec!["1.2.3.4".into()])
        .trusted_proxy_depth(5)
        .build()
        .expect("valid");
    let req: Arc<dyn GuardRequest> = Arc::new(
        MockRequest::builder()
            .client_host("1.2.3.4")
            .header("X-Forwarded-For", "10.0.0.1")
            .build(),
    );
    let ip = extract_client_ip(&req, &cfg, None).await;
    assert_eq!(ip, "1.2.3.4");
}

#[test]
fn user_agent_allowed_ignores_invalid_patterns() {
    let cfg = SecurityConfig {
        blocked_user_agents: vec!["[unclosed".into(), "legit-bot".into()],
        ..SecurityConfig::builder().build().expect("valid")
    };
    assert!(!is_user_agent_allowed("legit-bot agent", &cfg));
    assert!(is_user_agent_allowed("Mozilla/5.0", &cfg));
}

#[tokio::test]
async fn is_ip_allowed_rejects_invalid_ip() {
    let cfg = SecurityConfig::builder().build().expect("valid");
    assert!(!is_ip_allowed("not-an-ip", &cfg, None).await);
}

#[tokio::test]
async fn is_ip_allowed_exact_blacklist_match() {
    let cfg = SecurityConfig::builder()
        .blacklist(vec!["1.2.3.4".into()])
        .build()
        .expect("valid");
    assert!(!is_ip_allowed("1.2.3.4", &cfg, None).await);
    assert!(is_ip_allowed("1.2.3.5", &cfg, None).await);
}

#[tokio::test]
async fn is_ip_allowed_exact_whitelist_match() {
    let cfg = SecurityConfig::builder()
        .whitelist(Some(vec!["5.6.7.8".into()]))
        .build()
        .expect("valid");
    assert!(is_ip_allowed("5.6.7.8", &cfg, None).await);
    assert!(!is_ip_allowed("5.6.7.9", &cfg, None).await);
}

#[tokio::test]
async fn check_ip_country_without_rules_returns_false() {
    let cfg = SecurityConfig::builder().build().expect("valid");
    let handler: DynGeoIpHandler = Arc::new(StubGeoIp::new(Some("US".into())));
    let result = check_ip_country("1.1.1.1", &cfg, &handler).await.expect("ok");
    assert!(!result);
}

#[tokio::test]
async fn check_ip_country_whitelisted_returns_false() {
    let cfg = SecurityConfig {
        whitelist_countries: vec!["US".into()],
        ..SecurityConfig::builder().build().expect("base")
    };
    let handler: DynGeoIpHandler = Arc::new(StubGeoIp::new(Some("US".into())));
    let result = check_ip_country("1.1.1.1", &cfg, &handler).await.expect("ok");
    assert!(!result);
}

#[tokio::test]
async fn check_ip_country_blocked_returns_true() {
    let cfg = SecurityConfig {
        blocked_countries: vec!["CN".into()],
        ..SecurityConfig::builder().build().expect("base")
    };
    let handler: DynGeoIpHandler = Arc::new(StubGeoIp::new(Some("CN".into())));
    let result = check_ip_country("1.1.1.1", &cfg, &handler).await.expect("ok");
    assert!(result);
}

#[tokio::test]
async fn check_ip_country_unknown_returns_false() {
    let cfg = SecurityConfig {
        blocked_countries: vec!["CN".into()],
        ..SecurityConfig::builder().build().expect("base")
    };
    let handler: DynGeoIpHandler = Arc::new(StubGeoIp::new(None));
    let result = check_ip_country("1.1.1.1", &cfg, &handler).await.expect("ok");
    assert!(!result);
}

#[tokio::test]
async fn check_ip_country_unknown_region_returns_false() {
    let cfg = SecurityConfig {
        blocked_countries: vec!["CN".into()],
        ..SecurityConfig::builder().build().expect("base")
    };
    let handler: DynGeoIpHandler = Arc::new(StubGeoIp::new(Some("XX".into())));
    let result = check_ip_country("1.1.1.1", &cfg, &handler).await.expect("ok");
    assert!(!result);
}

#[tokio::test]
async fn is_ip_allowed_respects_geo_blocklist() {
    let cfg = SecurityConfig {
        blocked_countries: vec!["ZZ".into()],
        ..SecurityConfig::builder().build().expect("valid")
    };
    let handler: DynGeoIpHandler = Arc::new(StubGeoIp::new(Some("ZZ".into())));
    assert!(!is_ip_allowed("8.8.8.8", &cfg, Some(&handler)).await);
}

#[tokio::test]
async fn is_ip_allowed_allows_when_geo_check_errors() {
    let cfg = SecurityConfig {
        blocked_countries: vec!["XX".into()],
        ..SecurityConfig::builder().build().expect("valid")
    };
    let handler: DynGeoIpHandler = Arc::new(FailingGeoIp);
    assert!(is_ip_allowed("8.8.8.8", &cfg, Some(&handler)).await);
}

#[tokio::test]
async fn is_ip_allowed_geo_missing_country_is_allowed() {
    let cfg = SecurityConfig {
        blocked_countries: vec!["ZZ".into()],
        ..SecurityConfig::builder().build().expect("valid")
    };
    let handler: DynGeoIpHandler = Arc::new(StubGeoIp::new(None));
    assert!(is_ip_allowed("8.8.8.8", &cfg, Some(&handler)).await);
}

#[tokio::test]
async fn log_activity_request_at_info_level() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    log_activity(&req, LogType::Request, Some(LogLevel::Info)).await;
}

#[tokio::test]
async fn log_activity_suspicious_active_mode() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    log_activity(
        &req,
        LogType::Suspicious { reason: "injection", passive_mode: false, trigger_info: "" },
        Some(LogLevel::Warning),
    )
    .await;
}

#[tokio::test]
async fn log_activity_suspicious_passive_mode_with_trigger() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    log_activity(
        &req,
        LogType::Suspicious {
            reason: "pattern",
            passive_mode: true,
            trigger_info: "body contained xss",
        },
        Some(LogLevel::Error),
    )
    .await;
}

#[tokio::test]
async fn log_activity_suspicious_passive_mode_no_trigger() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    log_activity(
        &req,
        LogType::Suspicious { reason: "r", passive_mode: true, trigger_info: "" },
        Some(LogLevel::Critical),
    )
    .await;
}

#[tokio::test]
async fn log_activity_generic_capitalizes_label() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    log_activity(
        &req,
        LogType::Generic { log_type: "custom", reason: "something" },
        Some(LogLevel::Debug),
    )
    .await;
}

#[tokio::test]
async fn log_activity_none_level_returns_early() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    log_activity(&req, LogType::Request, None).await;
}

#[tokio::test]
async fn log_activity_generic_empty_log_type_handles_capitalization() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    log_activity(
        &req,
        LogType::Generic { log_type: "", reason: "nothing" },
        Some(LogLevel::Info),
    )
    .await;
}

#[test]
fn log_at_level_all_variants_do_not_panic() {
    log_at_level(LogLevel::Info, "info");
    log_at_level(LogLevel::Debug, "debug");
    log_at_level(LogLevel::Warning, "warn");
    log_at_level(LogLevel::Error, "err");
    log_at_level(LogLevel::Critical, "crit");
}

#[test]
fn log_type_debug_output() {
    let lt = LogType::Request;
    assert!(format!("{lt:?}").contains("Request"));
}

#[tokio::test]
async fn get_pipeline_response_time_with_no_request_is_none() {
    assert!(get_pipeline_response_time(None).is_none());
}

#[tokio::test]
async fn get_pipeline_response_time_initializes_state() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    let t1 = get_pipeline_response_time(Some(&req)).expect("some");
    assert!(t1 >= 0.0);
    let t2 = get_pipeline_response_time(Some(&req)).expect("some");
    assert!(t2 >= t1);
}

#[test]
fn extract_request_context_returns_unknown_when_no_client() {
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    let ctx = extract_request_context(&req);
    assert_eq!(ctx.client_ip, "unknown");
    assert_eq!(ctx.method, "GET");
}

#[test]
fn extract_request_context_from_full_request() {
    let req: Arc<dyn GuardRequest> = Arc::new(
        MockRequest::builder()
            .path("/resource")
            .method("POST")
            .client_host("7.7.7.7")
            .header("X", "Y")
            .build(),
    );
    let ctx = extract_request_context(&req);
    assert_eq!(ctx.client_ip, "7.7.7.7");
    assert_eq!(ctx.method, "POST");
    assert!(ctx.url.contains("/resource"));
    assert!(ctx.headers.contains_key("X"));
    assert!(format!("{ctx:?}").contains("RequestContext"));
    let clone = ctx.clone();
    assert_eq!(clone.client_ip, "7.7.7.7");
}

#[tokio::test]
async fn send_agent_event_no_handler_is_no_op() {
    send_agent_event(
        None,
        "event_type",
        "ip",
        "action",
        "reason",
        None,
        serde_json::Map::new(),
    )
    .await;
}

#[tokio::test]
async fn send_agent_event_delivers_full_event() {
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    let req: Arc<dyn GuardRequest> = Arc::new(
        MockRequest::builder()
            .path("/foo")
            .method("GET")
            .header("User-Agent", "test-agent")
            .build(),
    );
    let mut extra = serde_json::Map::new();
    extra.insert("key".into(), serde_json::json!("value"));
    send_agent_event(
        Some(&handler),
        "evt",
        "1.2.3.4",
        "allow",
        "ok",
        Some(&req),
        extra,
    )
    .await;
    let events = agent.events.lock();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "evt");
    assert_eq!(events[0]["ip_address"], "1.2.3.4");
    assert_eq!(events[0]["key"], "value");
}

#[tokio::test]
async fn send_agent_event_handles_agent_errors() {
    let agent: DynAgentHandler = Arc::new(FailingAgent);
    send_agent_event(
        Some(&agent),
        "evt",
        "1.2.3.4",
        "allow",
        "ok",
        None,
        serde_json::Map::new(),
    )
    .await;
}

#[tokio::test]
async fn send_agent_event_without_request_has_nulls() {
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    send_agent_event(
        Some(&handler),
        "evt",
        "ip",
        "a",
        "r",
        None,
        serde_json::Map::new(),
    )
    .await;
    let events = agent.events.lock();
    assert!(events[0]["endpoint"].is_null());
    assert!(events[0]["method"].is_null());
}

#[derive(Debug)]
struct StubGeoIp {
    country: parking_lot::Mutex<Option<String>>,
    init: Mutex<bool>,
}

impl StubGeoIp {
    fn new(country: Option<String>) -> Self {
        Self {
            country: parking_lot::Mutex::new(country),
            init: Mutex::new(false),
        }
    }
}

#[async_trait]
impl GeoIpHandler for StubGeoIp {
    fn is_initialized(&self) -> bool {
        *self.init.lock()
    }
    async fn initialize(&self) -> Result<()> {
        *self.init.lock() = true;
        Ok(())
    }
    async fn initialize_redis(&self, _: DynRedisHandler) -> Result<()> {
        Ok(())
    }
    async fn initialize_agent(&self, _: DynAgentHandler) -> Result<()> {
        Ok(())
    }
    fn get_country(&self, _ip: &str) -> Option<String> {
        self.country.lock().clone()
    }
}

#[derive(Debug)]
struct FailingGeoIp;

#[async_trait]
impl GeoIpHandler for FailingGeoIp {
    fn is_initialized(&self) -> bool {
        false
    }
    async fn initialize(&self) -> Result<()> {
        Err(guard_core_rs::error::GuardCoreError::GeoIp("boom".into()))
    }
    async fn initialize_redis(&self, _: DynRedisHandler) -> Result<()> {
        Ok(())
    }
    async fn initialize_agent(&self, _: DynAgentHandler) -> Result<()> {
        Ok(())
    }
    fn get_country(&self, _ip: &str) -> Option<String> {
        None
    }
}

#[derive(Debug)]
struct FailingAgent;

#[async_trait]
impl guard_core_rs::protocols::agent::AgentHandlerProtocol for FailingAgent {
    async fn initialize_redis(&self, _: DynRedisHandler) -> Result<()> {
        Ok(())
    }
    async fn send_event(&self, _event: serde_json::Value) -> Result<()> {
        Err(guard_core_rs::error::GuardCoreError::Agent("failed".into()))
    }
    async fn send_metric(&self, _m: serde_json::Value) -> Result<()> {
        Ok(())
    }
    async fn start(&self) -> Result<()> {
        Ok(())
    }
    async fn stop(&self) -> Result<()> {
        Ok(())
    }
    async fn flush_buffer(&self) -> Result<()> {
        Ok(())
    }
    async fn get_dynamic_rules(&self) -> Result<Option<guard_core_rs::models::DynamicRules>> {
        Ok(None)
    }
    async fn health_check(&self) -> Result<bool> {
        Ok(true)
    }
}

#[tokio::test]
async fn geoip_whitelist_country_allows() {
    let cfg = SecurityConfig {
        whitelist_countries: vec!["US".into()],
        ..SecurityConfig::builder().build().expect("valid")
    };
    let handler: DynGeoIpHandler = Arc::new(StubGeoIp::new(Some("US".into())));
    assert!(is_ip_allowed("8.8.8.8", &cfg, Some(&handler)).await);
}

#[tokio::test]
async fn geoip_initializes_when_needed() {
    let cfg = SecurityConfig {
        blocked_countries: vec!["ZZ".into()],
        ..SecurityConfig::builder().build().expect("valid")
    };
    let stub = Arc::new(StubGeoIp::new(Some("OK".into())));
    let handler: DynGeoIpHandler = Arc::clone(&stub) as DynGeoIpHandler;
    assert!(!stub.is_initialized());
    let _ = is_ip_allowed("8.8.8.8", &cfg, Some(&handler)).await;
    assert!(stub.is_initialized());
}

#[tokio::test]
async fn mock_request_exposes_full_request_surface() {
    let req = MockRequest::builder()
        .scheme("https")
        .method("POST")
        .path("/api/login")
        .client_host("127.0.0.1")
        .header("User-Agent", "test")
        .query("token", "abc")
        .body(bytes::Bytes::from_static(b"{\"user\":\"alice\"}"))
        .build()
        .arc();
    assert_eq!(req.url_scheme(), "https");
    assert_eq!(req.method(), "POST");
    assert_eq!(req.url_path(), "/api/login");
    assert_eq!(req.client_host().as_deref(), Some("127.0.0.1"));
    assert_eq!(req.header("User-Agent").as_deref(), Some("test"));
    assert_eq!(req.query_params().get("token").map(String::as_str), Some("abc"));
    let body = req.body().await.expect("body");
    assert_eq!(&body[..], b"{\"user\":\"alice\"}");
}
