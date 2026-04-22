#[path = "support/request.rs"]
mod mock_request;
#[path = "support/agent.rs"]
mod agent;
#[path = "support/mock_redis.rs"]
mod mock_redis;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::NaiveTime;
use guard_core_rs::decorators::{
    BaseSecurityDecorator, BaseSecurityMixin, ROUTE_ID_STATE_KEY, RouteConfig, SecurityDecorator,
    get_route_decorator_config,
};
use guard_core_rs::handlers::IPBanManager;
use guard_core_rs::handlers::behavior::{BehaviorAction, BehaviorRule, BehaviorRuleType};
use guard_core_rs::models::{CloudProvider, SecurityConfig};
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};
use guard_core_rs::protocols::request::GuardRequest;
use mock_redis::MockRedis;
use mock_request::MockRequest;

use agent::MockAgent;

#[test]
fn route_config_default_enables_suspicious_detection() {
    let rc = RouteConfig::new();
    assert!(rc.enable_suspicious_detection);
    assert!(rc.rate_limit.is_none());
    assert!(rc.allowed_ips.is_none());
}

#[test]
fn route_config_require_ip_sets_both_lists() {
    let rc = RouteConfig::new()
        .require_ip(Some(vec!["10.0.0.1".into()]), Some(vec!["1.2.3.4".into()]));
    assert_eq!(rc.allowed_ips.as_ref().map(Vec::len), Some(1));
    assert_eq!(rc.blocked_ips.len(), 1);
}

#[test]
fn route_config_require_ip_with_none_leaves_unset() {
    let rc = RouteConfig::new().require_ip(None, None);
    assert!(rc.allowed_ips.is_none());
    assert!(rc.blocked_ips.is_empty());
}

#[test]
fn route_config_rate_limit_chained() {
    let rc = RouteConfig::new().rate_limit(20, 30);
    assert_eq!(rc.rate_limit, Some(20));
    assert_eq!(rc.rate_limit_window, Some(30));
}

#[test]
fn route_config_block_clouds_defaults_to_all() {
    let rc = RouteConfig::new().block_clouds(None);
    let providers = rc.block_cloud_providers.expect("set");
    assert_eq!(providers.len(), 3);
    assert!(providers.contains(&CloudProvider::Aws));
    assert!(providers.contains(&CloudProvider::Gcp));
    assert!(providers.contains(&CloudProvider::Azure));
}

#[test]
fn route_config_block_clouds_specific_providers() {
    let rc = RouteConfig::new().block_clouds(Some(vec![CloudProvider::Aws]));
    let providers = rc.block_cloud_providers.expect("set");
    assert_eq!(providers, HashSet::from([CloudProvider::Aws]));
}

#[test]
fn route_config_require_auth() {
    let rc = RouteConfig::new().require_auth("bearer");
    assert_eq!(rc.auth_required.as_deref(), Some("bearer"));
}

#[test]
fn route_config_require_https() {
    let rc = RouteConfig::new().require_https();
    assert!(rc.require_https);
}

#[test]
fn route_config_api_key_sets_header() {
    let rc = RouteConfig::new().api_key_auth("X-API-Key");
    assert!(rc.api_key_required);
    assert!(rc.required_headers.contains_key("X-API-Key"));
}

#[test]
fn route_config_bypass_deduplicates() {
    let rc = RouteConfig::new()
        .bypass(vec!["rate_limit".into(), "rate_limit".into()]);
    assert_eq!(rc.bypassed_checks.len(), 1);
}

#[test]
fn route_config_usage_monitor_adds_rule() {
    let rc = RouteConfig::new().usage_monitor(10, 3600, BehaviorAction::Log);
    assert_eq!(rc.behavior_rules.len(), 1);
}

#[test]
fn route_config_return_monitor_adds_rule_with_pattern() {
    let rc = RouteConfig::new().return_monitor("status:500", 5, 600, BehaviorAction::Ban);
    assert_eq!(rc.behavior_rules.len(), 1);
    assert_eq!(rc.behavior_rules[0].pattern.as_deref(), Some("status:500"));
}

#[test]
fn route_config_time_window_sets_times() {
    let rc = RouteConfig::new().time_window(
        NaiveTime::from_hms_opt(8, 0, 0).expect("valid"),
        NaiveTime::from_hms_opt(17, 0, 0).expect("valid"),
        "UTC",
    );
    assert!(rc.time_window_start.is_some());
    assert!(rc.time_window_end.is_some());
    assert_eq!(rc.time_window_timezone.as_deref(), Some("UTC"));
}

#[test]
fn route_config_suspicious_detection_sets_metadata() {
    let rc = RouteConfig::new().suspicious_detection(false);
    assert!(!rc.enable_suspicious_detection);
    let metadata = rc.custom_metadata.get("enable_suspicious_detection").expect("present");
    assert_eq!(metadata.as_bool(), Some(false));
}

#[test]
fn route_config_block_user_agents_extends() {
    let rc = RouteConfig::new()
        .block_user_agents(vec!["bot".into()])
        .block_user_agents(vec!["crawler".into()]);
    assert_eq!(rc.blocked_user_agents.len(), 2);
}

#[test]
fn route_config_max_request_size() {
    let rc = RouteConfig::new().max_request_size(1024);
    assert_eq!(rc.max_request_size, Some(1024));
}

#[test]
fn route_config_require_referrer() {
    let rc = RouteConfig::new().require_referrer(vec!["trusted.example".into()]);
    assert_eq!(rc.require_referrer.as_ref().map(Vec::len), Some(1));
}

#[test]
fn decorator_registers_and_retrieves_route() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let rc = RouteConfig::new().rate_limit(5, 60);
    decorator.register("POST /api/login", rc);
    let retrieved = decorator.get_route_config("POST /api/login").expect("registered");
    assert_eq!(retrieved.rate_limit, Some(5));
}

#[test]
fn decorator_unregister_removes_route() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    decorator.register("GET /x", RouteConfig::new());
    decorator.unregister("GET /x");
    assert!(decorator.get_route_config("GET /x").is_none());
}

#[test]
fn route_config_block_countries_sets_list() {
    let rc = RouteConfig::new().block_countries(vec!["CN".into(), "RU".into()]);
    assert_eq!(rc.blocked_countries.len(), 2);
}

#[test]
fn route_config_allow_countries_sets_list() {
    let rc = RouteConfig::new().allow_countries(vec!["US".into()]);
    assert_eq!(rc.allowed_countries.len(), 1);
}

#[test]
fn route_config_geo_rate_limit_sets_map() {
    let mut limits = HashMap::new();
    limits.insert("US".to_string(), (10u32, 60u64));
    let rc = RouteConfig::new().geo_rate_limit(limits);
    assert!(rc.geo_rate_limits.is_some());
}

#[test]
fn route_config_require_headers_merges_map() {
    let mut headers = HashMap::new();
    headers.insert("X-Custom".to_string(), "v1".to_string());
    headers.insert("X-Extra".to_string(), "v2".to_string());
    let rc = RouteConfig::new().require_headers(headers);
    assert!(rc.required_headers.contains_key("X-Custom"));
    assert!(rc.required_headers.contains_key("X-Extra"));
}

#[test]
fn route_config_behavior_analysis_extends_rules() {
    let rule = BehaviorRule::new(BehaviorRuleType::Usage, 10, 60, None, BehaviorAction::Log);
    let rc = RouteConfig::new().behavior_analysis(vec![rule]);
    assert_eq!(rc.behavior_rules.len(), 1);
}

#[test]
fn route_config_suspicious_frequency_computes_max_calls() {
    let rc = RouteConfig::new().suspicious_frequency(0.5, 60, BehaviorAction::Alert);
    assert_eq!(rc.behavior_rules.len(), 1);
    assert_eq!(rc.behavior_rules[0].threshold, 30);
}

#[test]
fn route_config_content_type_filter() {
    let rc = RouteConfig::new().content_type_filter(vec!["application/json".into()]);
    assert_eq!(
        rc.allowed_content_types.as_ref().map(Vec::len),
        Some(1)
    );
}

#[test]
fn route_config_custom_validation_appends() {
    let validator = Arc::new(
        |_req: Arc<dyn GuardRequest>| -> futures::future::BoxFuture<
            'static,
            Option<Arc<dyn guard_core_rs::protocols::response::GuardResponse>>,
        > { Box::pin(async { None }) },
    );
    let rc = RouteConfig::new().custom_validation(validator);
    assert_eq!(rc.custom_validators.len(), 1);
}

#[test]
fn route_config_debug_output() {
    let rc = RouteConfig::new();
    let debug = format!("{rc:?}");
    assert!(debug.contains("RouteConfig"));
}

#[test]
fn base_security_decorator_delegates_to_mixin() {
    let mut base = BaseSecurityDecorator::new(RouteConfig::new());
    assert!(base.route_config().enable_suspicious_detection);
    base.route_config_mut().max_request_size = Some(512);
    assert_eq!(base.route_config().max_request_size, Some(512));
    let debug = format!("{base:?}");
    assert!(debug.contains("BaseSecurityDecorator"));
    let cloned = base.clone();
    assert_eq!(cloned.config.max_request_size, Some(512));
}

#[test]
fn base_security_decorator_default_works() {
    let base = BaseSecurityDecorator::default();
    assert!(!base.config.require_https);
}

#[test]
fn decorator_debug_output_counts_routes() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    decorator.register("A", RouteConfig::new());
    decorator.register("B", RouteConfig::new());
    let debug = format!("{decorator:?}");
    assert!(debug.contains("SecurityDecorator"));
}

#[tokio::test]
async fn mock_builder_full_surface_exercised() {
    let req = MockRequest::builder()
        .path("/p")
        .scheme("https")
        .method("GET")
        .client_host("1.2.3.4")
        .header("H", "V")
        .query("q", "v")
        .body(bytes::Bytes::from_static(b"data"))
        .build()
        .arc();
    assert_eq!(req.url_path(), "/p");
    assert_eq!(req.url_scheme(), "https");
    assert_eq!(req.method(), "GET");
    assert_eq!(req.client_host().as_deref(), Some("1.2.3.4"));
    assert_eq!(req.header("H").as_deref(), Some("V"));
    assert_eq!(req.query_param("q").as_deref(), Some("v"));
    assert_eq!(&req.body().await.unwrap()[..], b"data");
}

#[test]
fn decorator_behavior_tracker_reference_returned() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let _tracker = decorator.behavior_tracker();
}

#[tokio::test]
async fn decorator_send_decorator_event_without_agent() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    decorator
        .send_decorator_event(
            "evt",
            &req,
            "allow",
            "ok",
            "type",
            serde_json::Map::new(),
        )
        .await;
}

#[tokio::test]
async fn decorator_send_decorator_event_with_agent() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    decorator.initialize_agent(handler, None).await;
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::builder().client_host("1.2.3.4").build());
    decorator
        .send_decorator_event(
            "evt",
            &req,
            "allow",
            "ok",
            "type",
            serde_json::Map::new(),
        )
        .await;
    assert!(!agent.events.lock().is_empty());
}

#[tokio::test]
async fn decorator_send_access_denied_event() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    decorator.initialize_agent(handler, None).await;
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::builder().client_host("1.2.3.4").build());
    decorator
        .send_access_denied_event(&req, "no access", "ip_check", serde_json::Map::new())
        .await;
    let events = agent.events.lock();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "access_denied");
}

#[tokio::test]
async fn decorator_send_authentication_failed_event() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    decorator.initialize_agent(handler, None).await;
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::builder().client_host("1.2.3.4").build());
    decorator
        .send_authentication_failed_event(&req, "bad key", "api_key", serde_json::Map::new())
        .await;
    let events = agent.events.lock();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["metadata"]["auth_type"], "api_key");
}

#[tokio::test]
async fn decorator_send_rate_limit_event() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    decorator.initialize_agent(handler, None).await;
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::builder().client_host("1.2.3.4").build());
    decorator
        .send_rate_limit_event(&req, 10, 60, serde_json::Map::new())
        .await;
    let events = agent.events.lock();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["metadata"]["limit"], 10);
    assert_eq!(events[0]["metadata"]["window"], 60);
}

#[tokio::test]
async fn decorator_send_decorator_violation_event() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    decorator.initialize_agent(handler, None).await;
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::builder().client_host("1.2.3.4").build());
    decorator
        .send_decorator_violation_event(&req, "header_missing", "bad", serde_json::Map::new())
        .await;
    let events = agent.events.lock();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "decorator_violation");
}

#[tokio::test]
async fn decorator_initialize_behavior_tracking_without_redis() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    decorator.initialize_behavior_tracking(None).await;
}

#[tokio::test]
async fn decorator_initialize_behavior_tracking_with_redis() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let redis = Arc::new(MockRedis::default());
    let handler: DynRedisHandler = redis as Arc<dyn RedisHandlerProtocol>;
    decorator.initialize_behavior_tracking(Some(handler)).await;
}

#[tokio::test]
async fn decorator_initialize_agent_with_ipban_manager() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    let ipban = Arc::new(IPBanManager::new());
    decorator.initialize_agent(handler, Some(ipban)).await;
}

#[derive(Debug)]
struct FailingAgent;

#[async_trait::async_trait]
impl AgentHandlerProtocol for FailingAgent {
    async fn initialize_redis(&self, _: DynRedisHandler) -> guard_core_rs::error::Result<()> {
        Ok(())
    }
    async fn send_event(&self, _event: serde_json::Value) -> guard_core_rs::error::Result<()> {
        Err(guard_core_rs::error::GuardCoreError::Agent("fail".into()))
    }
    async fn send_metric(&self, _m: serde_json::Value) -> guard_core_rs::error::Result<()> {
        Ok(())
    }
    async fn start(&self) -> guard_core_rs::error::Result<()> {
        Ok(())
    }
    async fn stop(&self) -> guard_core_rs::error::Result<()> {
        Ok(())
    }
    async fn flush_buffer(&self) -> guard_core_rs::error::Result<()> {
        Ok(())
    }
    async fn get_dynamic_rules(
        &self,
    ) -> guard_core_rs::error::Result<Option<guard_core_rs::models::DynamicRules>> {
        Ok(None)
    }
    async fn health_check(&self) -> guard_core_rs::error::Result<bool> {
        Ok(true)
    }
}

#[tokio::test]
async fn decorator_logs_agent_send_failures() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let handler: DynAgentHandler = Arc::new(FailingAgent);
    decorator.initialize_agent(handler, None).await;
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::builder().client_host("1.2.3.4").build());
    decorator
        .send_decorator_event("e", &req, "a", "r", "t", serde_json::Map::new())
        .await;
}

#[test]
fn get_route_decorator_config_returns_none_when_no_state() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    assert!(get_route_decorator_config(&req, &decorator).is_none());
}

#[test]
fn get_route_decorator_config_returns_config_when_registered() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    decorator.register("route_x", RouteConfig::new().rate_limit(5, 60));
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    req.state().set_str(ROUTE_ID_STATE_KEY, "route_x");
    let retrieved = get_route_decorator_config(&req, &decorator).expect("found");
    assert_eq!(retrieved.rate_limit, Some(5));
}

#[test]
fn get_route_decorator_config_returns_none_when_unregistered_id() {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let decorator = SecurityDecorator::new(config);
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    req.state().set_str(ROUTE_ID_STATE_KEY, "ghost");
    assert!(get_route_decorator_config(&req, &decorator).is_none());
}
