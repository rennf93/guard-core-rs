#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

#[path = "support/geo_ip.rs"]
mod mock_geo;

use std::collections::HashMap;
use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::RateLimitCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::handlers::ratelimit::RateLimitManager;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::geo_ip::DynGeoIpHandler;
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::utils::CLIENT_IP_KEY;
use mock_agent::MockAgent;
use mock_geo::MockGeoIpHandler;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

fn resolver_with(path: &str, rc: RouteConfig) -> Arc<RouteConfigResolver> {
    let cfg = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let resolver = Arc::new(RouteConfigResolver::new(RoutingContext::new(cfg)));
    resolver.register(path, rc);
    resolver
}

fn empty_resolver() -> Arc<RouteConfigResolver> {
    Arc::new(RouteConfigResolver::new(RoutingContext::new(Arc::new(
        SecurityConfig::builder().build().expect("valid"),
    ))))
}

fn config(
    passive: bool,
    enable: bool,
    rate_limit: u32,
    window: u64,
    endpoint_limits: HashMap<String, (u32, u64)>,
) -> Arc<SecurityConfig> {
    let mut config = SecurityConfig::builder()
        .passive_mode(passive)
        .enable_rate_limiting(enable)
        .enable_redis(false)
        .rate_limit(rate_limit)
        .rate_limit_window(window)
        .build()
        .expect("valid");
    config.endpoint_rate_limits = endpoint_limits;
    Arc::new(config)
}

fn middleware(
    agent: Arc<MockAgent>,
    config: Arc<SecurityConfig>,
    geo: Option<DynGeoIpHandler>,
) -> Arc<MockMiddleware> {
    let dyn_agent: DynAgentHandler = agent as Arc<dyn AgentHandlerProtocol>;
    MockMiddleware::with_handlers(config, Some(dyn_agent), geo, None)
}

fn request(path: &str, ip: Option<&str>) -> DynGuardRequest {
    let request: DynGuardRequest = Arc::new(MockRequest::builder().path(path).build());
    if let Some(ip_value) = ip {
        request.state().set_str(CLIENT_IP_KEY, ip_value);
    }
    request
}

#[tokio::test]
async fn rate_limit_whitelisted_ip_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 10, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), config, None);
    let check = RateLimitCheck::new(middleware, empty_resolver(), rate_manager);
    let request: DynGuardRequest = Arc::new(MockRequest::default());
    request.state().set_bool("is_whitelisted", true);
    assert!(check.check(&request).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "rate_limit");
}

#[tokio::test]
async fn rate_limit_missing_client_ip_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 10, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), config, None);
    let check = RateLimitCheck::new(middleware, empty_resolver(), rate_manager);
    assert!(
        check
            .check(&request("/", None))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn rate_limit_bypassed_by_route_config() {
    let rc = RouteConfig::new().bypass(vec!["rate_limit".into()]);
    let resolver = resolver_with("/x", rc);
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 10, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), config, None);
    let check = RateLimitCheck::new(middleware, resolver, rate_manager);
    assert!(
        check
            .check(&request("/x", Some("10.0.0.1")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn rate_limit_global_within_limit_passes() {
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 100, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), config, None);
    let check = RateLimitCheck::new(middleware, empty_resolver(), rate_manager);
    assert!(
        check
            .check(&request("/x", Some("10.0.0.2")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn rate_limit_global_exceeds_limit_blocks() {
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 2, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), None);
    let check = RateLimitCheck::new(middleware, empty_resolver(), rate_manager);
    let ip = "10.0.0.3";
    let _ = check.check(&request("/x", Some(ip))).await.expect("ok");
    let _ = check.check(&request("/x", Some(ip))).await.expect("ok");
    let response = check.check(&request("/x", Some(ip))).await.expect("ok");
    assert!(response.is_some());
    assert_eq!(response.unwrap().status_code(), 429);
}

#[tokio::test]
async fn rate_limit_passive_mode_does_not_return_response() {
    let agent = Arc::new(MockAgent::default());
    let config = config(true, true, 1, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), None);
    let check = RateLimitCheck::new(middleware, empty_resolver(), rate_manager);
    let ip = "10.0.0.4";
    let _ = check.check(&request("/x", Some(ip))).await.expect("ok");
    let result = check.check(&request("/x", Some(ip))).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn rate_limit_endpoint_specific_exceeded() {
    let mut endpoints = HashMap::new();
    endpoints.insert("/limited".to_string(), (1u32, 60u64));
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 100, 60, endpoints);
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), None);
    let check = RateLimitCheck::new(middleware, empty_resolver(), rate_manager);
    let _ = check.check(&request("/limited", Some("10.0.0.5"))).await.expect("ok");
    let response = check
        .check(&request("/limited", Some("10.0.0.5")))
        .await
        .expect("ok");
    assert!(response.is_some());
}

#[tokio::test]
async fn rate_limit_route_specific_exceeded() {
    let rc = RouteConfig::new().rate_limit(1, 60);
    let resolver = resolver_with("/route", rc);
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 100, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), None);
    let check = RateLimitCheck::new(middleware, resolver, rate_manager);
    let _ = check.check(&request("/route", Some("10.0.0.6"))).await.expect("ok");
    let response = check
        .check(&request("/route", Some("10.0.0.6")))
        .await
        .expect("ok");
    assert!(response.is_some());
}

#[tokio::test]
async fn rate_limit_geo_specific_exceeded() {
    let geo = MockGeoIpHandler::with_mapping(&[("10.0.0.7", "US")]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let mut limits = HashMap::new();
    limits.insert("US".into(), (1u32, 60u64));
    let rc = RouteConfig::new().geo_rate_limit(limits);
    let resolver = resolver_with("/geo", rc);
    let agent = Arc::new(MockAgent::default());
    let mut base = SecurityConfig::builder()
        .enable_rate_limiting(true)
        .enable_redis(false)
        .rate_limit(100)
        .build()
        .expect("valid");
    base.geo_ip_handler = Some(Arc::clone(&dyn_geo));
    let config = Arc::new(base);
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), Some(dyn_geo));
    let check = RateLimitCheck::new(middleware, resolver, rate_manager);
    let _ = check.check(&request("/geo", Some("10.0.0.7"))).await.expect("ok");
    let response = check.check(&request("/geo", Some("10.0.0.7"))).await.expect("ok");
    assert!(response.is_some());
}

#[tokio::test]
async fn rate_limit_geo_wildcard_applies_when_country_not_mapped() {
    let geo = MockGeoIpHandler::with_mapping(&[]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let mut limits = HashMap::new();
    limits.insert("*".into(), (1u32, 60u64));
    let rc = RouteConfig::new().geo_rate_limit(limits);
    let resolver = resolver_with("/geo", rc);
    let agent = Arc::new(MockAgent::default());
    let mut base = SecurityConfig::builder()
        .enable_rate_limiting(true)
        .enable_redis(false)
        .rate_limit(100)
        .build()
        .expect("valid");
    base.geo_ip_handler = Some(Arc::clone(&dyn_geo));
    let config = Arc::new(base);
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), Some(dyn_geo));
    let check = RateLimitCheck::new(middleware, resolver, rate_manager);
    let _ = check.check(&request("/geo", Some("10.0.0.8"))).await.expect("ok");
    let response = check.check(&request("/geo", Some("10.0.0.8"))).await.expect("ok");
    assert!(response.is_some());
}

#[tokio::test]
async fn rate_limit_geo_without_handler_returns_none() {
    let mut limits = HashMap::new();
    limits.insert("US".into(), (1u32, 60u64));
    let rc = RouteConfig::new().geo_rate_limit(limits);
    let resolver = resolver_with("/geo", rc);
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 100, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), None);
    let check = RateLimitCheck::new(middleware, resolver, rate_manager);
    assert!(
        check
            .check(&request("/geo", Some("10.0.0.9")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn rate_limit_geo_empty_limits_returns_none() {
    let rc = RouteConfig::new().geo_rate_limit(HashMap::new());
    let resolver = resolver_with("/empty", rc);
    let agent = Arc::new(MockAgent::default());
    let config = config(false, true, 100, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), None);
    let check = RateLimitCheck::new(middleware, resolver, rate_manager);
    assert!(
        check
            .check(&request("/empty", Some("10.0.0.1")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn rate_limit_geo_no_matching_country_or_wildcard_returns_none() {
    let geo = MockGeoIpHandler::with_mapping(&[("10.0.0.5", "CA")]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let mut limits = HashMap::new();
    limits.insert("US".into(), (1u32, 60u64));
    let rc = RouteConfig::new().geo_rate_limit(limits);
    let resolver = resolver_with("/geo", rc);
    let agent = Arc::new(MockAgent::default());
    let mut base = SecurityConfig::builder()
        .enable_rate_limiting(true)
        .enable_redis(false)
        .rate_limit(100)
        .build()
        .expect("valid");
    base.geo_ip_handler = Some(Arc::clone(&dyn_geo));
    let config = Arc::new(base);
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), Some(dyn_geo));
    let check = RateLimitCheck::new(middleware, resolver, rate_manager);
    assert!(
        check
            .check(&request("/geo", Some("10.0.0.5")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn rate_limit_disabled_globally_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let config = config(false, false, 1, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config), None);
    let check = RateLimitCheck::new(middleware, empty_resolver(), rate_manager);
    let _ = check.check(&request("/x", Some("10.0.0.1"))).await.expect("ok");
    assert!(
        check
            .check(&request("/x", Some("10.0.0.1")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[test]
fn rate_limit_check_debug() {
    let config = config(false, true, 10, 60, HashMap::new());
    let rate_manager = RateLimitManager::new(Arc::clone(&config));
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(agent, config, None);
    let check = RateLimitCheck::new(middleware, empty_resolver(), rate_manager);
    assert!(format!("{check:?}").contains("RateLimitCheck"));
}
