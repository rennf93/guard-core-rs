#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::HttpsEnforcementCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_agent::MockAgent;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

fn resolver_with(route_path: &str, rc: RouteConfig) -> Arc<RouteConfigResolver> {
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let resolver = Arc::new(RouteConfigResolver::new(RoutingContext::new(config)));
    resolver.register(route_path, rc);
    resolver
}

fn empty_resolver() -> Arc<RouteConfigResolver> {
    Arc::new(RouteConfigResolver::new(RoutingContext::new(Arc::new(
        SecurityConfig::builder().build().expect("valid"),
    ))))
}

fn base_config() -> Arc<SecurityConfig> {
    Arc::new(
        SecurityConfig::builder()
            .enforce_https(false)
            .build()
            .expect("valid"),
    )
}

fn config_enforce_https(enforce: bool, passive: bool) -> Arc<SecurityConfig> {
    Arc::new(
        SecurityConfig::builder()
            .enforce_https(enforce)
            .passive_mode(passive)
            .build()
            .expect("valid"),
    )
}

fn config_with_trust(trust: bool, proxies: Vec<String>) -> Arc<SecurityConfig> {
    Arc::new(
        SecurityConfig::builder()
            .enforce_https(true)
            .trusted_proxies(proxies)
            .trust_x_forwarded_proto(trust)
            .build()
            .expect("valid"),
    )
}

fn agent_dyn(agent: Arc<MockAgent>) -> DynAgentHandler {
    agent as Arc<dyn AgentHandlerProtocol>
}

fn http_request(path: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().path(path).scheme("http").build())
}

fn https_request(path: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().path(path).scheme("https").build())
}

#[tokio::test]
async fn https_enforcement_allows_when_not_required() {
    let resolver = empty_resolver();
    let middleware = MockMiddleware::new(base_config());
    let check = HttpsEnforcementCheck::new(middleware, Arc::clone(&resolver));
    let request = http_request("/any");
    assert!(check.check(&request).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "https_enforcement");
}

#[tokio::test]
async fn https_enforcement_allows_when_already_https() {
    let resolver = empty_resolver();
    let middleware = MockMiddleware::new(config_enforce_https(true, false));
    let check = HttpsEnforcementCheck::new(middleware, resolver);
    let request = https_request("/secure");
    assert!(check.check(&request).await.expect("ok").is_none());
}

#[tokio::test]
async fn https_enforcement_redirects_when_required_and_not_https() {
    let resolver = empty_resolver();
    let agent = Arc::new(MockAgent::default());
    let middleware = MockMiddleware::with_handlers(
        config_enforce_https(true, false),
        Some(agent_dyn(Arc::clone(&agent))),
        None,
        None,
    );
    let check = HttpsEnforcementCheck::new(middleware, resolver);
    let response = check.check(&http_request("/")).await.expect("ok").expect("redirect");
    assert_eq!(response.status_code(), 301);
    assert!(response.header("Location").is_some());
    let events = agent.events.read();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]["event_type"],
        serde_json::Value::String("security_violation".into())
    );
}

#[tokio::test]
async fn https_enforcement_passive_mode_skips_redirect() {
    let resolver = empty_resolver();
    let agent = Arc::new(MockAgent::default());
    let middleware = MockMiddleware::with_handlers(
        config_enforce_https(true, true),
        Some(agent_dyn(Arc::clone(&agent))),
        None,
        None,
    );
    let check = HttpsEnforcementCheck::new(middleware, resolver);
    let result = check.check(&http_request("/")).await.expect("ok");
    assert!(result.is_none());
    assert_eq!(agent.events.read().len(), 1);
}

#[tokio::test]
async fn https_enforcement_route_level_require_https_overrides_config() {
    let mut rc = RouteConfig::new();
    rc.require_https = true;
    let resolver = resolver_with("/admin", rc);
    let middleware = MockMiddleware::new(base_config());
    let check = HttpsEnforcementCheck::new(middleware, resolver);
    let response = check.check(&http_request("/admin")).await.expect("ok").expect("redirect");
    assert_eq!(response.status_code(), 301);
}

#[tokio::test]
async fn https_enforcement_trusts_x_forwarded_proto_when_configured() {
    let middleware = MockMiddleware::new(config_with_trust(true, vec!["10.0.0.1".into()]));
    let resolver = empty_resolver();
    let check = HttpsEnforcementCheck::new(middleware, resolver);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .scheme("http")
            .client_host("10.0.0.1")
            .header("X-Forwarded-Proto", "HTTPS")
            .build(),
    );
    assert!(check.check(&request).await.expect("ok").is_none());
}

#[tokio::test]
async fn https_enforcement_ignores_x_forwarded_proto_from_untrusted_proxy() {
    let middleware = MockMiddleware::new(config_with_trust(true, vec!["10.0.0.2".into()]));
    let resolver = empty_resolver();
    let check = HttpsEnforcementCheck::new(middleware, resolver);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .scheme("http")
            .client_host("10.0.0.1")
            .header("X-Forwarded-Proto", "https")
            .build(),
    );
    assert!(check.check(&request).await.expect("ok").is_some());
}

#[tokio::test]
async fn https_enforcement_ignores_x_forwarded_proto_when_disabled() {
    let middleware = MockMiddleware::new(config_with_trust(false, vec!["10.0.0.1".into()]));
    let resolver = empty_resolver();
    let check = HttpsEnforcementCheck::new(middleware, resolver);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .scheme("http")
            .client_host("10.0.0.1")
            .header("X-Forwarded-Proto", "https")
            .build(),
    );
    assert!(check.check(&request).await.expect("ok").is_some());
}

#[tokio::test]
async fn https_enforcement_reads_non_https_forward_proto_as_http() {
    let middleware = MockMiddleware::new(config_with_trust(true, vec!["10.0.0.1".into()]));
    let resolver = empty_resolver();
    let check = HttpsEnforcementCheck::new(middleware, resolver);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .scheme("http")
            .client_host("10.0.0.1")
            .header("X-Forwarded-Proto", "http")
            .build(),
    );
    assert!(check.check(&request).await.expect("ok").is_some());
}

#[test]
fn https_enforcement_check_debug() {
    let middleware = MockMiddleware::new(base_config());
    let check = HttpsEnforcementCheck::new(middleware, empty_resolver());
    assert!(format!("{check:?}").contains("HttpsEnforcementCheck"));
}
