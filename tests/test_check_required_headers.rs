#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::collections::HashMap;
use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::RequiredHeadersCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_agent::MockAgent;
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

fn middleware_with_agent(passive: bool) -> (Arc<MockAgent>, Arc<MockMiddleware>) {
    let agent = Arc::new(MockAgent::default());
    let dyn_agent: DynAgentHandler = Arc::clone(&agent) as Arc<dyn AgentHandlerProtocol>;
    let config = Arc::new(
        SecurityConfig::builder()
            .passive_mode(passive)
            .build()
            .expect("valid"),
    );
    (agent, MockMiddleware::with_handlers(config, Some(dyn_agent), None, None))
}

fn request_at(path: &str, headers: &[(&str, &str)]) -> DynGuardRequest {
    let mut b = MockRequest::builder().path(path);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    Arc::new(b.build())
}

fn route_with_required(headers: &[(&str, &str)]) -> RouteConfig {
    let mut map = HashMap::new();
    for (k, v) in headers {
        map.insert((*k).to_string(), (*v).to_string());
    }
    RouteConfig::new().require_headers(map)
}

#[tokio::test]
async fn required_headers_no_route_returns_none() {
    let check = RequiredHeadersCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(check.check(&request_at("/", &[])).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "required_headers");
}

#[tokio::test]
async fn required_headers_empty_required_returns_none() {
    let resolver = resolver_with("/x", RouteConfig::new());
    let (_a, middleware) = middleware_with_agent(false);
    let check = RequiredHeadersCheck::new(middleware, resolver);
    assert!(check.check(&request_at("/x", &[])).await.expect("ok").is_none());
}

#[tokio::test]
async fn required_headers_satisfied_returns_none() {
    let resolver = resolver_with(
        "/secure",
        route_with_required(&[("X-Request-Id", "required")]),
    );
    let (_a, middleware) = middleware_with_agent(false);
    let check = RequiredHeadersCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request_at("/secure", &[("X-Request-Id", "abc")]))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn required_headers_non_required_value_is_ignored() {
    let resolver = resolver_with(
        "/x",
        route_with_required(&[("X-Optional", "optional")]),
    );
    let (_a, middleware) = middleware_with_agent(false);
    let check = RequiredHeadersCheck::new(middleware, resolver);
    assert!(check.check(&request_at("/x", &[])).await.expect("ok").is_none());
}

#[tokio::test]
async fn required_headers_missing_blocks_in_active_mode() {
    let resolver = resolver_with(
        "/secure",
        route_with_required(&[("x-api-key", "required")]),
    );
    let (agent, middleware) = middleware_with_agent(false);
    let check = RequiredHeadersCheck::new(middleware, resolver);
    let response = check
        .check(&request_at("/secure", &[]))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 400);
    let events = agent.events.read();
    assert_eq!(
        events[0]["decorator_type"],
        serde_json::Value::String("authentication".into())
    );
    assert_eq!(
        events[0]["violation_type"],
        serde_json::Value::String("api_key_required".into())
    );
}

#[tokio::test]
async fn required_headers_missing_passive_mode_returns_none() {
    let resolver = resolver_with(
        "/secure",
        route_with_required(&[("Authorization", "required")]),
    );
    let (agent, middleware) = middleware_with_agent(true);
    let check = RequiredHeadersCheck::new(middleware, resolver);
    let result = check.check(&request_at("/secure", &[])).await.expect("ok");
    assert!(result.is_none());
    assert_eq!(
        agent.events.read()[0]["violation_type"],
        serde_json::Value::String("required_header".into())
    );
    assert_eq!(
        agent.events.read()[0]["decorator_type"],
        serde_json::Value::String("authentication".into())
    );
}

#[tokio::test]
async fn required_headers_generic_header_classifies_advanced() {
    let resolver = resolver_with(
        "/z",
        route_with_required(&[("X-Tenant", "required")]),
    );
    let (agent, middleware) = middleware_with_agent(false);
    let check = RequiredHeadersCheck::new(middleware, resolver);
    let _ = check.check(&request_at("/z", &[])).await.expect("ok");
    assert_eq!(
        agent.events.read()[0]["decorator_type"],
        serde_json::Value::String("advanced".into())
    );
}

#[test]
fn required_headers_check_debug() {
    let check = RequiredHeadersCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(format!("{check:?}").contains("RequiredHeadersCheck"));
}
