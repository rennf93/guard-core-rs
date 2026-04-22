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
use guard_core_rs::core::checks::implementations::AuthenticationCheck;
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

fn request(path: &str, header: Option<&str>) -> DynGuardRequest {
    let mut b = MockRequest::builder().path(path);
    if let Some(h) = header {
        b = b.header("Authorization", h);
    }
    Arc::new(b.build())
}

#[tokio::test]
async fn authentication_no_route_returns_none() {
    let check = AuthenticationCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(check.check(&request("/", None)).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "authentication");
}

#[tokio::test]
async fn authentication_route_without_auth_required_returns_none() {
    let resolver = resolver_with("/open", RouteConfig::new());
    let (_a, middleware) = middleware_with_agent(false);
    let check = AuthenticationCheck::new(middleware, resolver);
    assert!(check.check(&request("/open", None)).await.expect("ok").is_none());
}

#[tokio::test]
async fn authentication_bearer_valid_returns_none() {
    let resolver = resolver_with("/secure", RouteConfig::new().require_auth("bearer"));
    let (_a, middleware) = middleware_with_agent(false);
    let check = AuthenticationCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request("/secure", Some("Bearer abc")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn authentication_bearer_missing_blocks_with_401() {
    let resolver = resolver_with("/secure", RouteConfig::new().require_auth("bearer"));
    let (agent, middleware) = middleware_with_agent(false);
    let check = AuthenticationCheck::new(middleware, resolver);
    let response = check
        .check(&request("/secure", None))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 401);
    let events = agent.events.read();
    assert_eq!(
        events[0]["event_type"],
        serde_json::Value::String("decorator_violation".into())
    );
}

#[tokio::test]
async fn authentication_bearer_invalid_scheme_blocks() {
    let resolver = resolver_with("/secure", RouteConfig::new().require_auth("bearer"));
    let (_a, middleware) = middleware_with_agent(false);
    let check = AuthenticationCheck::new(middleware, resolver);
    let response = check
        .check(&request("/secure", Some("Basic abc")))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
async fn authentication_basic_valid_returns_none() {
    let resolver = resolver_with("/secure", RouteConfig::new().require_auth("basic"));
    let (_a, middleware) = middleware_with_agent(false);
    let check = AuthenticationCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request("/secure", Some("Basic abc")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn authentication_basic_invalid_blocks() {
    let resolver = resolver_with("/secure", RouteConfig::new().require_auth("basic"));
    let (_a, middleware) = middleware_with_agent(false);
    let check = AuthenticationCheck::new(middleware, resolver);
    let response = check
        .check(&request("/secure", Some("Bearer abc")))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 401);
}

#[tokio::test]
async fn authentication_passive_mode_does_not_return_response() {
    let resolver = resolver_with("/secure", RouteConfig::new().require_auth("bearer"));
    let (agent, middleware) = middleware_with_agent(true);
    let check = AuthenticationCheck::new(middleware, resolver);
    let result = check.check(&request("/secure", None)).await.expect("ok");
    assert!(result.is_none());
    assert_eq!(
        agent.events.read()[0]["action_taken"],
        serde_json::Value::String("logged_only".into())
    );
}

#[tokio::test]
async fn authentication_custom_scheme_missing_reports_missing_auth() {
    let resolver = resolver_with("/secure", RouteConfig::new().require_auth("apikey"));
    let (agent, middleware) = middleware_with_agent(false);
    let check = AuthenticationCheck::new(middleware, resolver);
    let _ = check.check(&request("/secure", None)).await.expect("ok");
    assert_eq!(
        agent.events.read()[0]["reason"],
        serde_json::Value::String("Missing authentication".into())
    );
}

#[tokio::test]
async fn authentication_custom_scheme_present_reports_valid() {
    let resolver = resolver_with("/secure", RouteConfig::new().require_auth("apikey"));
    let (_a, middleware) = middleware_with_agent(false);
    let check = AuthenticationCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request("/secure", Some("ApiKey xyz")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[test]
fn authentication_check_debug() {
    let check = AuthenticationCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(format!("{check:?}").contains("AuthenticationCheck"));
}
