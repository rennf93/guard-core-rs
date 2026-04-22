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
use guard_core_rs::core::checks::implementations::RequestSizeContentCheck;
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

#[tokio::test]
async fn request_size_content_no_route_returns_none() {
    let check = RequestSizeContentCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(check.check(&request_at("/", &[])).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "request_size_content");
}

#[tokio::test]
async fn request_size_content_passes_when_size_within_limit() {
    let mut rc = RouteConfig::new();
    rc.max_request_size = Some(500);
    let resolver = resolver_with("/upload", rc);
    let (_agent, middleware) = middleware_with_agent(false);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request_at("/upload", &[("content-length", "100")]))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn request_size_content_blocks_when_size_exceeds_limit() {
    let mut rc = RouteConfig::new();
    rc.max_request_size = Some(100);
    let resolver = resolver_with("/upload", rc);
    let (agent, middleware) = middleware_with_agent(false);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    let response = check
        .check(&request_at("/upload", &[("content-length", "250")]))
        .await
        .expect("ok")
        .expect("response");
    assert_eq!(response.status_code(), 413);
    assert_eq!(
        agent.events.read()[0]["event_type"],
        serde_json::Value::String("content_filtered".into())
    );
}

#[tokio::test]
async fn request_size_content_passive_mode_logs_but_passes_through() {
    let mut rc = RouteConfig::new();
    rc.max_request_size = Some(100);
    let resolver = resolver_with("/upload", rc);
    let (agent, middleware) = middleware_with_agent(true);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    let result = check
        .check(&request_at("/upload", &[("content-length", "250")]))
        .await
        .expect("ok");
    assert!(result.is_none());
    assert_eq!(
        agent.events.read()[0]["action_taken"],
        serde_json::Value::String("logged_only".into())
    );
}

#[tokio::test]
async fn request_size_content_missing_content_length_header_is_allowed() {
    let mut rc = RouteConfig::new();
    rc.max_request_size = Some(100);
    let resolver = resolver_with("/upload", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request_at("/upload", &[]))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn request_size_content_invalid_content_length_header_is_allowed() {
    let mut rc = RouteConfig::new();
    rc.max_request_size = Some(100);
    let resolver = resolver_with("/upload", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request_at("/upload", &[("content-length", "xxx")]))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn request_size_content_allowed_content_type_passes() {
    let mut rc = RouteConfig::new();
    rc.allowed_content_types = Some(vec!["application/json".into()]);
    let resolver = resolver_with("/u", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request_at("/u", &[("content-type", "application/json; charset=utf-8")]))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn request_size_content_blocks_invalid_content_type() {
    let mut rc = RouteConfig::new();
    rc.allowed_content_types = Some(vec!["application/json".into()]);
    let resolver = resolver_with("/u", rc);
    let (agent, middleware) = middleware_with_agent(false);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    let response = check
        .check(&request_at("/u", &[("content-type", "text/plain")]))
        .await
        .expect("ok")
        .expect("response");
    assert_eq!(response.status_code(), 415);
    assert_eq!(
        agent.events.read()[0]["event_type"],
        serde_json::Value::String("content_filtered".into())
    );
}

#[tokio::test]
async fn request_size_content_passive_mode_blocks_but_returns_none_for_content_type() {
    let mut rc = RouteConfig::new();
    rc.allowed_content_types = Some(vec!["application/json".into()]);
    let resolver = resolver_with("/u", rc);
    let (_a, middleware) = middleware_with_agent(true);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    let result = check
        .check(&request_at("/u", &[("content-type", "text/plain")]))
        .await
        .expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn request_size_content_empty_content_type_when_missing_header() {
    let mut rc = RouteConfig::new();
    rc.allowed_content_types = Some(vec!["application/json".into()]);
    let resolver = resolver_with("/u", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    let response = check
        .check(&request_at("/u", &[]))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 415);
}

#[tokio::test]
async fn request_size_content_uses_cached_client_ip_when_available() {
    use guard_core_rs::utils::CLIENT_IP_KEY;
    let mut rc = RouteConfig::new();
    rc.max_request_size = Some(100);
    let resolver = resolver_with("/upload", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/upload")
            .header("content-length", "250")
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.200");
    let response = check.check(&request).await.expect("ok").expect("blocked");
    assert_eq!(response.status_code(), 413);
}

#[tokio::test]
async fn request_size_content_allowed_content_type_passive_uses_cached_ip() {
    use guard_core_rs::utils::CLIENT_IP_KEY;
    let mut rc = RouteConfig::new();
    rc.allowed_content_types = Some(vec!["application/json".into()]);
    let resolver = resolver_with("/u", rc);
    let (_a, middleware) = middleware_with_agent(true);
    let check = RequestSizeContentCheck::new(middleware, resolver);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/u")
            .header("content-type", "text/plain")
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.201");
    let result = check.check(&request).await.expect("ok");
    assert!(result.is_none());
}

#[test]
fn request_size_content_check_debug() {
    let check = RequestSizeContentCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(format!("{check:?}").contains("RequestSizeContentCheck"));
}
