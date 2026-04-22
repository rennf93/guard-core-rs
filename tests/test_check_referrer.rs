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
use guard_core_rs::core::checks::implementations::ReferrerCheck;
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

fn request(path: &str, referer: Option<&str>) -> DynGuardRequest {
    let mut b = MockRequest::builder().path(path);
    if let Some(r) = referer {
        b = b.header("referer", r);
    }
    Arc::new(b.build())
}

#[tokio::test]
async fn referrer_no_route_returns_none() {
    let check = ReferrerCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(check.check(&request("/", None)).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "referrer");
}

#[tokio::test]
async fn referrer_route_without_require_returns_none() {
    let resolver = resolver_with("/x", RouteConfig::new());
    let (_a, middleware) = middleware_with_agent(false);
    let check = ReferrerCheck::new(middleware, resolver);
    assert!(check.check(&request("/x", None)).await.expect("ok").is_none());
}

#[tokio::test]
async fn referrer_empty_allowed_domains_returns_none() {
    let resolver = resolver_with("/x", RouteConfig::new().require_referrer(vec![]));
    let (_a, middleware) = middleware_with_agent(false);
    let check = ReferrerCheck::new(middleware, resolver);
    assert!(check.check(&request("/x", None)).await.expect("ok").is_none());
}

#[tokio::test]
async fn referrer_missing_header_blocks_with_403() {
    let resolver = resolver_with(
        "/secure",
        RouteConfig::new().require_referrer(vec!["example.com".into()]),
    );
    let (agent, middleware) = middleware_with_agent(false);
    let check = ReferrerCheck::new(middleware, resolver);
    let response = check
        .check(&request("/secure", None))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 403);
    assert_eq!(
        agent.events.read()[0]["reason"],
        serde_json::Value::String("Missing referrer header".into())
    );
}

#[tokio::test]
async fn referrer_missing_header_passive_mode_returns_none() {
    let resolver = resolver_with(
        "/secure",
        RouteConfig::new().require_referrer(vec!["example.com".into()]),
    );
    let (_a, middleware) = middleware_with_agent(true);
    let check = ReferrerCheck::new(middleware, resolver);
    let result = check.check(&request("/secure", None)).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn referrer_valid_domain_passes() {
    let resolver = resolver_with(
        "/secure",
        RouteConfig::new().require_referrer(vec!["example.com".into()]),
    );
    let (_a, middleware) = middleware_with_agent(false);
    let check = ReferrerCheck::new(middleware, resolver);
    assert!(
        check
            .check(&request("/secure", Some("https://example.com/page")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn referrer_invalid_domain_blocks_with_403() {
    let resolver = resolver_with(
        "/secure",
        RouteConfig::new().require_referrer(vec!["example.com".into()]),
    );
    let (agent, middleware) = middleware_with_agent(false);
    let check = ReferrerCheck::new(middleware, resolver);
    let response = check
        .check(&request("/secure", Some("https://malicious.io/")))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 403);
    let events = agent.events.read();
    assert!(events[0]["reason"]
        .as_str()
        .map(|r| r.contains("malicious.io"))
        .unwrap_or(false));
}

#[tokio::test]
async fn referrer_invalid_domain_passive_mode_returns_none() {
    let resolver = resolver_with(
        "/secure",
        RouteConfig::new().require_referrer(vec!["example.com".into()]),
    );
    let (_a, middleware) = middleware_with_agent(true);
    let check = ReferrerCheck::new(middleware, resolver);
    let result = check
        .check(&request("/secure", Some("https://malicious.io/")))
        .await
        .expect("ok");
    assert!(result.is_none());
}

#[test]
fn referrer_check_debug() {
    let check = ReferrerCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(format!("{check:?}").contains("ReferrerCheck"));
}
