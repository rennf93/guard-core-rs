#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::sync::Arc;

use chrono::{NaiveTime, Timelike, Utc};

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::TimeWindowCheck;
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

fn request(path: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().path(path).build())
}

fn now_offset(secs_offset: i64) -> NaiveTime {
    let now = Utc::now().time();
    let total = now.hour() as i64 * 60 + now.minute() as i64;
    let target = ((total + secs_offset + 1440) % 1440) as u32;
    NaiveTime::from_hms_opt(target / 60, target % 60, 0).expect("valid time")
}

#[tokio::test]
async fn time_window_no_route_returns_none() {
    let check = TimeWindowCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(check.check(&request("/")).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "time_window");
}

#[tokio::test]
async fn time_window_without_window_config_returns_none() {
    let resolver = resolver_with("/x", RouteConfig::new());
    let (_a, middleware) = middleware_with_agent(false);
    let check = TimeWindowCheck::new(middleware, resolver);
    assert!(check.check(&request("/x")).await.expect("ok").is_none());
}

#[tokio::test]
async fn time_window_inside_window_passes() {
    let start = now_offset(-60);
    let end = now_offset(60);
    let rc = RouteConfig::new().time_window(start, end, "UTC");
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = TimeWindowCheck::new(middleware, resolver);
    assert!(check.check(&request("/x")).await.expect("ok").is_none());
}

#[tokio::test]
async fn time_window_outside_window_blocks_with_403() {
    let start = now_offset(120);
    let end = now_offset(180);
    let rc = RouteConfig::new().time_window(start, end, "UTC");
    let resolver = resolver_with("/x", rc);
    let (agent, middleware) = middleware_with_agent(false);
    let check = TimeWindowCheck::new(middleware, resolver);
    let response = check.check(&request("/x")).await.expect("ok").expect("blocked");
    assert_eq!(response.status_code(), 403);
    assert_eq!(
        agent.events.read()[0]["event_type"],
        serde_json::Value::String("decorator_violation".into())
    );
}

#[tokio::test]
async fn time_window_passive_mode_does_not_return_response() {
    let start = now_offset(120);
    let end = now_offset(180);
    let rc = RouteConfig::new().time_window(start, end, "UTC");
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent(true);
    let check = TimeWindowCheck::new(middleware, resolver);
    let result = check.check(&request("/x")).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn time_window_wrapping_midnight_inside_range() {
    let start = now_offset(-5);
    let end = now_offset(5);
    let rc = RouteConfig::new().time_window(start, end, "UTC");
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = TimeWindowCheck::new(middleware, resolver);
    assert!(check.check(&request("/x")).await.expect("ok").is_none());
}

#[test]
fn time_window_check_debug() {
    let check = TimeWindowCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(format!("{check:?}").contains("TimeWindowCheck"));
}
