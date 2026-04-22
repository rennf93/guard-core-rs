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
use guard_core_rs::core::checks::implementations::UserAgentCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::utils::CLIENT_IP_KEY;
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

fn middleware_with_blocked_ua(
    passive: bool,
    patterns: Vec<String>,
) -> (Arc<MockAgent>, Arc<MockMiddleware>) {
    let agent = Arc::new(MockAgent::default());
    let dyn_agent: DynAgentHandler = Arc::clone(&agent) as Arc<dyn AgentHandlerProtocol>;
    let config = Arc::new(
        SecurityConfig::builder()
            .passive_mode(passive)
            .blocked_user_agents(patterns)
            .build()
            .expect("valid"),
    );
    (agent, MockMiddleware::with_handlers(config, Some(dyn_agent), None, None))
}

fn request(path: &str, agent: &str, client_ip: Option<&str>) -> DynGuardRequest {
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path(path)
            .header("User-Agent", agent)
            .build(),
    );
    if let Some(ip) = client_ip {
        request.state().set_str(CLIENT_IP_KEY, ip);
    }
    request
}

#[tokio::test]
async fn user_agent_whitelisted_request_is_allowed() {
    let (_a, middleware) = middleware_with_blocked_ua(false, vec!["evil".into()]);
    let check = UserAgentCheck::new(middleware, empty_resolver());
    let request: DynGuardRequest = Arc::new(MockRequest::default());
    request.state().set_bool("is_whitelisted", true);
    assert!(check.check(&request).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "user_agent");
}

#[tokio::test]
async fn user_agent_allowed_passes_when_no_restrictions() {
    let (_a, middleware) = middleware_with_blocked_ua(false, Vec::new());
    let check = UserAgentCheck::new(middleware, empty_resolver());
    assert!(
        check
            .check(&request("/", "Mozilla/5.0", None))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn user_agent_global_blocklist_blocks() {
    let (agent, middleware) = middleware_with_blocked_ua(false, vec!["evil".into()]);
    let check = UserAgentCheck::new(middleware, empty_resolver());
    let response = check
        .check(&request("/", "evil-agent/1.0", None))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 403);
    let events = agent.events.read();
    assert_eq!(
        events[0]["event_type"],
        serde_json::Value::String("user_agent_blocked".into())
    );
    assert_eq!(
        events[0]["filter_type"],
        serde_json::Value::String("global".into())
    );
}

#[tokio::test]
async fn user_agent_passive_mode_allows_but_logs() {
    let (agent, middleware) = middleware_with_blocked_ua(true, vec!["bad".into()]);
    let check = UserAgentCheck::new(middleware, empty_resolver());
    let result = check.check(&request("/", "bad-ua", None)).await.expect("ok");
    assert!(result.is_none());
    assert_eq!(
        agent.events.read()[0]["action_taken"],
        serde_json::Value::String("logged_only".into())
    );
}

#[tokio::test]
async fn user_agent_route_level_blocked_ua_returns_decorator_violation() {
    let rc = RouteConfig::new().block_user_agents(vec!["custom".into()]);
    let resolver = resolver_with("/x", rc);
    let (agent, middleware) = middleware_with_blocked_ua(false, Vec::new());
    let check = UserAgentCheck::new(middleware, resolver);
    let response = check
        .check(&request("/x", "custom-agent", None))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 403);
    assert_eq!(
        agent.events.read()[0]["event_type"],
        serde_json::Value::String("decorator_violation".into())
    );
}

#[tokio::test]
async fn user_agent_uses_cached_client_ip_when_available() {
    let (agent, middleware) = middleware_with_blocked_ua(false, vec!["evil".into()]);
    let check = UserAgentCheck::new(middleware, empty_resolver());
    check
        .check(&request("/", "evil", Some("10.0.0.1")))
        .await
        .expect("ok");
    assert_eq!(
        agent.events.read()[0]["ip_address"],
        serde_json::Value::String("10.0.0.1".into())
    );
}

#[test]
fn user_agent_check_debug() {
    let (_a, middleware) = middleware_with_blocked_ua(false, Vec::new());
    let check = UserAgentCheck::new(middleware, empty_resolver());
    assert!(format!("{check:?}").contains("UserAgentCheck"));
}
