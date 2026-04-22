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
use guard_core_rs::core::checks::implementations::RouteConfigCheck;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::middleware::DynGuardMiddleware;
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::utils::CLIENT_IP_KEY;
use mock_agent::MockAgent;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

fn middleware_no_proxies() -> DynGuardMiddleware {
    MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("valid")))
}

fn middleware_with_proxies() -> DynGuardMiddleware {
    let config = SecurityConfig::builder()
        .trusted_proxies(vec!["10.0.0.1".into()])
        .build()
        .expect("valid");
    MockMiddleware::new(Arc::new(config))
}

fn middleware_with_agent(agent: Arc<MockAgent>) -> DynGuardMiddleware {
    let handler: DynAgentHandler = agent as Arc<dyn AgentHandlerProtocol>;
    let config = SecurityConfig::builder()
        .trusted_proxies(vec!["10.0.0.1".into()])
        .build()
        .expect("valid");
    MockMiddleware::with_handlers(Arc::new(config), Some(handler), None, None)
}

fn request_with_host(host: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().client_host(host).build())
}

fn request_with_forward(host: &str, forwarded: &str) -> DynGuardRequest {
    Arc::new(
        MockRequest::builder()
            .client_host(host)
            .header("X-Forwarded-For", forwarded)
            .build(),
    )
}

#[tokio::test]
async fn route_config_check_sets_client_ip_from_direct_host() {
    let middleware = middleware_no_proxies();
    let check = RouteConfigCheck::new(Arc::clone(&middleware));
    let request = request_with_host("198.51.100.7");
    let result = check.check(&request).await.expect("ok");
    assert!(result.is_none());
    assert_eq!(
        request.state().get_str(CLIENT_IP_KEY).as_deref(),
        Some("198.51.100.7")
    );
    assert_eq!(check.check_name(), "route_config");
    assert!(!check.is_passive_mode());
}

#[tokio::test]
async fn route_config_check_handles_missing_client_host() {
    let middleware = middleware_no_proxies();
    let check = RouteConfigCheck::new(Arc::clone(&middleware));
    let request: DynGuardRequest = Arc::new(MockRequest::builder().build());
    check.check(&request).await.expect("ok");
    assert_eq!(
        request.state().get_str(CLIENT_IP_KEY).as_deref(),
        Some("unknown")
    );
}

#[tokio::test]
async fn route_config_check_sets_from_forwarded_when_trusted() {
    let middleware = middleware_with_proxies();
    let check = RouteConfigCheck::new(Arc::clone(&middleware));
    let request = request_with_forward("10.0.0.1", "203.0.113.9");
    check.check(&request).await.expect("ok");
    assert_eq!(
        request.state().get_str(CLIENT_IP_KEY).as_deref(),
        Some("203.0.113.9")
    );
}

#[tokio::test]
async fn route_config_check_with_agent_records_spoofing_event() {
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware_with_agent(Arc::clone(&agent));
    let mut builder = MockRequest::builder().client_host("198.51.100.5");
    builder = builder.header("X-Forwarded-For", "1.2.3.4");
    let request: DynGuardRequest = Arc::new(builder.build());
    let check = RouteConfigCheck::new(middleware);
    check.check(&request).await.expect("ok");
    let events = agent.events.read();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]["event_type"],
        serde_json::Value::String("suspicious_request".into())
    );
}

#[tokio::test]
async fn route_config_check_middleware_accessor_returns_same_arc() {
    let middleware = middleware_no_proxies();
    let check = RouteConfigCheck::new(Arc::clone(&middleware));
    assert!(Arc::ptr_eq(check.middleware(), &middleware));
}

#[test]
fn route_config_check_debug_output_is_visible() {
    let middleware = middleware_no_proxies();
    let check = RouteConfigCheck::new(middleware);
    let out = format!("{check:?}");
    assert!(out.contains("RouteConfigCheck"));
}
