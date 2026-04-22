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
use guard_core_rs::core::checks::implementations::EmergencyModeCheck;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::utils::CLIENT_IP_KEY;
use mock_agent::MockAgent;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

fn emergency_config(active: bool, whitelist: Vec<String>, passive: bool) -> Arc<SecurityConfig> {
    let mut config = SecurityConfig::builder()
        .passive_mode(passive)
        .build()
        .expect("valid");
    config.emergency_mode = active;
    config.emergency_whitelist = whitelist;
    Arc::new(config)
}

fn request() -> DynGuardRequest {
    Arc::new(MockRequest::builder().client_host("198.51.100.42").build())
}

fn agent_dyn(agent: Arc<MockAgent>) -> DynAgentHandler {
    agent as Arc<dyn AgentHandlerProtocol>
}

#[tokio::test]
async fn emergency_mode_disabled_returns_none() {
    let config = emergency_config(false, vec![], false);
    let middleware = MockMiddleware::new(config);
    let check = EmergencyModeCheck::new(middleware);
    assert!(check.check(&request()).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "emergency_mode");
}

#[tokio::test]
async fn emergency_mode_whitelisted_ip_bypasses_block() {
    let config = emergency_config(true, vec!["198.51.100.42".into()], false);
    let agent = Arc::new(MockAgent::default());
    let middleware = MockMiddleware::with_handlers(
        config,
        Some(agent_dyn(Arc::clone(&agent))),
        None,
        None,
    );
    let check = EmergencyModeCheck::new(middleware);
    assert!(check.check(&request()).await.expect("ok").is_none());
    assert!(agent.events.read().is_empty());
}

#[tokio::test]
async fn emergency_mode_non_whitelisted_in_active_mode_returns_block() {
    let config = emergency_config(true, Vec::new(), false);
    let agent = Arc::new(MockAgent::default());
    let middleware =
        MockMiddleware::with_handlers(config, Some(agent_dyn(Arc::clone(&agent))), None, None);
    let check = EmergencyModeCheck::new(middleware);
    let response = check.check(&request()).await.expect("ok").expect("blocked");
    assert_eq!(response.status_code(), 503);
    let events = agent.events.read();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]["event_type"],
        serde_json::Value::String("emergency_mode_block".into())
    );
    assert_eq!(
        events[0]["action_taken"],
        serde_json::Value::String("request_blocked".into())
    );
}

#[tokio::test]
async fn emergency_mode_passive_mode_returns_none_and_still_reports_event() {
    let config = emergency_config(true, Vec::new(), true);
    let agent = Arc::new(MockAgent::default());
    let middleware =
        MockMiddleware::with_handlers(config, Some(agent_dyn(Arc::clone(&agent))), None, None);
    let check = EmergencyModeCheck::new(middleware);
    let result = check.check(&request()).await.expect("ok");
    assert!(result.is_none());
    let events = agent.events.read();
    assert_eq!(
        events[0]["action_taken"],
        serde_json::Value::String("logged_only".into())
    );
}

#[tokio::test]
async fn emergency_mode_reads_cached_client_ip_when_already_set() {
    let config = emergency_config(true, vec!["10.10.10.10".into()], false);
    let middleware = MockMiddleware::new(config);
    let check = EmergencyModeCheck::new(middleware);
    let request: DynGuardRequest = Arc::new(MockRequest::default());
    request.state().set_str(CLIENT_IP_KEY, "10.10.10.10");
    assert!(check.check(&request).await.expect("ok").is_none());
}

#[test]
fn emergency_mode_check_debug_output() {
    let config = emergency_config(false, Vec::new(), false);
    let middleware = MockMiddleware::new(config);
    let check = EmergencyModeCheck::new(middleware);
    assert!(format!("{check:?}").contains("EmergencyModeCheck"));
}
