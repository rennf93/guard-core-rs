#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::sync::Arc;

use bytes::Bytes;
use futures::future::FutureExt;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::CustomRequestCheck;
use guard_core_rs::models::{CustomRequestCheck as CustomRequestCheckFn, CustomResponseModifier, SecurityConfig};
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::protocols::response::{DynGuardResponse, GuardResponse};
use mock_agent::MockAgent;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

struct StubResponse {
    status: u16,
}

impl std::fmt::Debug for StubResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubResponse").finish()
    }
}

impl GuardResponse for StubResponse {
    fn status_code(&self) -> u16 {
        self.status
    }
    fn headers(&self) -> std::collections::HashMap<String, String> {
        std::collections::HashMap::new()
    }
    fn set_header(&self, _: &str, _: &str) {}
    fn remove_header(&self, _: &str) {}
    fn body(&self) -> Option<Bytes> {
        None
    }
}

fn stub_response(status: u16) -> DynGuardResponse {
    Arc::new(StubResponse { status })
}

fn config_with_custom(
    passive: bool,
    blocking: bool,
    with_modifier: bool,
) -> Arc<SecurityConfig> {
    let mut config = SecurityConfig::builder()
        .passive_mode(passive)
        .build()
        .expect("valid");
    if blocking {
        config.custom_request_check = Some(CustomRequestCheckFn(Arc::new(|_req| {
            async move { Some(stub_response(418)) }.boxed()
        })));
    } else {
        config.custom_request_check = Some(CustomRequestCheckFn(Arc::new(|_req| {
            async move { None }.boxed()
        })));
    }
    if with_modifier {
        config.custom_response_modifier =
            Some(CustomResponseModifier(Arc::new(|_resp| {
                async move { stub_response(451) }.boxed()
            })));
    }
    Arc::new(config)
}

fn middleware(agent: Arc<MockAgent>, config: Arc<SecurityConfig>) -> Arc<MockMiddleware> {
    let dyn_agent: DynAgentHandler = agent as Arc<dyn AgentHandlerProtocol>;
    MockMiddleware::with_handlers(config, Some(dyn_agent), None, None)
}

fn request() -> DynGuardRequest {
    Arc::new(MockRequest::default())
}

#[tokio::test]
async fn custom_request_no_check_returns_none() {
    let middleware = MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v")));
    let check = CustomRequestCheck::new(middleware);
    assert!(check.check(&request()).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "custom_request");
}

#[tokio::test]
async fn custom_request_returning_none_is_allowed() {
    let agent = Arc::new(MockAgent::default());
    let config = config_with_custom(false, false, false);
    let middleware = middleware(Arc::clone(&agent), config);
    let check = CustomRequestCheck::new(middleware);
    assert!(check.check(&request()).await.expect("ok").is_none());
    assert!(agent.events.read().is_empty());
}

#[tokio::test]
async fn custom_request_blocking_returns_response() {
    let agent = Arc::new(MockAgent::default());
    let config = config_with_custom(false, true, false);
    let middleware = middleware(Arc::clone(&agent), config);
    let check = CustomRequestCheck::new(middleware);
    let response = check.check(&request()).await.expect("ok").expect("blocked");
    assert_eq!(response.status_code(), 418);
    assert_eq!(
        agent.events.read()[0]["event_type"],
        serde_json::Value::String("custom_request_check".into())
    );
}

#[tokio::test]
async fn custom_request_blocking_passive_mode_does_not_return_response() {
    let agent = Arc::new(MockAgent::default());
    let config = config_with_custom(true, true, false);
    let middleware = middleware(Arc::clone(&agent), config);
    let check = CustomRequestCheck::new(middleware);
    let result = check.check(&request()).await.expect("ok");
    assert!(result.is_none());
    assert_eq!(
        agent.events.read()[0]["action_taken"],
        serde_json::Value::String("logged_only".into())
    );
}

#[tokio::test]
async fn custom_request_applies_response_modifier_when_active() {
    let agent = Arc::new(MockAgent::default());
    let config = config_with_custom(false, true, true);
    let middleware = middleware(agent, config);
    let check = CustomRequestCheck::new(middleware);
    let response = check.check(&request()).await.expect("ok").expect("blocked");
    assert_eq!(response.status_code(), 451);
}

#[test]
fn custom_request_check_debug() {
    let middleware = MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v")));
    let check = CustomRequestCheck::new(middleware);
    assert!(format!("{check:?}").contains("CustomRequestCheck"));
}
