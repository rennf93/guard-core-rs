#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::RequestLoggingCheck;
use guard_core_rs::models::{LogLevel, SecurityConfig};
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

fn request() -> DynGuardRequest {
    Arc::new(MockRequest::default())
}

#[tokio::test]
async fn request_logging_check_always_returns_none_without_level() {
    let config = SecurityConfig::builder().build().expect("valid");
    let middleware = MockMiddleware::new(Arc::new(config));
    let check = RequestLoggingCheck::new(middleware);
    assert!(check.check(&request()).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "request_logging");
}

#[tokio::test]
async fn request_logging_check_returns_none_when_log_level_set() {
    let mut config = SecurityConfig::builder().build().expect("valid");
    config.log_request_level = Some(LogLevel::Info);
    let middleware = MockMiddleware::new(Arc::new(config));
    let check = RequestLoggingCheck::new(middleware);
    assert!(check.check(&request()).await.expect("ok").is_none());
}

#[test]
fn request_logging_check_debug_output() {
    let middleware = MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v")));
    let check = RequestLoggingCheck::new(middleware);
    assert!(format!("{check:?}").contains("RequestLoggingCheck"));
}
