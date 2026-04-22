#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

use std::sync::Arc;

use async_trait::async_trait;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::error::Result;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::middleware::DynGuardMiddleware;
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::protocols::response::DynGuardResponse;
use mock_middleware::MockMiddleware;

struct AlwaysNoneCheck {
    middleware: DynGuardMiddleware,
}

#[async_trait]
impl SecurityCheck for AlwaysNoneCheck {
    fn check_name(&self) -> &'static str {
        "always_none"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, _request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        Ok(None)
    }
}

fn build_middleware(passive: bool) -> DynGuardMiddleware {
    let config = SecurityConfig::builder()
        .passive_mode(passive)
        .build()
        .expect("valid");
    MockMiddleware::new(Arc::new(config))
}

#[test]
fn default_is_passive_mode_reflects_config() {
    let middleware = build_middleware(true);
    let check = AlwaysNoneCheck { middleware: Arc::clone(&middleware) };
    assert!(check.is_passive_mode());
    assert_eq!(check.check_name(), "always_none");
}

#[test]
fn default_is_passive_mode_false_when_disabled() {
    let middleware = build_middleware(false);
    let check = AlwaysNoneCheck { middleware: Arc::clone(&middleware) };
    assert!(!check.is_passive_mode());
}

#[tokio::test]
async fn check_returns_ok_none_by_default() {
    let middleware = build_middleware(false);
    let check = AlwaysNoneCheck { middleware: Arc::clone(&middleware) };
    let request: DynGuardRequest = Arc::new(mock_request::MockRequest::default());
    let out = check.check(&request).await.expect("ok");
    assert!(out.is_none());
}
