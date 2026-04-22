#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

use std::sync::Arc;

use async_trait::async_trait;

use guard_core_rs::core::checks::{SecurityCheck, SecurityCheckPipeline};
use guard_core_rs::error::{GuardCoreError, Result};
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::middleware::DynGuardMiddleware;
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::protocols::response::DynGuardResponse;
use mock_middleware::{InlineMockResponseFactory, MockMiddleware};
use mock_request::MockRequest;

struct BlockingCheck {
    name: &'static str,
    middleware: DynGuardMiddleware,
    response: DynGuardResponse,
}

#[async_trait]
impl SecurityCheck for BlockingCheck {
    fn check_name(&self) -> &'static str {
        self.name
    }
    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }
    async fn check(&self, _request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        Ok(Some(self.response.clone()))
    }
}

struct PassThroughCheck {
    name: &'static str,
    middleware: DynGuardMiddleware,
}

#[async_trait]
impl SecurityCheck for PassThroughCheck {
    fn check_name(&self) -> &'static str {
        self.name
    }
    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }
    async fn check(&self, _request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        Ok(None)
    }
}

struct ErroringCheck {
    middleware: DynGuardMiddleware,
}

#[async_trait]
impl SecurityCheck for ErroringCheck {
    fn check_name(&self) -> &'static str {
        "erroring"
    }
    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }
    async fn check(&self, _request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        Err(GuardCoreError::Other("boom".into()))
    }
}

fn middleware() -> DynGuardMiddleware {
    MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("valid")))
}

fn request() -> DynGuardRequest {
    Arc::new(MockRequest::default())
}

#[test]
fn pipeline_default_and_new_are_empty() {
    let pipeline = SecurityCheckPipeline::default();
    assert!(pipeline.get_check_names().is_empty());
    let new_pipeline = SecurityCheckPipeline::new();
    assert!(new_pipeline.get_check_names().is_empty());
}

#[test]
fn pipeline_debug_output_lists_check_names() {
    let middleware = middleware();
    let checks: Vec<Arc<dyn SecurityCheck>> = vec![Arc::new(PassThroughCheck {
        name: "first",
        middleware: Arc::clone(&middleware),
    })];
    let pipeline = SecurityCheckPipeline::with_checks(checks);
    let output = format!("{pipeline:?}");
    assert!(output.contains("first"));
    assert!(output.contains("SecurityCheckPipeline"));
}

#[test]
fn pipeline_add_check_appends_to_list() {
    let middleware = middleware();
    let mut pipeline = SecurityCheckPipeline::new();
    pipeline.add_check(Arc::new(PassThroughCheck {
        name: "alpha",
        middleware: Arc::clone(&middleware),
    }));
    pipeline.add_check(Arc::new(PassThroughCheck {
        name: "beta",
        middleware: Arc::clone(&middleware),
    }));
    assert_eq!(pipeline.get_check_names(), vec!["alpha", "beta"]);
}

#[test]
fn pipeline_remove_check_removes_existing_and_reports_change() {
    let middleware = middleware();
    let mut pipeline = SecurityCheckPipeline::new();
    pipeline.add_check(Arc::new(PassThroughCheck {
        name: "alpha",
        middleware: Arc::clone(&middleware),
    }));
    assert!(pipeline.remove_check("alpha"));
    assert!(pipeline.get_check_names().is_empty());
}

#[test]
fn pipeline_remove_check_returns_false_for_missing_name() {
    let mut pipeline = SecurityCheckPipeline::new();
    assert!(!pipeline.remove_check("nope"));
}

#[tokio::test]
async fn pipeline_executes_each_check_and_short_circuits_on_response() {
    let middleware = middleware();
    let factory = InlineMockResponseFactory::default();
    let response = factory.create_response_for_test();
    let pipeline = SecurityCheckPipeline::with_checks(vec![
        Arc::new(PassThroughCheck {
            name: "first",
            middleware: Arc::clone(&middleware),
        }) as Arc<dyn SecurityCheck>,
        Arc::new(BlockingCheck {
            name: "second",
            middleware: Arc::clone(&middleware),
            response: response.clone(),
        }) as Arc<dyn SecurityCheck>,
        Arc::new(PassThroughCheck {
            name: "third",
            middleware: Arc::clone(&middleware),
        }) as Arc<dyn SecurityCheck>,
    ]);
    let returned = pipeline.execute(&request()).await.expect("ok").expect("response");
    assert_eq!(returned.status_code(), response.status_code());
}

#[tokio::test]
async fn pipeline_returns_none_when_no_check_blocks() {
    let middleware = middleware();
    let pipeline = SecurityCheckPipeline::with_checks(vec![
        Arc::new(PassThroughCheck {
            name: "first",
            middleware: Arc::clone(&middleware),
        }) as Arc<dyn SecurityCheck>,
        Arc::new(PassThroughCheck {
            name: "second",
            middleware,
        }) as Arc<dyn SecurityCheck>,
    ]);
    assert!(pipeline.execute(&request()).await.expect("ok").is_none());
}

#[tokio::test]
async fn pipeline_propagates_errors_from_checks() {
    let middleware = middleware();
    let pipeline =
        SecurityCheckPipeline::with_checks(vec![Arc::new(ErroringCheck { middleware }) as _]);
    let err = pipeline.execute(&request()).await.unwrap_err();
    assert!(format!("{err}").contains("boom"));
}

impl InlineMockResponseFactory {
    fn create_response_for_test(&self) -> DynGuardResponse {
        use guard_core_rs::protocols::response::GuardResponseFactory;
        self.create_response("blocked", 418)
    }
}
