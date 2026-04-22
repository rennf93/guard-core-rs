#[path = "support/request.rs"]
mod mock_request;

use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheckPipeline;
use guard_core_rs::protocols::request::GuardRequest;
use mock_request::MockRequest;

#[test]
fn pipeline_empty_has_no_check_names() {
    let pipeline = SecurityCheckPipeline::new();
    assert!(pipeline.get_check_names().is_empty());
}

#[tokio::test]
async fn empty_pipeline_returns_none() {
    let pipeline = SecurityCheckPipeline::new();
    let req: Arc<dyn GuardRequest> = Arc::new(MockRequest::default());
    let result = pipeline.execute(&req).await.expect("ok");
    assert!(result.is_none());
}
