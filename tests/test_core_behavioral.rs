#[path = "support/request.rs"]
mod mock_request;

use std::sync::Arc;

use guard_core_rs::core::behavioral::context::BehavioralContext;
use guard_core_rs::core::behavioral::processor::BehavioralProcessor;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_request::MockRequest;

fn config() -> Arc<SecurityConfig> {
    Arc::new(SecurityConfig::builder().build().expect("valid"))
}

fn request_with(method: &str, path: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().method(method).path(path).build())
}

#[test]
fn behavioral_context_stores_config() {
    let cfg = config();
    let context = BehavioralContext::new(Arc::clone(&cfg));
    assert!(Arc::ptr_eq(&context.config, &cfg));
}

#[test]
fn behavioral_context_debug_output() {
    let context = BehavioralContext::new(config());
    let text = format!("{context:?}");
    assert!(text.contains("BehavioralContext"));
}

#[test]
fn behavioral_context_clone_shares_config() {
    let original = BehavioralContext::new(config());
    let cloned = original.clone();
    assert!(Arc::ptr_eq(&original.config, &cloned.config));
}

#[test]
fn behavioral_processor_context_accessor_returns_reference() {
    let context = BehavioralContext::new(config());
    let processor = BehavioralProcessor::new(context.clone());
    assert!(Arc::ptr_eq(&processor.context().config, &context.config));
}

#[tokio::test]
async fn get_endpoint_id_combines_method_and_path() {
    let processor = BehavioralProcessor::new(BehavioralContext::new(config()));
    let request = request_with("POST", "/api/data");
    assert_eq!(processor.get_endpoint_id(&request), "POST:/api/data");
}

#[tokio::test]
async fn get_endpoint_id_handles_root_path() {
    let processor = BehavioralProcessor::new(BehavioralContext::new(config()));
    let request = request_with("GET", "/");
    assert_eq!(processor.get_endpoint_id(&request), "GET:/");
}

#[test]
fn behavioral_processor_clone_and_debug() {
    let processor = BehavioralProcessor::new(BehavioralContext::new(config()));
    let cloned = processor.clone();
    let output = format!("{cloned:?}");
    assert!(output.contains("BehavioralProcessor"));
}
