#[path = "support/request.rs"]
mod mock_request;

use std::sync::Arc;

use guard_core_rs::core::bypass::context::BypassContext;
use guard_core_rs::core::bypass::handler::BypassHandler;
use guard_core_rs::core::validation::context::ValidationContext;
use guard_core_rs::core::validation::validator::RequestValidator;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_request::MockRequest;

fn config_with_excludes(excludes: Vec<String>) -> Arc<SecurityConfig> {
    let mut config = SecurityConfig::builder().build().expect("valid");
    config.exclude_paths = excludes;
    Arc::new(config)
}

fn build_handler(config: Arc<SecurityConfig>) -> BypassHandler {
    let validator = RequestValidator::new(ValidationContext::new(Arc::clone(&config)));
    BypassHandler::new(BypassContext::new(config), validator)
}

fn request_with_path(path: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().path(path).build())
}

#[test]
fn bypass_context_stores_config() {
    let config = config_with_excludes(Vec::new());
    let context = BypassContext::new(Arc::clone(&config));
    assert!(Arc::ptr_eq(&context.config, &config));
}

#[test]
fn bypass_context_clone_preserves_config() {
    let config = config_with_excludes(Vec::new());
    let original = BypassContext::new(config);
    let cloned = original.clone();
    assert!(Arc::ptr_eq(&original.config, &cloned.config));
}

#[test]
fn bypass_context_debug_mentions_struct_name() {
    let config = config_with_excludes(Vec::new());
    let context = BypassContext::new(config);
    let output = format!("{context:?}");
    assert!(output.contains("BypassContext"));
}

#[tokio::test]
async fn handle_passthrough_returns_true_for_excluded_path() {
    let handler = build_handler(config_with_excludes(vec!["/health".into()]));
    let request = request_with_path("/health");
    assert!(handler.handle_passthrough(&request));
}

#[tokio::test]
async fn handle_passthrough_returns_false_for_non_excluded_path() {
    let handler = build_handler(config_with_excludes(vec!["/health".into()]));
    let request = request_with_path("/api/data");
    assert!(!handler.handle_passthrough(&request));
}

#[tokio::test]
async fn handle_security_bypass_true_when_path_excluded() {
    let handler = build_handler(config_with_excludes(vec!["/health".into()]));
    let request = request_with_path("/health");
    assert!(handler.handle_security_bypass(&request, "rate_limit"));
}

#[tokio::test]
async fn handle_security_bypass_false_when_path_not_excluded() {
    let handler = build_handler(config_with_excludes(vec!["/health".into()]));
    let request = request_with_path("/api");
    assert!(!handler.handle_security_bypass(&request, "ip"));
}

#[test]
fn handler_debug_contains_type_name() {
    let handler = build_handler(config_with_excludes(Vec::new()));
    let debugged = format!("{handler:?}");
    assert!(debugged.contains("BypassHandler"));
}

#[test]
fn handler_clone_shares_underlying_config() {
    let handler = build_handler(config_with_excludes(Vec::new()));
    let _cloned = handler.clone();
}
