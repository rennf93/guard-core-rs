#[path = "support/response.rs"]
mod mock_response;

use std::sync::Arc;

use guard_core_rs::core::responses::context::ResponseContext;
use guard_core_rs::core::responses::factory::ErrorResponseFactory;
use guard_core_rs::models::{SecurityConfig, SecurityHeadersConfig};
use guard_core_rs::protocols::response::DynGuardResponseFactory;
use mock_response::{MockResponse, MockResponseFactory};

fn config_with_headers(headers: Option<SecurityHeadersConfig>) -> Arc<SecurityConfig> {
    let mut config = SecurityConfig::builder().build().expect("valid");
    config.security_headers = headers;
    Arc::new(config)
}

fn factory() -> DynGuardResponseFactory {
    Arc::new(MockResponseFactory::default())
}

#[test]
fn response_context_stores_fields() {
    let cfg = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let f = factory();
    let context = ResponseContext::new(Arc::clone(&cfg), Arc::clone(&f));
    assert!(Arc::ptr_eq(&context.config, &cfg));
    assert!(Arc::ptr_eq(&context.response_factory, &f));
}

#[test]
fn response_context_clone_preserves_fields() {
    let cfg = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let f = factory();
    let original = ResponseContext::new(Arc::clone(&cfg), Arc::clone(&f));
    let cloned = original.clone();
    assert!(Arc::ptr_eq(&cloned.config, &cfg));
    assert!(Arc::ptr_eq(&cloned.response_factory, &f));
}

#[test]
fn response_context_debug_output() {
    let context = ResponseContext::new(
        Arc::new(SecurityConfig::builder().build().expect("valid")),
        factory(),
    );
    assert!(format!("{context:?}").contains("ResponseContext"));
}

#[test]
fn error_response_factory_uses_default_message_when_no_override() {
    let context = ResponseContext::new(
        Arc::new(SecurityConfig::builder().build().expect("valid")),
        factory(),
    );
    let err_factory = ErrorResponseFactory::new(context);
    let response = err_factory.create_error_response(429, "Too many");
    assert_eq!(response.status_code(), 429);
}

#[test]
fn error_response_factory_uses_custom_message_when_available() {
    let mut config = SecurityConfig::builder().build().expect("valid");
    config.custom_error_responses.insert(403, "Nope".into());
    let context = ResponseContext::new(Arc::new(config), factory());
    let err_factory = ErrorResponseFactory::new(context);
    let response = err_factory.create_error_response(403, "default");
    assert_eq!(response.status_code(), 403);
}

#[test]
fn error_response_factory_creates_https_redirect() {
    let context = ResponseContext::new(
        Arc::new(SecurityConfig::builder().build().expect("valid")),
        factory(),
    );
    let err_factory = ErrorResponseFactory::new(context);
    let response = err_factory.create_https_redirect("https://example.com/a");
    assert_eq!(response.status_code(), 301);
    assert_eq!(
        response.header("Location").as_deref(),
        Some("https://example.com/a")
    );
}

#[test]
fn error_response_factory_process_response_applies_full_security_headers() {
    let mut headers = SecurityHeadersConfig::default();
    let mut custom = std::collections::HashMap::new();
    custom.insert("X-Custom".to_string(), "value".to_string());
    headers.custom = Some(custom);
    headers.csp = Some("default-src 'self'".into());
    let cfg = config_with_headers(Some(headers));
    let context = ResponseContext::new(cfg, factory());
    let err_factory = ErrorResponseFactory::new(context);
    let response = MockResponse::new(200, "ok");
    let processed = err_factory.process_response(response);
    assert!(processed.header("Strict-Transport-Security").is_some());
    assert!(processed.header("Content-Security-Policy").is_some());
    assert_eq!(
        processed.header("X-Custom").as_deref(),
        Some("value")
    );
}

#[test]
fn error_response_factory_process_response_skips_headers_when_disabled() {
    let headers = SecurityHeadersConfig { enabled: false, ..SecurityHeadersConfig::default() };
    let cfg = config_with_headers(Some(headers));
    let context = ResponseContext::new(cfg, factory());
    let err_factory = ErrorResponseFactory::new(context);
    let response = MockResponse::new(200, "ok");
    let processed = err_factory.process_response(response);
    assert!(processed.header("X-Frame-Options").is_none());
}

#[test]
fn error_response_factory_process_response_skips_headers_when_none() {
    let cfg = config_with_headers(None);
    let context = ResponseContext::new(cfg, factory());
    let err_factory = ErrorResponseFactory::new(context);
    let response = MockResponse::new(200, "ok");
    let processed = err_factory.process_response(response);
    assert!(processed.header("X-Frame-Options").is_none());
}

#[test]
fn error_response_factory_debug_output() {
    let context = ResponseContext::new(
        Arc::new(SecurityConfig::builder().build().expect("valid")),
        factory(),
    );
    let err_factory = ErrorResponseFactory::new(context);
    assert!(format!("{err_factory:?}").contains("ErrorResponseFactory"));
}

#[test]
fn error_response_factory_clone_works() {
    let context = ResponseContext::new(
        Arc::new(SecurityConfig::builder().build().expect("valid")),
        factory(),
    );
    let err_factory = ErrorResponseFactory::new(context);
    let cloned = err_factory.clone();
    let response = cloned.create_error_response(500, "server error");
    assert_eq!(response.status_code(), 500);
}

#[test]
fn error_response_factory_applies_hsts_variations() {
    let mut headers = SecurityHeadersConfig::default();
    headers.hsts.include_subdomains = false;
    headers.hsts.preload = true;
    headers.hsts.max_age = 60;
    let cfg = config_with_headers(Some(headers));
    let context = ResponseContext::new(cfg, factory());
    let err_factory = ErrorResponseFactory::new(context);
    let response = MockResponse::new(200, "ok");
    let processed = err_factory.process_response(response);
    let hsts = processed
        .header("Strict-Transport-Security")
        .expect("hsts");
    assert!(hsts.contains("max-age=60"));
    assert!(hsts.contains("preload"));
    assert!(!hsts.contains("includeSubDomains"));
}
