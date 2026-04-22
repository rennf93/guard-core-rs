#[path = "support/response.rs"]
mod mock_response;

use std::sync::Arc;

use guard_core_rs::core::responses::context::ResponseContext;
use guard_core_rs::core::responses::factory::ErrorResponseFactory;
use guard_core_rs::models::{SecurityConfig, SecurityHeadersConfig};
use guard_core_rs::protocols::response::{GuardResponse, GuardResponseFactory};
use mock_response::{MockResponse, MockResponseFactory};

#[test]
fn mock_response_headers_roundtrip() {
    let response = MockResponse::new(200, "hello");
    response.set_header("Content-Type", "text/plain");
    assert_eq!(response.status_code(), 200);
    let headers = response.headers();
    assert_eq!(headers.get("Content-Type").map(String::as_str), Some("text/plain"));
    assert_eq!(response.body().as_deref(), Some("hello".as_bytes()));
}

#[test]
fn mock_response_remove_header() {
    let response = MockResponse::new(200, "");
    response.set_header("X-Test", "v1");
    response.remove_header("X-Test");
    assert!(response.header("X-Test").is_none());
}

#[test]
fn mock_factory_records_created_responses() {
    let factory = Arc::new(MockResponseFactory::default());
    let _r1 = factory.create_response("blocked", 403);
    let _r2 = factory.create_response("limited", 429);
    let created = factory.created.read();
    assert_eq!(created.len(), 2);
    assert_eq!(created[0], (403, "blocked".into()));
    assert_eq!(created[1], (429, "limited".into()));
}

#[test]
fn mock_factory_redirect_sets_location() {
    let factory = Arc::new(MockResponseFactory::default());
    let resp = factory.create_redirect_response("https://example.com", 301);
    assert_eq!(resp.status_code(), 301);
    assert_eq!(resp.header("Location").as_deref(), Some("https://example.com"));
}

#[test]
fn error_response_factory_uses_custom_messages() {
    let mut config = SecurityConfig::builder().build().expect("valid");
    config
        .custom_error_responses
        .insert(403, "Custom Forbidden".into());
    let factory = Arc::new(MockResponseFactory::default());
    let context = ResponseContext::new(Arc::new(config), factory.clone());
    let error_factory = ErrorResponseFactory::new(context);
    let _r = error_factory.create_error_response(403, "Default");
    let created = factory.created.read();
    assert_eq!(created[0], (403, "Custom Forbidden".into()));
}

#[test]
fn error_response_factory_applies_security_headers() {
    let mut config = SecurityConfig::builder().build().expect("valid");
    config.security_headers = Some(SecurityHeadersConfig::default());
    let factory = Arc::new(MockResponseFactory::default());
    let context = ResponseContext::new(Arc::new(config), factory);
    let error_factory = ErrorResponseFactory::new(context);
    let response = MockResponse::new(200, "ok");
    let processed = error_factory.process_response(response);
    let headers = processed.headers();
    assert!(headers.contains_key("X-Frame-Options"));
    assert!(headers.contains_key("X-Content-Type-Options"));
    assert!(headers.contains_key("Strict-Transport-Security"));
}
