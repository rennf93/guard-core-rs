#[path = "support/request.rs"]
mod mock_request;

use std::sync::Arc;

use chrono::{NaiveTime, Timelike, Utc};

use guard_core_rs::core::validation::context::ValidationContext;
use guard_core_rs::core::validation::validator::RequestValidator;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_request::MockRequest;

fn config_with_trusted_proxies(proxies: Vec<String>, trust_forwarded: bool) -> Arc<SecurityConfig> {
    let config = SecurityConfig::builder()
        .trusted_proxies(proxies)
        .trust_x_forwarded_proto(trust_forwarded)
        .build()
        .expect("valid");
    Arc::new(config)
}

fn config_with_excludes(excludes: Vec<String>) -> Arc<SecurityConfig> {
    let mut config = SecurityConfig::builder().build().expect("valid");
    config.exclude_paths = excludes;
    Arc::new(config)
}

fn build_request(builder: MockRequest) -> DynGuardRequest {
    Arc::new(builder)
}

#[test]
fn validation_context_stores_config() {
    let config = config_with_trusted_proxies(Vec::new(), false);
    let context = ValidationContext::new(Arc::clone(&config));
    assert!(Arc::ptr_eq(&context.config, &config));
}

#[test]
fn validation_context_debug_contains_name() {
    let config = config_with_trusted_proxies(Vec::new(), false);
    let context = ValidationContext::new(config);
    let text = format!("{context:?}");
    assert!(text.contains("ValidationContext"));
}

#[test]
fn validation_context_clone_shares_config() {
    let config = config_with_trusted_proxies(Vec::new(), false);
    let a = ValidationContext::new(config);
    let b = a.clone();
    assert!(Arc::ptr_eq(&a.config, &b.config));
}

#[tokio::test]
async fn validator_is_request_https_when_scheme_is_https() {
    let config = config_with_trusted_proxies(Vec::new(), false);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let request = build_request(MockRequest::builder().scheme("https").build());
    assert!(validator.is_request_https(&request));
}

#[tokio::test]
async fn validator_is_request_https_with_forwarded_proto_when_trusted() {
    let config = config_with_trusted_proxies(Vec::new(), true);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let request = build_request(
        MockRequest::builder()
            .scheme("http")
            .header("X-Forwarded-Proto", "HTTPS")
            .build(),
    );
    assert!(validator.is_request_https(&request));
}

#[tokio::test]
async fn validator_is_request_https_false_when_forwarded_proto_disabled() {
    let config = config_with_trusted_proxies(Vec::new(), false);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let request = build_request(
        MockRequest::builder()
            .scheme("http")
            .header("X-Forwarded-Proto", "https")
            .build(),
    );
    assert!(!validator.is_request_https(&request));
}

#[tokio::test]
async fn validator_is_request_https_false_when_forwarded_proto_missing() {
    let config = config_with_trusted_proxies(Vec::new(), true);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let request = build_request(MockRequest::builder().scheme("http").build());
    assert!(!validator.is_request_https(&request));
}

#[tokio::test]
async fn validator_is_request_https_false_when_forwarded_proto_non_https() {
    let config = config_with_trusted_proxies(Vec::new(), true);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let request = build_request(
        MockRequest::builder()
            .scheme("http")
            .header("X-Forwarded-Proto", "http")
            .build(),
    );
    assert!(!validator.is_request_https(&request));
}

#[test]
fn validator_is_trusted_proxy_matches_exact_ip() {
    let config = config_with_trusted_proxies(vec!["10.0.0.1".into()], false);
    let validator = RequestValidator::new(ValidationContext::new(config));
    assert!(validator.is_trusted_proxy("10.0.0.1"));
    assert!(!validator.is_trusted_proxy("10.0.0.2"));
}

#[test]
fn validator_is_trusted_proxy_matches_cidr() {
    let config = config_with_trusted_proxies(vec!["192.168.0.0/16".into()], false);
    let validator = RequestValidator::new(ValidationContext::new(config));
    assert!(validator.is_trusted_proxy("192.168.1.50"));
    assert!(!validator.is_trusted_proxy("10.0.0.1"));
}

#[test]
fn validator_check_time_window_normal_range() {
    let config = config_with_trusted_proxies(Vec::new(), false);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let now = Utc::now().time();
    let start = now
        .with_second(0)
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(now);
    let end_secs = start.num_seconds_from_midnight() + 3600;
    let end = NaiveTime::from_num_seconds_from_midnight_opt(end_secs % 86_400, 0).unwrap();
    assert!(validator.check_time_window(start, end));
}

#[test]
fn validator_check_time_window_returns_false_outside_range() {
    let config = config_with_trusted_proxies(Vec::new(), false);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let now = Utc::now().time();
    let one_hour_before = (now.num_seconds_from_midnight() + 86_400 - 7200) % 86_400;
    let one_hour_before_end = (now.num_seconds_from_midnight() + 86_400 - 3600) % 86_400;
    let start = NaiveTime::from_num_seconds_from_midnight_opt(one_hour_before, 0).unwrap();
    let end = NaiveTime::from_num_seconds_from_midnight_opt(one_hour_before_end, 0).unwrap();
    assert!(!validator.check_time_window(start, end));
}

#[test]
fn validator_check_time_window_wraps_around_midnight() {
    let config = config_with_trusted_proxies(Vec::new(), false);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let now = Utc::now().time();
    let now_s = now.num_seconds_from_midnight();
    let start = NaiveTime::from_num_seconds_from_midnight_opt((now_s + 86_400 - 60) % 86_400, 0)
        .unwrap();
    let end = NaiveTime::from_num_seconds_from_midnight_opt((now_s + 60) % 86_400, 0).unwrap();
    assert!(validator.check_time_window(start, end));
}

#[tokio::test]
async fn validator_is_path_excluded_exact_match() {
    let config = config_with_excludes(vec!["/healthz".into()]);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let request = build_request(MockRequest::builder().path("/healthz").build());
    assert!(validator.is_path_excluded(&request));
}

#[tokio::test]
async fn validator_is_path_excluded_prefix_match() {
    let config = config_with_excludes(vec!["/static".into()]);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let request = build_request(MockRequest::builder().path("/static/image.png").build());
    assert!(validator.is_path_excluded(&request));
}

#[tokio::test]
async fn validator_is_path_excluded_returns_false_for_other_path() {
    let config = config_with_excludes(vec!["/docs".into()]);
    let validator = RequestValidator::new(ValidationContext::new(config));
    let request = build_request(MockRequest::builder().path("/api/v1/items").build());
    assert!(!validator.is_path_excluded(&request));
}

#[test]
fn validator_debug_output_contains_type() {
    let config = config_with_excludes(Vec::new());
    let validator = RequestValidator::new(ValidationContext::new(config));
    let debugged = format!("{validator:?}");
    assert!(debugged.contains("RequestValidator"));
}
