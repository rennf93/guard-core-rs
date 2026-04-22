#[path = "support/request.rs"]
mod mock_request;

#[path = "support/geo_ip.rs"]
mod mock_geo;

use std::net::IpAddr;
use std::sync::Arc;

use serde_json::{Value, json};

use guard_core_rs::core::checks::helpers::{
    check_country_access, check_route_ip_access, check_user_agent_allowed,
    get_detection_disabled_reason, get_effective_penetration_setting,
    get_request_content_length, get_request_content_type, is_ip_in_blacklist,
    is_ip_in_whitelist, is_referrer_domain_allowed, request_path_excluded,
    validate_auth_header, validate_auth_header_for_scheme,
};
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::geo_ip::DynGeoIpHandler;
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_geo::MockGeoIpHandler;
use mock_request::MockRequest;

#[test]
fn validate_auth_header_accepts_known_schemes() {
    assert!(validate_auth_header("Basic abc"));
    assert!(validate_auth_header("Bearer token"));
    assert!(validate_auth_header("Digest value"));
    assert!(validate_auth_header("ApiKey some"));
    assert!(validate_auth_header("Token abc"));
}

#[test]
fn validate_auth_header_rejects_empty_and_unknown() {
    assert!(!validate_auth_header(""));
    assert!(!validate_auth_header("   "));
    assert!(!validate_auth_header("Custom scheme"));
}

#[test]
fn validate_auth_header_for_scheme_bearer_valid() {
    let (ok, msg) = validate_auth_header_for_scheme("Bearer token", "bearer");
    assert!(ok);
    assert!(msg.is_empty());
}

#[test]
fn validate_auth_header_for_scheme_bearer_invalid() {
    let (ok, msg) = validate_auth_header_for_scheme("Token abc", "bearer");
    assert!(!ok);
    assert_eq!(msg, "Missing or invalid Bearer token");
}

#[test]
fn validate_auth_header_for_scheme_basic_valid() {
    let (ok, _) = validate_auth_header_for_scheme("Basic aGVsbG8=", "basic");
    assert!(ok);
}

#[test]
fn validate_auth_header_for_scheme_basic_invalid() {
    let (ok, msg) = validate_auth_header_for_scheme("Other", "basic");
    assert!(!ok);
    assert_eq!(msg, "Missing or invalid Basic authentication");
}

#[test]
fn validate_auth_header_for_scheme_default_empty() {
    let (ok, msg) = validate_auth_header_for_scheme("", "custom");
    assert!(!ok);
    assert_eq!(msg, "Missing authentication");
}

#[test]
fn validate_auth_header_for_scheme_default_present() {
    let (ok, msg) = validate_auth_header_for_scheme("anything", "custom");
    assert!(ok);
    assert!(msg.is_empty());
}

#[test]
fn request_path_excluded_exact_match() {
    assert!(request_path_excluded("/foo", &["/foo".into()]));
}

#[test]
fn request_path_excluded_prefix_match() {
    assert!(request_path_excluded("/foo/bar", &["/foo".into()]));
}

#[test]
fn request_path_excluded_no_match() {
    assert!(!request_path_excluded(
        "/other",
        &["/foo".into(), "/bar".into()]
    ));
}

#[test]
fn request_path_excluded_prefix_must_have_slash() {
    assert!(!request_path_excluded("/foobar", &["/foo".into()]));
}

fn request_with_headers(pairs: &[(&str, &str)]) -> DynGuardRequest {
    let mut builder = MockRequest::builder();
    for (k, v) in pairs {
        builder = builder.header(*k, *v);
    }
    Arc::new(builder.build())
}

#[tokio::test]
async fn get_request_content_type_returns_value() {
    let request = request_with_headers(&[("Content-Type", "application/json")]);
    assert_eq!(
        get_request_content_type(&request).as_deref(),
        Some("application/json")
    );
}

#[tokio::test]
async fn get_request_content_type_returns_none_when_missing() {
    let request = request_with_headers(&[]);
    assert!(get_request_content_type(&request).is_none());
}

#[tokio::test]
async fn get_request_content_length_parses_valid_value() {
    let request = request_with_headers(&[("Content-Length", "42")]);
    assert_eq!(get_request_content_length(&request), Some(42));
}

#[tokio::test]
async fn get_request_content_length_returns_none_when_invalid() {
    let request = request_with_headers(&[("Content-Length", "not-a-number")]);
    assert!(get_request_content_length(&request).is_none());
}

#[tokio::test]
async fn get_request_content_length_returns_none_when_absent() {
    let request = request_with_headers(&[]);
    assert!(get_request_content_length(&request).is_none());
}

#[test]
fn is_ip_in_blacklist_matches_exact_ip() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(is_ip_in_blacklist("10.0.0.1", &ip, &["10.0.0.1".into()]));
}

#[test]
fn is_ip_in_blacklist_matches_cidr() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    assert!(is_ip_in_blacklist(
        "10.0.0.5",
        &ip,
        &["10.0.0.0/24".into()]
    ));
}

#[test]
fn is_ip_in_blacklist_no_match() {
    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    assert!(!is_ip_in_blacklist(
        "10.0.0.5",
        &ip,
        &["192.168.0.0/24".into(), "172.16.0.1".into()]
    ));
}

#[test]
fn is_ip_in_blacklist_skips_invalid_cidr() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(!is_ip_in_blacklist(
        "10.0.0.1",
        &ip,
        &["not-a-net/99".into()]
    ));
}

#[test]
fn is_ip_in_whitelist_empty_returns_none() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(is_ip_in_whitelist("10.0.0.1", &ip, &[]), None);
}

#[test]
fn is_ip_in_whitelist_exact_match() {
    let ip: IpAddr = "10.0.0.2".parse().unwrap();
    assert_eq!(
        is_ip_in_whitelist("10.0.0.2", &ip, &["10.0.0.2".into()]),
        Some(true)
    );
}

#[test]
fn is_ip_in_whitelist_cidr_match() {
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert_eq!(
        is_ip_in_whitelist("192.168.1.1", &ip, &["192.168.0.0/16".into()]),
        Some(true)
    );
}

#[test]
fn is_ip_in_whitelist_returns_some_false_if_not_matched() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(
        is_ip_in_whitelist("10.0.0.1", &ip, &["192.168.0.0/16".into()]),
        Some(false)
    );
}

#[test]
fn is_ip_in_whitelist_ignores_invalid_cidr() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(
        is_ip_in_whitelist("10.0.0.1", &ip, &["bad/net".into()]),
        Some(false)
    );
}

fn route_with_blocked_country(country: &str) -> RouteConfig {
    RouteConfig::new().block_countries(vec![country.into()])
}

fn route_with_allowed_country(country: &str) -> RouteConfig {
    RouteConfig::new().allow_countries(vec![country.into()])
}

#[test]
fn check_country_access_returns_none_without_geo_handler() {
    let route = RouteConfig::new();
    assert!(check_country_access("10.0.0.1", &route, None).is_none());
}

#[test]
fn check_country_access_blocked_country() {
    let geo = MockGeoIpHandler::with_mapping(&[("10.0.0.1", "US")]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let route = route_with_blocked_country("US");
    assert_eq!(
        check_country_access("10.0.0.1", &route, Some(&dyn_geo)),
        Some(false)
    );
}

#[test]
fn check_country_access_allowed_country() {
    let geo = MockGeoIpHandler::with_mapping(&[("10.0.0.1", "CA")]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let route = route_with_allowed_country("CA");
    assert_eq!(
        check_country_access("10.0.0.1", &route, Some(&dyn_geo)),
        Some(true)
    );
}

#[test]
fn check_country_access_allowed_country_rejected() {
    let geo = MockGeoIpHandler::with_mapping(&[("10.0.0.1", "DE")]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let route = route_with_allowed_country("CA");
    assert_eq!(
        check_country_access("10.0.0.1", &route, Some(&dyn_geo)),
        Some(false)
    );
}

#[test]
fn check_country_access_empty_route_returns_none() {
    let geo = MockGeoIpHandler::with_mapping(&[("10.0.0.1", "US")]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let route = RouteConfig::new();
    assert!(check_country_access("10.0.0.1", &route, Some(&dyn_geo)).is_none());
}

#[test]
fn check_country_access_allowed_without_country_resolution() {
    let geo = MockGeoIpHandler::with_mapping(&[]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let route = route_with_allowed_country("CA");
    assert_eq!(
        check_country_access("10.0.0.1", &route, Some(&dyn_geo)),
        Some(false)
    );
}

#[test]
fn check_route_ip_access_invalid_ip_returns_false() {
    let route = RouteConfig::new();
    assert_eq!(
        check_route_ip_access("not-an-ip", &route, None),
        Some(false)
    );
}

#[test]
fn check_route_ip_access_blocked_ip_returns_false() {
    let route = RouteConfig::new().require_ip(None, Some(vec!["10.0.0.1".into()]));
    assert_eq!(
        check_route_ip_access("10.0.0.1", &route, None),
        Some(false)
    );
}

#[test]
fn check_route_ip_access_allowed_whitelist_true() {
    let route = RouteConfig::new().require_ip(Some(vec!["10.0.0.2".into()]), None);
    assert_eq!(
        check_route_ip_access("10.0.0.2", &route, None),
        Some(true)
    );
}

#[test]
fn check_route_ip_access_whitelist_miss() {
    let route = RouteConfig::new().require_ip(Some(vec!["10.0.0.2".into()]), None);
    assert_eq!(
        check_route_ip_access("10.0.0.3", &route, None),
        Some(false)
    );
}

#[test]
fn check_route_ip_access_returns_none_without_rules() {
    let route = RouteConfig::new();
    assert!(check_route_ip_access("10.0.0.1", &route, None).is_none());
}

#[test]
fn check_route_ip_access_delegates_to_country_when_no_ip_rules() {
    let route = route_with_allowed_country("US");
    let geo = MockGeoIpHandler::with_mapping(&[("10.0.0.1", "US")]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    assert_eq!(
        check_route_ip_access("10.0.0.1", &route, Some(&dyn_geo)),
        Some(true)
    );
}

fn config_with_blocked_ua(patterns: Vec<String>) -> SecurityConfig {
    
    SecurityConfig::builder()
        .blocked_user_agents(patterns)
        .build()
        .expect("valid")
}

#[test]
fn check_user_agent_allowed_route_pattern_blocks() {
    let config = config_with_blocked_ua(vec![]);
    let route = RouteConfig::new().block_user_agents(vec!["bad.*".into()]);
    assert!(!check_user_agent_allowed("bad-bot", Some(&route), &config));
}

#[test]
fn check_user_agent_allowed_route_pattern_pass_through() {
    let config = config_with_blocked_ua(vec![]);
    let route = RouteConfig::new().block_user_agents(vec!["bad.*".into()]);
    assert!(check_user_agent_allowed("friendly-bot", Some(&route), &config));
}

#[test]
fn check_user_agent_allowed_ignores_invalid_pattern_and_uses_global() {
    let config = config_with_blocked_ua(vec!["evil".into()]);
    let route = RouteConfig::new().block_user_agents(vec!["[".into()]);
    assert!(!check_user_agent_allowed("evil-agent", Some(&route), &config));
}

#[test]
fn check_user_agent_allowed_no_route_uses_global() {
    let config = config_with_blocked_ua(vec!["evil".into()]);
    assert!(!check_user_agent_allowed("evil", None, &config));
    assert!(check_user_agent_allowed("nice", None, &config));
}

#[test]
fn is_referrer_domain_allowed_exact_domain() {
    assert!(is_referrer_domain_allowed(
        "https://example.com/page",
        &["example.com".into()]
    ));
}

#[test]
fn is_referrer_domain_allowed_subdomain() {
    assert!(is_referrer_domain_allowed(
        "https://sub.example.com/",
        &["example.com".into()]
    ));
}

#[test]
fn is_referrer_domain_allowed_case_insensitive() {
    assert!(is_referrer_domain_allowed(
        "https://EXAMPLE.com/",
        &["Example.COM".into()]
    ));
}

#[test]
fn is_referrer_domain_allowed_no_match() {
    assert!(!is_referrer_domain_allowed(
        "https://evil.com/",
        &["example.com".into()]
    ));
}

#[test]
fn is_referrer_domain_allowed_invalid_url() {
    assert!(!is_referrer_domain_allowed(
        "::::invalid",
        &["example.com".into()]
    ));
}

#[test]
fn is_referrer_domain_allowed_missing_host() {
    assert!(!is_referrer_domain_allowed(
        "file:///path",
        &["example.com".into()]
    ));
}

fn config_with_penetration_enabled(enabled: bool) -> SecurityConfig {
    
    SecurityConfig::builder()
        .enable_penetration_detection(enabled)
        .build()
        .expect("valid")
}

#[test]
fn get_effective_penetration_setting_uses_config_when_no_route() {
    let config = config_with_penetration_enabled(true);
    let (enabled, route_specific) = get_effective_penetration_setting(&config, None);
    assert!(enabled);
    assert!(route_specific.is_none());
}

#[test]
fn get_effective_penetration_setting_uses_route_override() {
    let config = config_with_penetration_enabled(true);
    let mut route = RouteConfig::new();
    route
        .custom_metadata
        .insert("enable_suspicious_detection".into(), Value::Bool(false));
    let (enabled, route_specific) = get_effective_penetration_setting(&config, Some(&route));
    assert!(!enabled);
    assert_eq!(route_specific, Some(false));
}

#[test]
fn get_effective_penetration_setting_route_override_non_bool_falls_back() {
    let config = config_with_penetration_enabled(true);
    let mut route = RouteConfig::new();
    route
        .custom_metadata
        .insert("enable_suspicious_detection".into(), json!("yes"));
    let (enabled, route_specific) = get_effective_penetration_setting(&config, Some(&route));
    assert!(enabled);
    assert!(route_specific.is_none());
}

#[test]
fn get_detection_disabled_reason_disabled_by_decorator() {
    let config = config_with_penetration_enabled(true);
    assert_eq!(
        get_detection_disabled_reason(&config, Some(false)),
        "disabled_by_decorator"
    );
}

#[test]
fn get_detection_disabled_reason_not_enabled() {
    let config = config_with_penetration_enabled(false);
    assert_eq!(
        get_detection_disabled_reason(&config, Some(false)),
        "not_enabled"
    );
    assert_eq!(
        get_detection_disabled_reason(&config, None),
        "not_enabled"
    );
}
