#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

use std::collections::HashSet;
use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::{
    AuthenticationCheck, CloudIpRefreshCheck, CustomRequestCheck, CustomValidatorsCheck,
    EmergencyModeCheck, HttpsEnforcementCheck, IpSecurityCheck, RateLimitCheck, ReferrerCheck,
    RequestLoggingCheck, RequestSizeContentCheck, RequiredHeadersCheck, RouteConfigCheck,
    SuspiciousActivityCheck, TimeWindowCheck, UserAgentCheck,
};
#[cfg(feature = "cloud-providers")]
use guard_core_rs::core::checks::implementations::CloudProviderCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
#[cfg(feature = "cloud-providers")]
use guard_core_rs::handlers::cloud::CloudManager;
use guard_core_rs::handlers::ipban::IPBanManager;
use guard_core_rs::handlers::ratelimit::RateLimitManager;
use guard_core_rs::handlers::suspatterns::SusPatternsManager;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::middleware::DynGuardMiddleware;
use mock_middleware::MockMiddleware;

fn middleware() -> DynGuardMiddleware {
    MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("valid")))
}

fn resolver() -> Arc<RouteConfigResolver> {
    Arc::new(RouteConfigResolver::new(RoutingContext::new(Arc::new(
        SecurityConfig::builder().build().expect("valid"),
    ))))
}

#[test]
fn route_config_check_middleware_accessor() {
    let m = middleware();
    let check = RouteConfigCheck::new(Arc::clone(&m));
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn emergency_mode_check_middleware_accessor() {
    let m = middleware();
    let check = EmergencyModeCheck::new(Arc::clone(&m));
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn https_enforcement_check_middleware_accessor() {
    let m = middleware();
    let check = HttpsEnforcementCheck::new(Arc::clone(&m), resolver());
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn request_logging_check_middleware_accessor() {
    let m = middleware();
    let check = RequestLoggingCheck::new(Arc::clone(&m));
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn request_size_content_check_middleware_accessor() {
    let m = middleware();
    let check = RequestSizeContentCheck::new(Arc::clone(&m), resolver());
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn required_headers_check_middleware_accessor() {
    let m = middleware();
    let check = RequiredHeadersCheck::new(Arc::clone(&m), resolver());
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn authentication_check_middleware_accessor() {
    let m = middleware();
    let check = AuthenticationCheck::new(Arc::clone(&m), resolver());
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn referrer_check_middleware_accessor() {
    let m = middleware();
    let check = ReferrerCheck::new(Arc::clone(&m), resolver());
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn custom_validators_check_middleware_accessor() {
    let m = middleware();
    let check = CustomValidatorsCheck::new(Arc::clone(&m), resolver());
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn time_window_check_middleware_accessor() {
    let m = middleware();
    let check = TimeWindowCheck::new(Arc::clone(&m), resolver());
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn cloud_ip_refresh_check_middleware_accessor() {
    let m = middleware();
    let check = CloudIpRefreshCheck::new(Arc::clone(&m));
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn ip_security_check_middleware_accessor() {
    let m = middleware();
    let check = IpSecurityCheck::new(
        Arc::clone(&m),
        resolver(),
        Arc::new(IPBanManager::new()),
    );
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[cfg(feature = "cloud-providers")]
#[test]
fn cloud_provider_check_middleware_accessor() {
    let m = middleware();
    let check = CloudProviderCheck::new(Arc::clone(&m), resolver(), Arc::new(CloudManager::new()));
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn user_agent_check_middleware_accessor() {
    let m = middleware();
    let check = UserAgentCheck::new(Arc::clone(&m), resolver());
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn rate_limit_check_middleware_accessor() {
    let m = middleware();
    let config = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let rm = RateLimitManager::new(config);
    let check = RateLimitCheck::new(Arc::clone(&m), resolver(), rm);
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn suspicious_activity_check_middleware_accessor() {
    let m = middleware();
    let config = SecurityConfig::builder().build().expect("valid");
    let check = SuspiciousActivityCheck::new(
        Arc::clone(&m),
        resolver(),
        Arc::new(IPBanManager::new()),
        Arc::new(SusPatternsManager::new(Some(&config))),
    );
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn custom_request_check_middleware_accessor() {
    let m = middleware();
    let check = CustomRequestCheck::new(Arc::clone(&m));
    assert!(Arc::ptr_eq(check.middleware(), &m));
}

#[test]
fn is_passive_mode_returns_config_value() {
    let config = Arc::new(
        SecurityConfig::builder()
            .passive_mode(true)
            .build()
            .expect("valid"),
    );
    let m = MockMiddleware::new(config);
    let check = RouteConfigCheck::new(m);
    assert!(check.is_passive_mode());
}

#[test]
fn cloud_providers_ensures_compile_reach() {
    let set: HashSet<guard_core_rs::models::CloudProvider> = HashSet::new();
    drop(set);
}
