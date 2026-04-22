#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

use std::collections::HashSet;
use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::CloudIpRefreshCheck;
use guard_core_rs::models::{CloudProvider, SecurityConfig};
use guard_core_rs::protocols::middleware::{DynGuardMiddleware, GuardMiddlewareProtocol};
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

fn request() -> DynGuardRequest {
    Arc::new(MockRequest::default())
}

fn middleware_with_clouds(set: Option<HashSet<CloudProvider>>) -> Arc<MockMiddleware> {
    let config = SecurityConfig::builder()
        .block_cloud_providers(set)
        .build()
        .expect("valid");
    MockMiddleware::new(Arc::new(config))
}

#[tokio::test]
async fn cloud_ip_refresh_noop_when_no_providers_configured() {
    let middleware = middleware_with_clouds(None);
    let dyn_middleware: DynGuardMiddleware = Arc::clone(&middleware) as DynGuardMiddleware;
    let check = CloudIpRefreshCheck::new(Arc::clone(&dyn_middleware));
    assert!(check.check(&request()).await.expect("ok").is_none());
    assert_eq!(middleware.cloud_refresh_calls(), 0);
    assert_eq!(check.check_name(), "cloud_ip_refresh");
}

#[tokio::test]
async fn cloud_ip_refresh_invokes_refresh_when_overdue() {
    let mut providers = HashSet::new();
    providers.insert(CloudProvider::Aws);
    let middleware = middleware_with_clouds(Some(providers));
    middleware.set_last_cloud_ip_refresh(0);
    let dyn_middleware: DynGuardMiddleware = Arc::clone(&middleware) as DynGuardMiddleware;
    let check = CloudIpRefreshCheck::new(Arc::clone(&dyn_middleware));
    check.check(&request()).await.expect("ok");
    assert_eq!(middleware.cloud_refresh_calls(), 1);
}

#[tokio::test]
async fn cloud_ip_refresh_skips_when_refresh_recent() {
    let mut providers = HashSet::new();
    providers.insert(CloudProvider::Azure);
    let middleware = middleware_with_clouds(Some(providers));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("duration")
        .as_secs() as i64;
    middleware.set_last_cloud_ip_refresh(now);
    let dyn_middleware: DynGuardMiddleware = Arc::clone(&middleware) as DynGuardMiddleware;
    let check = CloudIpRefreshCheck::new(Arc::clone(&dyn_middleware));
    check.check(&request()).await.expect("ok");
    assert_eq!(middleware.cloud_refresh_calls(), 0);
}

#[tokio::test]
async fn cloud_ip_refresh_propagates_refresh_failure() {
    let mut providers = HashSet::new();
    providers.insert(CloudProvider::Gcp);
    let config = SecurityConfig::builder()
        .block_cloud_providers(Some(providers))
        .build()
        .expect("valid");
    let middleware = MockMiddleware::with_refresh_failure(Arc::new(config));
    middleware.set_last_cloud_ip_refresh(0);
    let dyn_middleware: DynGuardMiddleware = Arc::clone(&middleware) as DynGuardMiddleware;
    let check = CloudIpRefreshCheck::new(Arc::clone(&dyn_middleware));
    let err = check.check(&request()).await.unwrap_err();
    assert!(format!("{err}").contains("forced"));
}

#[test]
fn cloud_ip_refresh_check_debug_and_middleware() {
    let middleware: DynGuardMiddleware = middleware_with_clouds(None);
    let check = CloudIpRefreshCheck::new(Arc::clone(&middleware));
    assert!(Arc::ptr_eq(check.middleware(), &middleware));
    assert!(format!("{check:?}").contains("CloudIpRefreshCheck"));
}
