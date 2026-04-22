#![cfg(feature = "cloud-providers")]

#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

#[path = "support/mock_redis.rs"]
mod mock_redis;

use std::collections::HashSet;
use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::CloudProviderCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::handlers::cloud::CloudManager;
use guard_core_rs::models::{CloudProvider, SecurityConfig};
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::utils::CLIENT_IP_KEY;
use mock_agent::MockAgent;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

fn resolver_with(path: &str, rc: RouteConfig) -> Arc<RouteConfigResolver> {
    let cfg = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let resolver = Arc::new(RouteConfigResolver::new(RoutingContext::new(cfg)));
    resolver.register(path, rc);
    resolver
}

fn empty_resolver() -> Arc<RouteConfigResolver> {
    Arc::new(RouteConfigResolver::new(RoutingContext::new(Arc::new(
        SecurityConfig::builder().build().expect("valid"),
    ))))
}

fn config_with_cloud(set: Option<HashSet<CloudProvider>>) -> Arc<SecurityConfig> {
    let config = SecurityConfig::builder()
        .block_cloud_providers(set)
        .build()
        .expect("valid");
    Arc::new(config)
}

fn middleware(agent: Arc<MockAgent>, config: Arc<SecurityConfig>) -> Arc<MockMiddleware> {
    let dyn_agent: DynAgentHandler = agent as Arc<dyn AgentHandlerProtocol>;
    MockMiddleware::with_handlers(config, Some(dyn_agent), None, None)
}

fn request_with_ip(path: &str, ip: Option<&str>) -> DynGuardRequest {
    let request: DynGuardRequest = Arc::new(MockRequest::builder().path(path).build());
    if let Some(ip_value) = ip {
        request.state().set_str(CLIENT_IP_KEY, ip_value);
    }
    request
}

#[tokio::test]
async fn cloud_provider_whitelisted_ip_bypasses() {
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(Arc::clone(&agent), config_with_cloud(None));
    let cloud_manager = Arc::new(CloudManager::new());
    let check = CloudProviderCheck::new(middleware, empty_resolver(), cloud_manager);
    let request: DynGuardRequest = Arc::new(MockRequest::default());
    request.state().set_bool("is_whitelisted", true);
    assert!(check.check(&request).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "cloud_provider");
}

#[tokio::test]
async fn cloud_provider_missing_client_ip_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(Arc::clone(&agent), config_with_cloud(None));
    let cloud_manager = Arc::new(CloudManager::new());
    let check = CloudProviderCheck::new(middleware, empty_resolver(), cloud_manager);
    assert!(
        check
            .check(&request_with_ip("/", None))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn cloud_provider_bypassed_by_route_config() {
    let rc = RouteConfig::new().bypass(vec!["clouds".into()]);
    let resolver = resolver_with("/x", rc);
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(Arc::clone(&agent), config_with_cloud(None));
    let cloud_manager = Arc::new(CloudManager::new());
    let check = CloudProviderCheck::new(middleware, resolver, cloud_manager);
    assert!(
        check
            .check(&request_with_ip("/x", Some("10.0.0.1")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn cloud_provider_no_providers_configured_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(Arc::clone(&agent), config_with_cloud(None));
    let cloud_manager = Arc::new(CloudManager::new());
    let check = CloudProviderCheck::new(middleware, empty_resolver(), cloud_manager);
    assert!(
        check
            .check(&request_with_ip("/", Some("10.0.0.1")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn cloud_provider_empty_provider_set_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let middleware =
        middleware(Arc::clone(&agent), config_with_cloud(Some(HashSet::new())));
    let cloud_manager = Arc::new(CloudManager::new());
    let check = CloudProviderCheck::new(middleware, empty_resolver(), cloud_manager);
    assert!(
        check
            .check(&request_with_ip("/", Some("10.0.0.1")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn cloud_provider_not_in_ranges_returns_none() {
    let mut providers = HashSet::new();
    providers.insert(CloudProvider::Aws);
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(Arc::clone(&agent), config_with_cloud(Some(providers)));
    let cloud_manager = Arc::new(CloudManager::new());
    let check = CloudProviderCheck::new(middleware, empty_resolver(), cloud_manager);
    assert!(
        check
            .check(&request_with_ip("/", Some("10.0.0.1")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn cloud_provider_route_level_providers_override_config() {
    let rc = RouteConfig::new().block_clouds(Some(vec![CloudProvider::Gcp]));
    let resolver = resolver_with("/gcp", rc);
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(Arc::clone(&agent), config_with_cloud(None));
    let cloud_manager = Arc::new(CloudManager::new());
    let check = CloudProviderCheck::new(middleware, resolver, cloud_manager);
    assert!(
        check
            .check(&request_with_ip("/gcp", Some("10.0.0.1")))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn cloud_provider_matched_ip_emits_event_with_provider_details() {
    use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};
    use serde_json::Value;
    let mut providers = HashSet::new();
    providers.insert(CloudProvider::Aws);
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(Arc::clone(&agent), config_with_cloud(Some(providers.clone())));
    let cloud_manager = Arc::new(CloudManager::new());
    let mock = Arc::new(mock_redis::MockRedis::default());
    mock.data.insert(
        "cloud_ranges:AWS".into(),
        Value::String("10.10.0.0/16".into()),
    );
    let dyn_handler: DynRedisHandler = mock.clone() as Arc<dyn RedisHandlerProtocol>;
    cloud_manager
        .initialize_redis(dyn_handler, providers.clone(), 60)
        .await
        .expect("init");
    let check = CloudProviderCheck::new(middleware, empty_resolver(), cloud_manager);
    let response = check
        .check(&request_with_ip("/api", Some("10.10.1.2")))
        .await
        .expect("ok");
    assert!(response.is_some());
    let events: Vec<Value> = agent.events.read().iter().cloned().collect();
    assert!(events.iter().any(|e| {
        e.get("cloud_provider").and_then(Value::as_str).is_some_and(|v| v == "AWS")
            || e.get("metadata")
                .and_then(|m| m.get("cloud_provider"))
                .and_then(Value::as_str)
                .is_some_and(|v| v == "AWS")
    }));
}

#[test]
fn cloud_provider_check_debug() {
    let agent = Arc::new(MockAgent::default());
    let middleware = middleware(agent, config_with_cloud(None));
    let cloud_manager = Arc::new(CloudManager::new());
    let check = CloudProviderCheck::new(middleware, empty_resolver(), cloud_manager);
    assert!(format!("{check:?}").contains("CloudProviderCheck"));
}
