#[path = "support/request.rs"]
mod mock_request;

use std::collections::HashSet;
use std::sync::Arc;

use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::models::{CloudProvider, SecurityConfig};
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_request::MockRequest;

fn default_config() -> Arc<SecurityConfig> {
    Arc::new(SecurityConfig::builder().build().expect("valid"))
}

fn config_with_cloud_providers(set: HashSet<CloudProvider>) -> Arc<SecurityConfig> {
    let config = SecurityConfig::builder()
        .block_cloud_providers(Some(set))
        .build()
        .expect("valid");
    Arc::new(config)
}

fn request_at(path: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().path(path).build())
}

#[test]
fn routing_context_stores_config() {
    let config = default_config();
    let context = RoutingContext::new(Arc::clone(&config));
    assert!(Arc::ptr_eq(&context.config, &config));
}

#[test]
fn routing_context_debug_contains_type() {
    let context = RoutingContext::new(default_config());
    assert!(format!("{context:?}").contains("RoutingContext"));
}

#[test]
fn resolver_has_empty_registry_initially() {
    let resolver = RouteConfigResolver::new(RoutingContext::new(default_config()));
    let request = request_at("/anything");
    assert!(resolver.get_route_config(&request).is_none());
}

#[test]
fn resolver_register_and_get_route_config() {
    let resolver = RouteConfigResolver::new(RoutingContext::new(default_config()));
    let route_config = RouteConfig::new().rate_limit(5, 60);
    resolver.register("/limited", route_config);
    let request = request_at("/limited");
    let resolved = resolver.get_route_config(&request).expect("route present");
    assert_eq!(resolved.rate_limit, Some(5));
    assert_eq!(resolved.rate_limit_window, Some(60));
}

#[test]
fn resolver_should_bypass_check_returns_true_for_registered_bypass() {
    let resolver = RouteConfigResolver::new(RoutingContext::new(default_config()));
    let route_config = RouteConfig::new().bypass(vec!["rate_limit".into()]);
    resolver.register("/bypass", route_config);
    let request = request_at("/bypass");
    assert!(resolver.should_bypass_check(&request, "rate_limit"));
    assert!(!resolver.should_bypass_check(&request, "ip"));
}

#[test]
fn resolver_should_bypass_check_returns_false_when_no_route() {
    let resolver = RouteConfigResolver::new(RoutingContext::new(default_config()));
    let request = request_at("/absent");
    assert!(!resolver.should_bypass_check(&request, "rate_limit"));
}

#[test]
fn resolver_get_cloud_providers_from_route() {
    let resolver = RouteConfigResolver::new(RoutingContext::new(default_config()));
    let mut providers = HashSet::new();
    providers.insert(CloudProvider::Aws);
    let route_config = RouteConfig::new().block_clouds(Some(vec![CloudProvider::Aws]));
    resolver.register("/aws", route_config);
    let request = request_at("/aws");
    let resolved = resolver
        .get_cloud_providers_to_check(&request)
        .expect("present");
    assert!(resolved.contains(&CloudProvider::Aws));
}

#[test]
fn resolver_get_cloud_providers_falls_back_to_config() {
    let mut providers = HashSet::new();
    providers.insert(CloudProvider::Gcp);
    let resolver = RouteConfigResolver::new(RoutingContext::new(config_with_cloud_providers(
        providers.clone(),
    )));
    let request = request_at("/no-route");
    let resolved = resolver
        .get_cloud_providers_to_check(&request)
        .expect("fallback config");
    assert!(resolved.contains(&CloudProvider::Gcp));
}

#[test]
fn resolver_get_cloud_providers_returns_none_when_neither_present() {
    let resolver = RouteConfigResolver::new(RoutingContext::new(default_config()));
    let request = request_at("/plain");
    assert!(resolver.get_cloud_providers_to_check(&request).is_none());
}

#[test]
fn resolver_context_accessor_returns_reference() {
    let context = RoutingContext::new(default_config());
    let resolver = RouteConfigResolver::new(context.clone());
    assert!(Arc::ptr_eq(&resolver.context().config, &context.config));
}

#[test]
fn resolver_clone_and_debug() {
    let resolver = RouteConfigResolver::new(RoutingContext::new(default_config()));
    let cloned = resolver.clone();
    assert!(format!("{cloned:?}").contains("RouteConfigResolver"));
}
