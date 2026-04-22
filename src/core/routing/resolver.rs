//! Resolver mapping incoming requests to their
//! [`crate::decorators::RouteConfig`].

use std::collections::HashSet;
use std::sync::Arc;

use crate::core::routing::context::RoutingContext;
use crate::decorators::RouteConfig;
use crate::models::CloudProvider;
use crate::protocols::request::DynGuardRequest;

/// Registry of per-path [`crate::decorators::RouteConfig`] entries and
/// resolver of route-level overrides.
#[derive(Clone, Debug)]
pub struct RouteConfigResolver {
    context: RoutingContext,
    route_registry: Arc<dashmap::DashMap<String, RouteConfig>>,
}

impl RouteConfigResolver {
    /// Creates a fresh resolver with an empty registry.
    pub fn new(context: RoutingContext) -> Self {
        Self { context, route_registry: Arc::new(dashmap::DashMap::new()) }
    }

    /// Returns the shared
    /// [`crate::core::routing::context::RoutingContext`].
    pub const fn context(&self) -> &RoutingContext {
        &self.context
    }

    /// Registers `route_config` under the supplied path.
    pub fn register(&self, path: impl Into<String>, route_config: RouteConfig) {
        self.route_registry.insert(path.into(), route_config);
    }

    /// Returns the [`crate::decorators::RouteConfig`] matching the request's
    /// path, if any.
    pub fn get_route_config(&self, request: &DynGuardRequest) -> Option<RouteConfig> {
        self.route_registry
            .get(&request.url_path())
            .map(|entry| entry.value().clone())
    }

    /// Returns `true` when the route's bypass list contains `check_name`.
    pub fn should_bypass_check(&self, request: &DynGuardRequest, check_name: &str) -> bool {
        self.get_route_config(request)
            .map(|rc| rc.bypassed_checks.iter().any(|c| c == check_name))
            .unwrap_or(false)
    }

    /// Returns the set of [`crate::models::CloudProvider`] values to check
    /// for `request`, merging route-level overrides with the global list.
    pub fn get_cloud_providers_to_check(
        &self,
        request: &DynGuardRequest,
    ) -> Option<HashSet<CloudProvider>> {
        self.get_route_config(request)
            .and_then(|rc| rc.block_cloud_providers)
            .or_else(|| self.context.config.block_cloud_providers.clone())
    }
}
