//! Dependency-injection context passed into the route-config resolver.

use std::sync::Arc;

use crate::models::SecurityConfig;

/// Bundle holding the shared [`crate::models::SecurityConfig`] used by
/// [`crate::core::routing::resolver::RouteConfigResolver`].
#[derive(Clone, Debug)]
pub struct RoutingContext {
    /// Shared security configuration.
    pub config: Arc<SecurityConfig>,
}

impl RoutingContext {
    /// Creates a new context wrapping `config`.
    pub const fn new(config: Arc<SecurityConfig>) -> Self {
        Self { config }
    }
}
