//! Dependency-injection context passed into the error-response factory.

use std::sync::Arc;

use crate::models::SecurityConfig;
use crate::protocols::response::DynGuardResponseFactory;

/// Bundle holding the [`crate::models::SecurityConfig`] and the
/// [`crate::protocols::response::DynGuardResponseFactory`] consumed by
/// [`crate::core::responses::factory::ErrorResponseFactory`].
#[derive(Clone)]
pub struct ResponseContext {
    /// Shared security configuration.
    pub config: Arc<SecurityConfig>,
    /// Response factory supplied by the framework adapter.
    pub response_factory: DynGuardResponseFactory,
}

impl std::fmt::Debug for ResponseContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseContext").finish_non_exhaustive()
    }
}

impl ResponseContext {
    /// Creates a new context wrapping `config` and `response_factory`.
    pub const fn new(config: Arc<SecurityConfig>, response_factory: DynGuardResponseFactory) -> Self {
        Self { config, response_factory }
    }
}
