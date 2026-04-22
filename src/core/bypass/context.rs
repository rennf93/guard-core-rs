//! Dependency-injection context passed into the bypass handler.

use std::sync::Arc;

use crate::models::SecurityConfig;

/// Context carrying the shared [`crate::models::SecurityConfig`] used by
/// [`crate::core::bypass::handler::BypassHandler`].
#[derive(Clone, Debug)]
pub struct BypassContext {
    /// Shared security configuration.
    pub config: Arc<SecurityConfig>,
}

impl BypassContext {
    /// Creates a new context wrapping `config`.
    pub const fn new(config: Arc<SecurityConfig>) -> Self {
        Self { config }
    }
}
