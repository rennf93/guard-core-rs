//! Dependency-injection context passed into the request validator.

use std::sync::Arc;

use crate::models::SecurityConfig;

/// Bundle holding the shared [`crate::models::SecurityConfig`] used by
/// [`crate::core::validation::validator::RequestValidator`].
#[derive(Clone, Debug)]
pub struct ValidationContext {
    /// Shared security configuration.
    pub config: Arc<SecurityConfig>,
}

impl ValidationContext {
    /// Creates a new context wrapping `config`.
    pub const fn new(config: Arc<SecurityConfig>) -> Self {
        Self { config }
    }
}
