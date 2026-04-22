//! Dependency-injection context passed into the behavioural processor.

use std::sync::Arc;

use crate::models::SecurityConfig;

/// Context carrying the shared [`crate::models::SecurityConfig`] used by the
/// behavioural processor.
#[derive(Clone, Debug)]
pub struct BehavioralContext {
    /// Shared security configuration.
    pub config: Arc<SecurityConfig>,
}

impl BehavioralContext {
    /// Creates a new context wrapping `config`.
    pub const fn new(config: Arc<SecurityConfig>) -> Self {
        Self { config }
    }
}
