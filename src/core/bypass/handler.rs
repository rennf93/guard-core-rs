//! Handler deciding whether a request bypasses the security pipeline.

use crate::core::bypass::context::BypassContext;
use crate::core::validation::validator::RequestValidator;
use crate::protocols::request::DynGuardRequest;

/// Combines a [`crate::core::bypass::context::BypassContext`] with a
/// [`crate::core::validation::validator::RequestValidator`] to decide whether
/// a request should be allowed through without further checks.
#[derive(Clone, Debug)]
pub struct BypassHandler {
    context: BypassContext,
    validator: RequestValidator,
}

impl BypassHandler {
    /// Builds a new handler from its context and validator.
    pub const fn new(context: BypassContext, validator: RequestValidator) -> Self {
        Self { context, validator }
    }

    /// Returns `true` when the request's path matches any entry in
    /// [`crate::models::SecurityConfig::exclude_paths`].
    pub fn handle_passthrough(&self, request: &DynGuardRequest) -> bool {
        self.validator.is_path_excluded(request)
    }

    /// Returns `true` when the request should bypass `check_name`.
    ///
    /// Currently simply delegates to
    /// [`crate::core::bypass::handler::BypassHandler::handle_passthrough`].
    pub fn handle_security_bypass(&self, request: &DynGuardRequest, check_name: &str) -> bool {
        if self.handle_passthrough(request) {
            return true;
        }
        let _ = check_name;
        let _ = &self.context;
        false
    }
}
