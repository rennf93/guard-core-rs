use async_trait::async_trait;

use crate::core::checks::base::SecurityCheck;
use crate::error::Result;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{LogType, log_activity};

/// Emits a request log at
/// [`crate::models::SecurityConfig::log_request_level`] without ever
/// short-circuiting the pipeline.
pub struct RequestLoggingCheck {
    middleware: DynGuardMiddleware,
}

impl std::fmt::Debug for RequestLoggingCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestLoggingCheck").finish_non_exhaustive()
    }
}

impl RequestLoggingCheck {
    /// Creates a new check bound to the supplied middleware.
    pub const fn new(middleware: DynGuardMiddleware) -> Self {
        Self { middleware }
    }
}

#[async_trait]
impl SecurityCheck for RequestLoggingCheck {
    fn check_name(&self) -> &'static str {
        "request_logging"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let level = self.middleware.config().log_request_level;
        log_activity(request, LogType::Request, level).await;
        Ok(None)
    }
}
