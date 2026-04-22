use async_trait::async_trait;

use crate::core::checks::base::SecurityCheck;
use crate::error::Result;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, extract_client_ip};

/// Extracts the client IP and stashes it under
/// [`crate::utils::CLIENT_IP_KEY`] for use by downstream checks.
pub struct RouteConfigCheck {
    middleware: DynGuardMiddleware,
}

impl std::fmt::Debug for RouteConfigCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteConfigCheck").finish_non_exhaustive()
    }
}

impl RouteConfigCheck {
    /// Creates a new check bound to the supplied middleware.
    pub const fn new(middleware: DynGuardMiddleware) -> Self {
        Self { middleware }
    }
}

#[async_trait]
impl SecurityCheck for RouteConfigCheck {
    fn check_name(&self) -> &'static str {
        "route_config"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let agent = self.middleware.agent_handler();
        let client_ip = extract_client_ip(request, &self.middleware.config(), agent.as_ref()).await;
        request.state().set_str(CLIENT_IP_KEY, client_ip);
        Ok(None)
    }
}
