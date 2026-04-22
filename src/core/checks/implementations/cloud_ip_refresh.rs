use async_trait::async_trait;

use crate::core::checks::base::SecurityCheck;
use crate::error::Result;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;

/// Refreshes the cached cloud provider IP ranges when the configured
/// [`crate::models::SecurityConfig::cloud_ip_refresh_interval`] has elapsed.
pub struct CloudIpRefreshCheck {
    middleware: DynGuardMiddleware,
}

impl std::fmt::Debug for CloudIpRefreshCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudIpRefreshCheck").finish_non_exhaustive()
    }
}

impl CloudIpRefreshCheck {
    /// Creates a new check bound to the supplied middleware.
    pub const fn new(middleware: DynGuardMiddleware) -> Self {
        Self { middleware }
    }
}

#[async_trait]
impl SecurityCheck for CloudIpRefreshCheck {
    fn check_name(&self) -> &'static str {
        "cloud_ip_refresh"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, _request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let config = self.middleware.config();
        if config.block_cloud_providers.is_none() {
            return Ok(None);
        }
        let now = epoch_secs() as i64;
        let last = self.middleware.last_cloud_ip_refresh();
        if now - last > config.cloud_ip_refresh_interval as i64 {
            self.middleware.refresh_cloud_ip_ranges().await?;
        }
        Ok(None)
    }
}

fn epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
