#![cfg(feature = "cloud-providers")]

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::routing::RouteConfigResolver;
use crate::error::Result;
use crate::handlers::cloud::CloudManager;
use crate::models::{CloudProvider, LogLevel};
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, log_activity, send_agent_event};

/// Bypass token that disables the cloud-provider check on a route.
pub const BYPASS_CHECK_CLOUDS: &str = "clouds";
/// [`crate::protocols::request::RequestState`] key marking a whitelisted IP.
pub const IS_WHITELISTED_STATE_KEY: &str = "is_whitelisted";

/// Blocks requests originating from configured cloud-provider IP ranges.
pub struct CloudProviderCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
    cloud_manager: Arc<CloudManager>,
}

impl std::fmt::Debug for CloudProviderCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudProviderCheck").finish_non_exhaustive()
    }
}

impl CloudProviderCheck {
    /// Creates a new check from the shared middleware, route resolver, and
    /// [`crate::handlers::cloud::CloudManager`].
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
        cloud_manager: Arc<CloudManager>,
    ) -> Self {
        Self { middleware, route_resolver, cloud_manager }
    }
}

#[async_trait]
impl SecurityCheck for CloudProviderCheck {
    fn check_name(&self) -> &'static str {
        "cloud_provider"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        if request.state().get_bool(IS_WHITELISTED_STATE_KEY).unwrap_or(false) {
            return Ok(None);
        }
        let Some(client_ip) = request.state().get_str(CLIENT_IP_KEY) else {
            return Ok(None);
        };

        let route_config = self.route_resolver.get_route_config(request);
        if let Some(ref rc) = route_config
            && rc.bypassed_checks.iter().any(|c| c == BYPASS_CHECK_CLOUDS)
        {
            return Ok(None);
        }

        let providers_to_check = resolve_providers_to_check(&self.middleware, route_config.as_ref());
        let Some(providers_to_check) = providers_to_check else {
            return Ok(None);
        };
        if providers_to_check.is_empty() {
            return Ok(None);
        }

        if !self.cloud_manager.is_cloud_ip(&client_ip, &providers_to_check).await {
            return Ok(None);
        }

        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;

        log_activity(
            request,
            LogType::Suspicious {
                reason: &format!("Blocked cloud provider IP: {client_ip}"),
                passive_mode,
                trigger_info: "",
            },
            suspicious_level.or(Some(LogLevel::Warning)),
        )
        .await;

        let details = self
            .cloud_manager
            .get_cloud_provider_details(&client_ip, &providers_to_check)
            .await;
        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let agent = self.middleware.agent_handler();
        let provider_name = details
            .as_ref()
            .map(|(p, _)| p.as_str())
            .unwrap_or("unknown");
        let network = details.as_ref().map(|(_, n)| n.clone()).unwrap_or_default();

        let mut extra: Map<String, Value> = Map::new();
        extra.insert("cloud_provider".into(), json!(provider_name));
        extra.insert("network".into(), json!(network));
        let reason = format!("IP belongs to blocked cloud provider: {provider_name}");
        send_agent_event(
            agent.as_ref(),
            "cloud_blocked",
            &client_ip,
            action_taken,
            &reason,
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(
                self.middleware
                    .create_error_response(403, "Cloud provider IP not allowed")
                    .await?,
            ));
        }
        Ok(None)
    }
}

fn resolve_providers_to_check(
    middleware: &DynGuardMiddleware,
    route_config: Option<&crate::decorators::base::RouteConfig>,
) -> Option<HashSet<CloudProvider>> {
    if let Some(rc) = route_config
        && let Some(ref providers) = rc.block_cloud_providers
    {
        return Some(providers.clone());
    }
    middleware.config().block_cloud_providers.clone()
}
