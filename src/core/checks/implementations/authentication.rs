use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::checks::helpers::validate_auth_header_for_scheme;
use crate::core::routing::RouteConfigResolver;
use crate::decorators::base::RouteConfig;
use crate::error::Result;
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, extract_client_ip, log_activity, send_agent_event};

/// Validates per-route authentication requirements (`bearer`, `basic`, ...).
///
/// See [`crate::decorators::base::RouteConfig::require_auth`].
pub struct AuthenticationCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
}

impl std::fmt::Debug for AuthenticationCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticationCheck").finish_non_exhaustive()
    }
}

impl AuthenticationCheck {
    /// Creates a new check from the shared middleware and route resolver.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
    ) -> Self {
        Self { middleware, route_resolver }
    }

    async fn handle_auth_failure(
        &self,
        request: &DynGuardRequest,
        auth_reason: &str,
        route_config: &RouteConfig,
    ) -> Result<Option<DynGuardResponse>> {
        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;

        log_activity(
            request,
            LogType::Suspicious {
                reason: &format!("Authentication failure: {auth_reason}"),
                passive_mode,
                trigger_info: "",
            },
            suspicious_level.or(Some(LogLevel::Warning)),
        )
        .await;

        let agent = self.middleware.agent_handler();
        let client_ip = match request.state().get_str(CLIENT_IP_KEY) {
            Some(ip) => ip,
            None => extract_client_ip(request, &config, agent.as_ref()).await,
        };

        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("decorator_type".into(), json!("authentication"));
        extra.insert("violation_type".into(), json!("require_auth"));
        extra.insert(
            "auth_type".into(),
            json!(route_config.auth_required.clone()),
        );
        send_agent_event(
            agent.as_ref(),
            "decorator_violation",
            &client_ip,
            action_taken,
            auth_reason,
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(
                self.middleware
                    .create_error_response(401, "Authentication required")
                    .await?,
            ));
        }
        Ok(None)
    }
}

#[async_trait]
impl SecurityCheck for AuthenticationCheck {
    fn check_name(&self) -> &'static str {
        "authentication"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let Some(route_config) = self.route_resolver.get_route_config(request) else {
            return Ok(None);
        };
        let Some(ref auth_type) = route_config.auth_required else {
            return Ok(None);
        };

        let auth_header = request.header("authorization").unwrap_or_default();
        let (is_valid, auth_reason) =
            validate_auth_header_for_scheme(&auth_header, auth_type.as_str());
        if is_valid {
            return Ok(None);
        }

        let message = if auth_reason.is_empty() {
            format!("Missing {auth_type} authentication")
        } else {
            auth_reason.to_string()
        };
        self.handle_auth_failure(request, &message, &route_config).await
    }
}
