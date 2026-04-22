use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::checks::helpers::check_user_agent_allowed;
use crate::core::routing::RouteConfigResolver;
use crate::error::Result;
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, extract_client_ip, log_activity, send_agent_event};

/// [`crate::protocols::request::RequestState`] key marking a whitelisted IP.
pub const IS_WHITELISTED_STATE_KEY: &str = "is_whitelisted";

/// Rejects requests whose `User-Agent` matches any configured block pattern.
pub struct UserAgentCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
}

impl std::fmt::Debug for UserAgentCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserAgentCheck").finish_non_exhaustive()
    }
}

impl UserAgentCheck {
    /// Creates a new check from the shared middleware and route resolver.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
    ) -> Self {
        Self { middleware, route_resolver }
    }
}

#[async_trait]
impl SecurityCheck for UserAgentCheck {
    fn check_name(&self) -> &'static str {
        "user_agent"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        if request.state().get_bool(IS_WHITELISTED_STATE_KEY).unwrap_or(false) {
            return Ok(None);
        }
        let route_config = self.route_resolver.get_route_config(request);
        let user_agent = request.header("User-Agent").unwrap_or_default();
        let config = self.middleware.config();

        if check_user_agent_allowed(&user_agent, route_config.as_ref(), &config) {
            return Ok(None);
        }

        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;

        log_activity(
            request,
            LogType::Suspicious {
                reason: &format!("Blocked user agent: {user_agent}"),
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

        let route_specific_block = route_config
            .as_ref()
            .map(|rc| !rc.blocked_user_agents.is_empty())
            .unwrap_or(false);

        if route_specific_block {
            let mut extra: Map<String, Value> = Map::new();
            extra.insert("decorator_type".into(), json!("access_control"));
            extra.insert("violation_type".into(), json!("user_agent"));
            extra.insert("blocked_user_agent".into(), json!(user_agent));
            send_agent_event(
                agent.as_ref(),
                "decorator_violation",
                &client_ip,
                action_taken,
                &format!("User agent '{user_agent}' blocked"),
                Some(request),
                extra,
            )
            .await;
        } else {
            let mut extra: Map<String, Value> = Map::new();
            extra.insert("user_agent".into(), json!(user_agent));
            extra.insert("filter_type".into(), json!("global"));
            send_agent_event(
                agent.as_ref(),
                "user_agent_blocked",
                &client_ip,
                action_taken,
                &format!("User agent '{user_agent}' in global blocklist"),
                Some(request),
                extra,
            )
            .await;
        }

        if !passive_mode {
            return Ok(Some(
                self.middleware
                    .create_error_response(403, "User-Agent not allowed")
                    .await?,
            ));
        }
        Ok(None)
    }
}
