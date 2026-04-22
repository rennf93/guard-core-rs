use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::routing::RouteConfigResolver;
use crate::error::Result;
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, extract_client_ip, log_activity, send_agent_event};

/// Runs every user-registered
/// [`crate::decorators::base::CustomValidator`] attached to the route.
pub struct CustomValidatorsCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
}

impl std::fmt::Debug for CustomValidatorsCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomValidatorsCheck").finish_non_exhaustive()
    }
}

impl CustomValidatorsCheck {
    /// Creates a new check from the shared middleware and route resolver.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
    ) -> Self {
        Self { middleware, route_resolver }
    }
}

#[async_trait]
impl SecurityCheck for CustomValidatorsCheck {
    fn check_name(&self) -> &'static str {
        "custom_validators"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let Some(route_config) = self.route_resolver.get_route_config(request) else {
            return Ok(None);
        };
        if route_config.custom_validators.is_empty() {
            return Ok(None);
        }

        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;

        for validator in &route_config.custom_validators {
            let request_clone = request.clone();
            let validator_fn = Arc::clone(validator);
            let validation_response = validator_fn(request_clone).await;
            let Some(validation_response) = validation_response else {
                continue;
            };

            log_activity(
                request,
                LogType::Suspicious {
                    reason: "Custom validation failed",
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
            extra.insert("decorator_type".into(), json!("content_filtering"));
            extra.insert("violation_type".into(), json!("custom_validation"));
            extra.insert("validator_name".into(), json!("anonymous"));
            send_agent_event(
                agent.as_ref(),
                "decorator_violation",
                &client_ip,
                action_taken,
                "Custom validation failed",
                Some(request),
                extra,
            )
            .await;

            if !passive_mode {
                return Ok(Some(validation_response));
            }
        }
        Ok(None)
    }
}
