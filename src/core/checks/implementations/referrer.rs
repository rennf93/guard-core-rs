use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::checks::helpers::is_referrer_domain_allowed;
use crate::core::routing::RouteConfigResolver;
use crate::decorators::base::RouteConfig;
use crate::error::Result;
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, extract_client_ip, log_activity, send_agent_event};

/// Validates the `Referer` header against the allow-listed domains of the
/// matching [`crate::decorators::base::RouteConfig::require_referrer`].
pub struct ReferrerCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
}

impl std::fmt::Debug for ReferrerCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReferrerCheck").finish_non_exhaustive()
    }
}

impl ReferrerCheck {
    /// Creates a new check from the shared middleware and route resolver.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
    ) -> Self {
        Self { middleware, route_resolver }
    }

    async fn log_and_send(
        &self,
        request: &DynGuardRequest,
        log_reason: &str,
        event_reason: &str,
        extra_referrer: Option<&str>,
        route_config: &RouteConfig,
    ) {
        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;

        log_activity(
            request,
            LogType::Suspicious {
                reason: log_reason,
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
        extra.insert("violation_type".into(), json!("require_referrer"));
        extra.insert(
            "allowed_domains".into(),
            json!(route_config.require_referrer.clone()),
        );
        if let Some(ref_value) = extra_referrer {
            extra.insert("referrer".into(), json!(ref_value));
        }
        send_agent_event(
            agent.as_ref(),
            "decorator_violation",
            &client_ip,
            action_taken,
            event_reason,
            Some(request),
            extra,
        )
        .await;
    }
}

#[async_trait]
impl SecurityCheck for ReferrerCheck {
    fn check_name(&self) -> &'static str {
        "referrer"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let Some(route_config) = self.route_resolver.get_route_config(request) else {
            return Ok(None);
        };
        let Some(ref allowed_domains) = route_config.require_referrer else {
            return Ok(None);
        };
        if allowed_domains.is_empty() {
            return Ok(None);
        }

        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let referrer = request.header("referer").unwrap_or_default();

        if referrer.is_empty() {
            self.log_and_send(
                request,
                "Missing referrer header",
                "Missing referrer header",
                None,
                &route_config,
            )
            .await;
            if !passive_mode {
                return Ok(Some(
                    self.middleware
                        .create_error_response(403, "Referrer required")
                        .await?,
                ));
            }
            return Ok(None);
        }

        if !is_referrer_domain_allowed(&referrer, allowed_domains) {
            self.log_and_send(
                request,
                &format!("Invalid referrer: {referrer}"),
                &format!("Referrer '{referrer}' not in allowed domains"),
                Some(&referrer),
                &route_config,
            )
            .await;
            if !passive_mode {
                return Ok(Some(
                    self.middleware
                        .create_error_response(403, "Invalid referrer")
                        .await?,
                ));
            }
        }
        Ok(None)
    }
}
