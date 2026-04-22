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

/// Rejects requests missing any required header declared on the route.
pub struct RequiredHeadersCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
}

impl std::fmt::Debug for RequiredHeadersCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequiredHeadersCheck").finish_non_exhaustive()
    }
}

impl RequiredHeadersCheck {
    /// Creates a new check from the shared middleware and route resolver.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
    ) -> Self {
        Self { middleware, route_resolver }
    }

    async fn handle_missing_header(
        &self,
        request: &DynGuardRequest,
        header: &str,
    ) -> Result<Option<DynGuardResponse>> {
        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;
        let reason = format!("Missing required header: {header}");

        log_activity(
            request,
            LogType::Suspicious {
                reason: &reason,
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

        let (decorator_type, violation_type) = classify_header_violation(header);
        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("decorator_type".into(), json!(decorator_type));
        extra.insert("violation_type".into(), json!(violation_type));
        extra.insert("missing_header".into(), json!(header));
        send_agent_event(
            agent.as_ref(),
            "decorator_violation",
            &client_ip,
            action_taken,
            &reason,
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(self.middleware.create_error_response(400, &reason).await?));
        }
        Ok(None)
    }
}

#[async_trait]
impl SecurityCheck for RequiredHeadersCheck {
    fn check_name(&self) -> &'static str {
        "required_headers"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let Some(route_config) = self.route_resolver.get_route_config(request) else {
            return Ok(None);
        };
        if route_config.required_headers.is_empty() {
            return Ok(None);
        }
        for (header, expected) in &route_config.required_headers {
            if expected == "required" && request.header(header).unwrap_or_default().is_empty() {
                return self.handle_missing_header(request, header).await;
            }
        }
        Ok(None)
    }
}

fn classify_header_violation(header_name: &str) -> (&'static str, &'static str) {
    let lower = header_name.to_ascii_lowercase();
    match lower.as_str() {
        "x-api-key" => ("authentication", "api_key_required"),
        "authorization" => ("authentication", "required_header"),
        _ => ("advanced", "required_header"),
    }
}
