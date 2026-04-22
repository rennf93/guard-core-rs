use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::routing::RouteConfigResolver;
use crate::decorators::base::RouteConfig;
use crate::error::Result;
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, extract_client_ip, log_activity, send_agent_event};

/// Enforces per-route `max_request_size` and `allowed_content_types`.
pub struct RequestSizeContentCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
}

impl std::fmt::Debug for RequestSizeContentCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSizeContentCheck").finish_non_exhaustive()
    }
}

impl RequestSizeContentCheck {
    /// Creates a new check from the shared middleware and route resolver.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
    ) -> Self {
        Self { middleware, route_resolver }
    }

    async fn check_request_size_limit(
        &self,
        request: &DynGuardRequest,
        route_config: &RouteConfig,
    ) -> Result<Option<DynGuardResponse>> {
        let Some(max_size) = route_config.max_request_size else {
            return Ok(None);
        };
        let Some(content_length) = request.header("content-length") else {
            return Ok(None);
        };
        let Ok(content_length_value) = content_length.parse::<u64>() else {
            return Ok(None);
        };
        if content_length_value <= max_size {
            return Ok(None);
        }

        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;
        let message = format!("Request size {content_length} exceeds limit");
        let log_reason = format!("{message}: {max_size}");

        log_activity(
            request,
            LogType::Suspicious {
                reason: &log_reason,
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
        extra.insert("violation_type".into(), json!("max_request_size"));
        send_agent_event(
            agent.as_ref(),
            "content_filtered",
            &client_ip,
            action_taken,
            &log_reason,
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(
                self.middleware
                    .create_error_response(413, "Request too large")
                    .await?,
            ));
        }
        Ok(None)
    }

    async fn check_content_type_allowed(
        &self,
        request: &DynGuardRequest,
        route_config: &RouteConfig,
    ) -> Result<Option<DynGuardResponse>> {
        let Some(ref allowed_content_types) = route_config.allowed_content_types else {
            return Ok(None);
        };
        let content_type_raw = request.header("content-type").unwrap_or_default();
        let content_type = content_type_raw
            .split(';')
            .next()
            .unwrap_or("")
            .to_string();
        if allowed_content_types.iter().any(|ct| ct == &content_type) {
            return Ok(None);
        }

        let config = self.middleware.config();
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;
        let log_reason = format!("Invalid content type: {content_type}");
        log_activity(
            request,
            LogType::Suspicious {
                reason: &log_reason,
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

        let message = format!("Content type {content_type} not in allowed types");
        let event_reason = format!("{message}: {allowed_content_types:?}");
        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("decorator_type".into(), json!("content_filtering"));
        extra.insert("violation_type".into(), json!("content_type"));
        send_agent_event(
            agent.as_ref(),
            "content_filtered",
            &client_ip,
            action_taken,
            &event_reason,
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(
                self.middleware
                    .create_error_response(415, "Unsupported content type")
                    .await?,
            ));
        }
        Ok(None)
    }
}

#[async_trait]
impl SecurityCheck for RequestSizeContentCheck {
    fn check_name(&self) -> &'static str {
        "request_size_content"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let Some(route_config) = self.route_resolver.get_route_config(request) else {
            return Ok(None);
        };
        if let Some(response) = self.check_request_size_limit(request, &route_config).await? {
            return Ok(Some(response));
        }
        self.check_content_type_allowed(request, &route_config).await
    }
}
