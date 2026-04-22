use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::core::checks::helpers::{
    get_detection_disabled_reason, get_effective_penetration_setting,
};
use crate::core::routing::RouteConfigResolver;
use crate::decorators::base::RouteConfig;
use crate::error::Result;
use crate::handlers::ipban::IPBanManager;
use crate::handlers::suspatterns::{CTX_HEADER, CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_URL_PATH, SusPatternsManager};
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, LogType, log_activity, new_correlation_id, send_agent_event};

/// Bypass token that disables penetration detection on a route.
pub const BYPASS_CHECK_PENETRATION: &str = "penetration";
/// [`crate::protocols::request::RequestState`] key marking a whitelisted IP.
pub const IS_WHITELISTED_STATE_KEY: &str = "is_whitelisted";

/// Evaluates request content against the
/// [`crate::handlers::suspatterns::SusPatternsManager`] and triggers auto-bans
/// when thresholds are exceeded.
pub struct SuspiciousActivityCheck {
    middleware: DynGuardMiddleware,
    route_resolver: Arc<RouteConfigResolver>,
    ipban_manager: Arc<IPBanManager>,
    patterns_manager: Arc<SusPatternsManager>,
}

impl std::fmt::Debug for SuspiciousActivityCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuspiciousActivityCheck").finish_non_exhaustive()
    }
}

impl SuspiciousActivityCheck {
    /// Creates a new check from the shared middleware, route resolver,
    /// [`crate::handlers::ipban::IPBanManager`], and pattern manager.
    pub const fn new(
        middleware: DynGuardMiddleware,
        route_resolver: Arc<RouteConfigResolver>,
        ipban_manager: Arc<IPBanManager>,
        patterns_manager: Arc<SusPatternsManager>,
    ) -> Self {
        Self { middleware, route_resolver, ipban_manager, patterns_manager }
    }

    async fn detect_penetration(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
    ) -> (bool, String) {
        let correlation_id = new_correlation_id();
        let path = request.url_path();
        let (path_hit, path_trigger) = self
            .patterns_manager
            .detect_pattern_match(&path, client_ip, CTX_URL_PATH, Some(&correlation_id))
            .await;
        if path_hit {
            return (true, path_trigger.unwrap_or_default());
        }

        for (key, value) in request.query_params() {
            let combined = format!("{key}={value}");
            let (hit, trigger) = self
                .patterns_manager
                .detect_pattern_match(
                    &combined,
                    client_ip,
                    CTX_QUERY_PARAM,
                    Some(&correlation_id),
                )
                .await;
            if hit {
                return (true, trigger.unwrap_or_default());
            }
        }

        for (name, value) in request.headers() {
            if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("cookie") {
                continue;
            }
            let (hit, trigger) = self
                .patterns_manager
                .detect_pattern_match(&value, client_ip, CTX_HEADER, Some(&correlation_id))
                .await;
            if hit {
                return (true, trigger.unwrap_or_default());
            }
        }

        if let Ok(body) = request.body().await {
            if !body.is_empty()
                && let Ok(body_str) = std::str::from_utf8(&body)
            {
                let (hit, trigger) = self
                    .patterns_manager
                    .detect_pattern_match(
                        body_str,
                        client_ip,
                        CTX_REQUEST_BODY,
                        Some(&correlation_id),
                    )
                    .await;
                if hit {
                    return (true, trigger.unwrap_or_default());
                }
            }
        }

        (false, String::new())
    }

    async fn handle_suspicious_passive_mode(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
        trigger_info: &str,
    ) {
        let config = self.middleware.config();
        let suspicious_level = config.log_suspicious_level;
        log_activity(
            request,
            LogType::Suspicious {
                reason: &format!("Suspicious activity detected: {client_ip}"),
                passive_mode: true,
                trigger_info,
            },
            suspicious_level.or(Some(LogLevel::Warning)),
        )
        .await;

        let counts = self.middleware.suspicious_request_counts();
        let count = counts.get(client_ip).map(|v| *v.value()).unwrap_or(0);
        let agent = self.middleware.agent_handler();
        let message = "Suspicious pattern detected (passive mode)";
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("request_count".into(), json!(count));
        extra.insert("passive_mode".into(), json!(true));
        extra.insert("trigger_info".into(), json!(trigger_info));
        send_agent_event(
            agent.as_ref(),
            "penetration_attempt",
            client_ip,
            "logged_only",
            &format!("{message}: {trigger_info}"),
            Some(request),
            extra,
        )
        .await;
    }

    async fn handle_suspicious_active_mode(
        &self,
        request: &DynGuardRequest,
        client_ip: &str,
        trigger_info: &str,
    ) -> Result<DynGuardResponse> {
        let config = self.middleware.config();
        let suspicious_level = config.log_suspicious_level;
        let counts = self.middleware.suspicious_request_counts();
        let current_count = counts.get(client_ip).map(|v| *v.value()).unwrap_or(0);

        if config.enable_ip_banning && current_count >= config.auto_ban_threshold as u64 {
            self.ipban_manager
                .ban_ip(client_ip, config.auto_ban_duration, "penetration_attempt")
                .await?;
            log_activity(
                request,
                LogType::Suspicious {
                    reason: &format!(
                        "IP banned due to suspicious activity: {client_ip} - {trigger_info}"
                    ),
                    passive_mode: false,
                    trigger_info: "",
                },
                suspicious_level.or(Some(LogLevel::Warning)),
            )
            .await;
            return self.middleware.create_error_response(403, "IP has been banned").await;
        }

        log_activity(
            request,
            LogType::Suspicious {
                reason: &format!(
                    "Suspicious activity detected for IP: {client_ip} - {trigger_info}"
                ),
                passive_mode: false,
                trigger_info: "",
            },
            suspicious_level.or(Some(LogLevel::Warning)),
        )
        .await;

        let agent = self.middleware.agent_handler();
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("request_count".into(), json!(current_count));
        extra.insert("trigger_info".into(), json!(trigger_info));
        send_agent_event(
            agent.as_ref(),
            "penetration_attempt",
            client_ip,
            "request_blocked",
            &format!("Penetration attempt detected: {trigger_info}"),
            Some(request),
            extra,
        )
        .await;

        self.middleware
            .create_error_response(400, "Suspicious activity detected")
            .await
    }
}

#[async_trait]
impl SecurityCheck for SuspiciousActivityCheck {
    fn check_name(&self) -> &'static str {
        "suspicious_activity"
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
        let config = self.middleware.config();
        let (penetration_enabled, route_specific) =
            get_effective_penetration_setting(&config, route_config.as_ref());

        let bypass_penetration = route_config
            .as_ref()
            .map(|rc: &RouteConfig| {
                rc.bypassed_checks
                    .iter()
                    .any(|c| c == BYPASS_CHECK_PENETRATION)
            })
            .unwrap_or(false);

        let (detection_result, trigger_info) = if penetration_enabled && !bypass_penetration {
            self.detect_penetration(request, &client_ip).await
        } else {
            (
                false,
                get_detection_disabled_reason(&config, route_specific).to_string(),
            )
        };

        if trigger_info == "disabled_by_decorator" {
            let agent = self.middleware.agent_handler();
            let mut extra: Map<String, Value> = Map::new();
            extra.insert("decorator_type".into(), json!("advanced"));
            extra.insert(
                "violation_type".into(),
                json!("suspicious_detection_disabled"),
            );
            send_agent_event(
                agent.as_ref(),
                "decorator_violation",
                &client_ip,
                "detection_disabled",
                "Suspicious pattern detection disabled by route decorator",
                Some(request),
                extra,
            )
            .await;
            return Ok(None);
        }

        if !detection_result {
            return Ok(None);
        }

        let counts = self.middleware.suspicious_request_counts();
        let mut entry = counts.entry(client_ip.clone()).or_insert(0);
        *entry += 1;
        drop(entry);

        if config.passive_mode {
            self.handle_suspicious_passive_mode(request, &client_ip, &trigger_info).await;
            return Ok(None);
        }

        Ok(Some(
            self.handle_suspicious_active_mode(request, &client_ip, &trigger_info)
                .await?,
        ))
    }
}
