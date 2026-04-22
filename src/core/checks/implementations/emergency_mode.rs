use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::error::Result;
use crate::models::LogLevel;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{
    CLIENT_IP_KEY, LogType, extract_client_ip, log_activity, send_agent_event,
};

/// Enforces emergency-mode whitelist-only access when
/// [`crate::models::SecurityConfig::emergency_mode`] is active.
pub struct EmergencyModeCheck {
    middleware: DynGuardMiddleware,
}

impl std::fmt::Debug for EmergencyModeCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmergencyModeCheck").finish_non_exhaustive()
    }
}

impl EmergencyModeCheck {
    /// Creates a new check bound to the supplied middleware.
    pub const fn new(middleware: DynGuardMiddleware) -> Self {
        Self { middleware }
    }
}

#[async_trait]
impl SecurityCheck for EmergencyModeCheck {
    fn check_name(&self) -> &'static str {
        "emergency_mode"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let config = self.middleware.config();
        if !config.emergency_mode {
            return Ok(None);
        }
        let agent = self.middleware.agent_handler();
        let client_ip = match request.state().get_str(CLIENT_IP_KEY) {
            Some(ip) => ip,
            None => extract_client_ip(request, &config, agent.as_ref()).await,
        };
        let passive_mode = config.passive_mode;
        let suspicious_level = config.log_suspicious_level;
        let whitelisted = config.emergency_whitelist.iter().any(|ip| ip == &client_ip);

        if whitelisted {
            log_activity(
                request,
                LogType::Generic {
                    log_type: "info",
                    reason: &format!(
                        "[EMERGENCY MODE] Allowed access for whitelisted IP {client_ip}"
                    ),
                },
                Some(LogLevel::Info),
            )
            .await;
            return Ok(None);
        }

        let reason = format!("[EMERGENCY MODE] Access denied for IP {client_ip}");
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

        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let block_reason = format!("[EMERGENCY MODE] IP {client_ip} not in whitelist");
        let mut extra: Map<String, Value> = Map::new();
        extra.insert(
            "emergency_whitelist_count".into(),
            json!(config.emergency_whitelist.len()),
        );
        extra.insert("emergency_active".into(), json!(true));
        send_agent_event(
            agent.as_ref(),
            "emergency_mode_block",
            &client_ip,
            action_taken,
            &block_reason,
            Some(request),
            extra,
        )
        .await;

        if !passive_mode {
            return Ok(Some(
                self.middleware
                    .create_error_response(503, "Service temporarily unavailable")
                    .await?,
            ));
        }
        Ok(None)
    }
}
