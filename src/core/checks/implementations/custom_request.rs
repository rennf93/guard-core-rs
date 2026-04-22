use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::core::checks::base::SecurityCheck;
use crate::error::Result;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;
use crate::utils::{CLIENT_IP_KEY, extract_client_ip, send_agent_event};

/// Invokes the user-supplied
/// [`crate::models::SecurityConfig::custom_request_check`] callback before
/// standard checks run.
pub struct CustomRequestCheck {
    middleware: DynGuardMiddleware,
}

impl std::fmt::Debug for CustomRequestCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomRequestCheck").finish_non_exhaustive()
    }
}

impl CustomRequestCheck {
    /// Creates a new check bound to the supplied middleware.
    pub const fn new(middleware: DynGuardMiddleware) -> Self {
        Self { middleware }
    }
}

#[async_trait]
impl SecurityCheck for CustomRequestCheck {
    fn check_name(&self) -> &'static str {
        "custom_request"
    }

    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }

    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        let config = self.middleware.config();
        let Some(custom_check) = config.custom_request_check.as_ref() else {
            return Ok(None);
        };

        let request_clone = request.clone();
        let custom_response = (custom_check.0)(request_clone).await;
        let Some(custom_response) = custom_response else {
            return Ok(None);
        };

        let passive_mode = config.passive_mode;
        let agent = self.middleware.agent_handler();
        let client_ip = match request.state().get_str(CLIENT_IP_KEY) {
            Some(ip) => ip,
            None => extract_client_ip(request, &config, agent.as_ref()).await,
        };
        let status_code = custom_response.status_code();
        let action_taken = if passive_mode { "logged_only" } else { "request_blocked" };
        let mut extra: Map<String, Value> = Map::new();
        extra.insert("response_status".into(), json!(status_code));
        extra.insert("check_function".into(), json!("custom"));
        send_agent_event(
            agent.as_ref(),
            "custom_request_check",
            &client_ip,
            action_taken,
            "Custom request check returned blocking response",
            Some(request),
            extra,
        )
        .await;

        if passive_mode {
            return Ok(None);
        }

        if let Some(modifier) = config.custom_response_modifier.as_ref() {
            let modified = (modifier.0)(custom_response.clone()).await;
            return Ok(Some(modified));
        }
        Ok(Some(custom_response))
    }
}
