//! Event bus that fans security events out to the Guard Agent.

use serde_json::{Map, Value, json};

use crate::protocols::agent::DynAgentHandler;
use crate::protocols::request::DynGuardRequest;
use crate::utils::{get_pipeline_response_time, send_agent_event};

/// Wraps the optional [`crate::protocols::agent::DynAgentHandler`] and
/// dispatches security events with a consistent envelope shape.
#[derive(Clone, Debug)]
pub struct SecurityEventBus {
    agent_handler: Option<DynAgentHandler>,
}

impl SecurityEventBus {
    /// Creates a bus bound to the optional agent handler.
    pub const fn new(agent_handler: Option<DynAgentHandler>) -> Self {
        Self { agent_handler }
    }

    /// Returns a reference to the stored handler, if any.
    pub fn agent_handler(&self) -> Option<&DynAgentHandler> {
        self.agent_handler.as_ref()
    }

    /// Forwards a structured middleware event through
    /// [`crate::utils::send_agent_event`].
    pub async fn send_middleware_event(
        &self,
        event_type: &str,
        ip_address: &str,
        action_taken: &str,
        reason: &str,
        request: Option<&DynGuardRequest>,
        extra: Map<String, Value>,
    ) {
        send_agent_event(
            self.agent_handler.as_ref(),
            event_type,
            ip_address,
            action_taken,
            reason,
            request,
            extra,
        )
        .await;
    }

    /// Convenience wrapper that emits an HTTPS-violation event.
    pub async fn send_https_violation_event(
        &self,
        ip_address: &str,
        request: Option<&DynGuardRequest>,
    ) {
        let mut extra = Map::new();
        extra.insert("violation".into(), json!("https_required"));
        extra.insert(
            "response_time".into(),
            json!(get_pipeline_response_time(request)),
        );
        self.send_middleware_event(
            "security_violation",
            ip_address,
            "redirect",
            "HTTPS required",
            request,
            extra,
        )
        .await;
    }
}
