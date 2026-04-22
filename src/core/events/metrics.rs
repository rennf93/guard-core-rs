//! Metrics collector forwarding per-request counters to the Guard Agent.

use serde_json::{Map, Value, json};

use crate::protocols::agent::DynAgentHandler;
use crate::protocols::request::DynGuardRequest;
use crate::utils::get_pipeline_response_time;

/// Accumulates per-request metrics and forwards them through the optional
/// Guard Agent handler.
#[derive(Clone, Debug)]
pub struct MetricsCollector {
    agent_handler: Option<DynAgentHandler>,
}

impl MetricsCollector {
    /// Creates a collector bound to the optional agent handler.
    pub const fn new(agent_handler: Option<DynAgentHandler>) -> Self {
        Self { agent_handler }
    }

    /// Emits a metric describing the outcome of the current request.
    pub async fn collect_request_metrics(
        &self,
        request: &DynGuardRequest,
        status_code: u16,
        action_taken: &str,
    ) {
        let Some(agent) = &self.agent_handler else { return };
        let mut metric = Map::new();
        metric.insert("endpoint".into(), json!(request.url_path()));
        metric.insert("method".into(), json!(request.method()));
        metric.insert("status_code".into(), json!(status_code));
        metric.insert("action_taken".into(), json!(action_taken));
        metric.insert(
            "response_time".into(),
            json!(get_pipeline_response_time(Some(request))),
        );
        let _ = agent.send_metric(Value::Object(metric)).await;
    }
}
