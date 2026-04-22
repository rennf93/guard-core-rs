#[path = "support/request.rs"]
mod mock_request;

#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::sync::Arc;

use serde_json::{Map, Value, json};

use guard_core_rs::core::events::metrics::MetricsCollector;
use guard_core_rs::core::events::middleware_events::SecurityEventBus;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use mock_agent::MockAgent;
use mock_request::MockRequest;

fn request() -> DynGuardRequest {
    Arc::new(
        MockRequest::builder()
            .method("POST")
            .path("/api/data")
            .build(),
    )
}

fn agent_handler(agent: Arc<MockAgent>) -> DynAgentHandler {
    agent as Arc<dyn AgentHandlerProtocol>
}

#[test]
fn event_bus_without_agent_clones() {
    let bus = SecurityEventBus::new(None);
    let cloned = bus.clone();
    assert!(cloned.agent_handler().is_none());
    assert!(format!("{bus:?}").contains("SecurityEventBus"));
}

#[test]
fn event_bus_with_agent_exposes_handler() {
    let agent = Arc::new(MockAgent::default());
    let bus = SecurityEventBus::new(Some(agent_handler(agent)));
    assert!(bus.agent_handler().is_some());
}

#[tokio::test]
async fn send_middleware_event_forwards_to_agent() {
    let agent = Arc::new(MockAgent::default());
    let bus = SecurityEventBus::new(Some(agent_handler(Arc::clone(&agent))));
    let mut extra = Map::new();
    extra.insert("reason".into(), json!("testing"));
    bus.send_middleware_event(
        "custom_event",
        "127.0.0.1",
        "logged_only",
        "unit test",
        Some(&request()),
        extra,
    )
    .await;
    let events = agent.events.read();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], Value::String("custom_event".into()));
    assert_eq!(events[0]["reason"], Value::String("testing".into()));
}

#[tokio::test]
async fn send_middleware_event_without_agent_is_noop() {
    let bus = SecurityEventBus::new(None);
    bus.send_middleware_event(
        "ignored",
        "127.0.0.1",
        "logged",
        "no agent",
        None,
        Map::new(),
    )
    .await;
}

#[tokio::test]
async fn send_https_violation_event_emits_expected_fields() {
    let agent = Arc::new(MockAgent::default());
    let bus = SecurityEventBus::new(Some(agent_handler(Arc::clone(&agent))));
    bus.send_https_violation_event("10.0.0.1", Some(&request()))
        .await;
    let events = agent.events.read();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action_taken"], Value::String("redirect".into()));
    assert_eq!(events[0]["violation"], Value::String("https_required".into()));
}

#[tokio::test]
async fn send_https_violation_event_when_send_fails_does_not_panic() {
    let agent = Arc::new(MockAgent::default());
    *agent.fail_events.write() = true;
    let bus = SecurityEventBus::new(Some(agent_handler(Arc::clone(&agent))));
    bus.send_https_violation_event("10.0.0.1", None).await;
    assert!(agent.events.read().is_empty());
}

#[tokio::test]
async fn metrics_collector_without_agent_is_noop() {
    let collector = MetricsCollector::new(None);
    collector
        .collect_request_metrics(&request(), 200, "allowed")
        .await;
    assert!(format!("{collector:?}").contains("MetricsCollector"));
}

#[tokio::test]
async fn metrics_collector_with_agent_records_metric() {
    let agent = Arc::new(MockAgent::default());
    let collector = MetricsCollector::new(Some(agent_handler(Arc::clone(&agent))));
    collector
        .collect_request_metrics(&request(), 403, "request_blocked")
        .await;
    let metrics = agent.metrics.read();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0]["endpoint"], Value::String("/api/data".into()));
    assert_eq!(metrics[0]["status_code"], Value::Number(403.into()));
    assert_eq!(
        metrics[0]["action_taken"],
        Value::String("request_blocked".into())
    );
    assert!(metrics[0]["response_time"].is_number());
}
