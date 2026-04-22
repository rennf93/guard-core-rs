use async_trait::async_trait;
use parking_lot::RwLock;
use serde_json::Value;

use guard_core_rs::error::{GuardCoreError, Result};
use guard_core_rs::models::DynamicRules;
use guard_core_rs::protocols::agent::AgentHandlerProtocol;
use guard_core_rs::protocols::redis::DynRedisHandler;

#[derive(Default)]
pub(crate) struct MockAgent {
    pub(crate) events: RwLock<Vec<Value>>,
    pub(crate) metrics: RwLock<Vec<Value>>,
    pub(crate) started: RwLock<bool>,
    pub(crate) stopped: RwLock<bool>,
    pub(crate) flushed: RwLock<u32>,
    pub(crate) dynamic_rules: RwLock<Option<DynamicRules>>,
    pub(crate) fail_events: RwLock<bool>,
    pub(crate) fail_rules: RwLock<bool>,
    pub(crate) fail_health: RwLock<bool>,
}

impl std::fmt::Debug for MockAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockAgent")
            .field("events", &self.events.read().len())
            .finish()
    }
}

#[async_trait]
impl AgentHandlerProtocol for MockAgent {
    async fn initialize_redis(&self, _handler: DynRedisHandler) -> Result<()> {
        Ok(())
    }

    async fn send_event(&self, event: Value) -> Result<()> {
        if *self.fail_events.read() {
            return Err(GuardCoreError::Agent("mock send_event failure".into()));
        }
        self.events.write().push(event);
        Ok(())
    }

    async fn send_metric(&self, metric: Value) -> Result<()> {
        self.metrics.write().push(metric);
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        *self.started.write() = true;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        *self.stopped.write() = true;
        Ok(())
    }

    async fn flush_buffer(&self) -> Result<()> {
        *self.flushed.write() += 1;
        Ok(())
    }

    async fn get_dynamic_rules(&self) -> Result<Option<DynamicRules>> {
        if *self.fail_rules.read() {
            return Err(GuardCoreError::Agent("mock get rules failure".into()));
        }
        Ok(self.dynamic_rules.read().clone())
    }

    async fn health_check(&self) -> Result<bool> {
        if *self.fail_health.read() {
            return Err(GuardCoreError::Agent("mock health failure".into()));
        }
        Ok(true)
    }
}
