use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::Value;

use guard_core_rs::error::Result;
use guard_core_rs::models::DynamicRules;
use guard_core_rs::protocols::agent::AgentHandlerProtocol;
use guard_core_rs::protocols::redis::DynRedisHandler;

#[derive(Debug, Default)]
pub(crate) struct MockAgent {
    pub events: Mutex<Vec<Value>>,
    pub metrics: Mutex<Vec<Value>>,
}

impl MockAgent {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

#[async_trait]
impl AgentHandlerProtocol for MockAgent {
    async fn initialize_redis(&self, _redis_handler: DynRedisHandler) -> Result<()> {
        Ok(())
    }

    async fn send_event(&self, event: Value) -> Result<()> {
        self.events.lock().push(event);
        Ok(())
    }

    async fn send_metric(&self, metric: Value) -> Result<()> {
        self.metrics.lock().push(metric);
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    async fn flush_buffer(&self) -> Result<()> {
        Ok(())
    }

    async fn get_dynamic_rules(&self) -> Result<Option<DynamicRules>> {
        Ok(None)
    }

    async fn health_check(&self) -> Result<bool> {
        Ok(true)
    }
}
