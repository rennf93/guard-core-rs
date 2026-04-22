use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use guard_core_rs::error::Result;
use guard_core_rs::protocols::agent::DynAgentHandler;
use guard_core_rs::protocols::geo_ip::{DynGeoIpHandler, GeoIpHandler};
use guard_core_rs::protocols::redis::DynRedisHandler;

#[derive(Default)]
pub(crate) struct MockGeoIpHandler {
    pub(crate) initialized: RwLock<bool>,
    pub(crate) countries: RwLock<HashMap<String, String>>,
    pub(crate) redis_calls: RwLock<u32>,
    pub(crate) agent_calls: RwLock<u32>,
}

impl std::fmt::Debug for MockGeoIpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockGeoIpHandler").finish()
    }
}

impl MockGeoIpHandler {
    pub(crate) fn with_mapping(mappings: &[(&str, &str)]) -> Arc<Self> {
        let handler = Self::default();
        *handler.initialized.write() = true;
        for (ip, country) in mappings {
            handler
                .countries
                .write()
                .insert((*ip).to_string(), (*country).to_string());
        }
        Arc::new(handler)
    }

    pub(crate) fn dyn_handler(self: Arc<Self>) -> DynGeoIpHandler {
        self
    }
}

#[async_trait]
impl GeoIpHandler for MockGeoIpHandler {
    fn is_initialized(&self) -> bool {
        *self.initialized.read()
    }

    async fn initialize(&self) -> Result<()> {
        *self.initialized.write() = true;
        Ok(())
    }

    async fn initialize_redis(&self, _redis_handler: DynRedisHandler) -> Result<()> {
        *self.redis_calls.write() += 1;
        Ok(())
    }

    async fn initialize_agent(&self, _agent_handler: DynAgentHandler) -> Result<()> {
        *self.agent_calls.write() += 1;
        Ok(())
    }

    fn get_country(&self, ip: &str) -> Option<String> {
        self.countries.read().get(ip).cloned()
    }
}
