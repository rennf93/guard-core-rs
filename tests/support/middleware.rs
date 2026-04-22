use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};

use guard_core_rs::error::Result;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::DynAgentHandler;
use guard_core_rs::protocols::geo_ip::DynGeoIpHandler;
use guard_core_rs::protocols::middleware::GuardMiddlewareProtocol;
use guard_core_rs::protocols::redis::DynRedisHandler;
use guard_core_rs::protocols::response::{
    DynGuardResponse, DynGuardResponseFactory, GuardResponse, GuardResponseFactory,
};

pub(crate) struct InlineMockResponse {
    status: u16,
    headers: Arc<DashMap<String, String>>,
    body: Option<Bytes>,
}

impl std::fmt::Debug for InlineMockResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineMockResponse").field("status", &self.status).finish()
    }
}

impl GuardResponse for InlineMockResponse {
    fn status_code(&self) -> u16 {
        self.status
    }
    fn headers(&self) -> HashMap<String, String> {
        self.headers
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }
    fn set_header(&self, name: &str, value: &str) {
        self.headers.insert(name.to_string(), value.to_string());
    }
    fn remove_header(&self, name: &str) {
        self.headers.remove(name);
    }
    fn body(&self) -> Option<Bytes> {
        self.body.clone()
    }
}

#[derive(Default)]
pub(crate) struct InlineMockResponseFactory {
    pub(crate) created: RwLock<Vec<(u16, String)>>,
}

impl std::fmt::Debug for InlineMockResponseFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineMockResponseFactory")
            .field("created", &self.created.read().len())
            .finish()
    }
}

impl GuardResponseFactory for InlineMockResponseFactory {
    fn create_response(&self, content: &str, status_code: u16) -> DynGuardResponse {
        self.created.write().push((status_code, content.to_string()));
        Arc::new(InlineMockResponse {
            status: status_code,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::copy_from_slice(content.as_bytes())),
        })
    }

    fn create_redirect_response(&self, url: &str, status_code: u16) -> DynGuardResponse {
        let response = Arc::new(InlineMockResponse {
            status: status_code,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::new()),
        });
        response.set_header("Location", url);
        response
    }
}

pub(crate) struct MockMiddleware {
    config: Arc<SecurityConfig>,
    response_factory: DynGuardResponseFactory,
    agent_handler: Option<DynAgentHandler>,
    geo_ip_handler: Option<DynGeoIpHandler>,
    redis_handler: Option<DynRedisHandler>,
    last_cloud_refresh: Mutex<i64>,
    suspicious_counts: Arc<DashMap<String, u64>>,
    cloud_refresh_calls: Arc<Mutex<u32>>,
    refresh_error: bool,
}

impl MockMiddleware {
    pub(crate) fn new(config: Arc<SecurityConfig>) -> Arc<Self> {
        let factory: DynGuardResponseFactory = Arc::new(InlineMockResponseFactory::default());
        Arc::new(Self {
            config,
            response_factory: factory,
            agent_handler: None,
            geo_ip_handler: None,
            redis_handler: None,
            last_cloud_refresh: Mutex::new(0),
            suspicious_counts: Arc::new(DashMap::new()),
            cloud_refresh_calls: Arc::new(Mutex::new(0)),
            refresh_error: false,
        })
    }

    pub(crate) fn with_handlers(
        config: Arc<SecurityConfig>,
        agent: Option<DynAgentHandler>,
        geo: Option<DynGeoIpHandler>,
        redis: Option<DynRedisHandler>,
    ) -> Arc<Self> {
        let factory: DynGuardResponseFactory = Arc::new(InlineMockResponseFactory::default());
        Arc::new(Self {
            config,
            response_factory: factory,
            agent_handler: agent,
            geo_ip_handler: geo,
            redis_handler: redis,
            last_cloud_refresh: Mutex::new(0),
            suspicious_counts: Arc::new(DashMap::new()),
            cloud_refresh_calls: Arc::new(Mutex::new(0)),
            refresh_error: false,
        })
    }

    pub(crate) fn with_refresh_failure(config: Arc<SecurityConfig>) -> Arc<Self> {
        let factory: DynGuardResponseFactory = Arc::new(InlineMockResponseFactory::default());
        Arc::new(Self {
            config,
            response_factory: factory,
            agent_handler: None,
            geo_ip_handler: None,
            redis_handler: None,
            last_cloud_refresh: Mutex::new(0),
            suspicious_counts: Arc::new(DashMap::new()),
            cloud_refresh_calls: Arc::new(Mutex::new(0)),
            refresh_error: true,
        })
    }

    pub(crate) fn cloud_refresh_calls(&self) -> u32 {
        *self.cloud_refresh_calls.lock()
    }
}

#[async_trait]
impl GuardMiddlewareProtocol for MockMiddleware {
    fn config(&self) -> Arc<SecurityConfig> {
        Arc::clone(&self.config)
    }

    fn last_cloud_ip_refresh(&self) -> i64 {
        *self.last_cloud_refresh.lock()
    }

    fn set_last_cloud_ip_refresh(&self, ts: i64) {
        *self.last_cloud_refresh.lock() = ts;
    }

    fn suspicious_request_counts(&self) -> Arc<DashMap<String, u64>> {
        Arc::clone(&self.suspicious_counts)
    }

    fn event_bus(&self) -> Arc<dyn Any + Send + Sync> {
        Arc::new(())
    }

    fn route_resolver(&self) -> Arc<dyn Any + Send + Sync> {
        Arc::new(())
    }

    fn response_factory(&self) -> Arc<dyn Any + Send + Sync> {
        Arc::new(())
    }

    fn rate_limit_handler(&self) -> Arc<dyn Any + Send + Sync> {
        Arc::new(())
    }

    fn agent_handler(&self) -> Option<DynAgentHandler> {
        self.agent_handler.clone()
    }

    fn geo_ip_handler(&self) -> Option<DynGeoIpHandler> {
        self.geo_ip_handler.clone()
    }

    fn redis_handler(&self) -> Option<DynRedisHandler> {
        self.redis_handler.clone()
    }

    fn guard_response_factory(&self) -> DynGuardResponseFactory {
        Arc::clone(&self.response_factory)
    }

    async fn create_error_response(
        &self,
        status_code: u16,
        default_message: &str,
    ) -> Result<DynGuardResponse> {
        let message = self
            .config
            .custom_error_responses
            .get(&status_code)
            .cloned()
            .unwrap_or_else(|| default_message.to_string());
        Ok(self.response_factory.create_response(&message, status_code))
    }

    async fn refresh_cloud_ip_ranges(&self) -> Result<()> {
        *self.cloud_refresh_calls.lock() += 1;
        if self.refresh_error {
            return Err(guard_core_rs::error::GuardCoreError::CloudProvider(
                "forced".into(),
            ));
        }
        Ok(())
    }
}

#[tokio::test]
async fn __touch_all_mock_middleware_helpers() {
    let cfg = Arc::new(SecurityConfig::default());
    let mw1 = MockMiddleware::new(Arc::clone(&cfg));
    let mw2 = MockMiddleware::with_handlers(Arc::clone(&cfg), None, None, None);
    let mw3 = MockMiddleware::with_refresh_failure(Arc::clone(&cfg));
    let _ = mw2.cloud_refresh_calls();
    let _ = mw3.cloud_refresh_calls();
    let _ = mw1.config();
    let _ = mw1.last_cloud_ip_refresh();
    mw1.set_last_cloud_ip_refresh(1);
    let _ = mw1.suspicious_request_counts();
    let _ = mw1.event_bus();
    let _ = mw1.route_resolver();
    let _ = mw1.response_factory();
    let _ = mw1.rate_limit_handler();
    let _ = mw1.agent_handler();
    let _ = mw1.geo_ip_handler();
    let _ = mw1.redis_handler();
    let _ = mw1.guard_response_factory();
    let _ = mw1.create_error_response(500, "x").await;
    let _ = mw1.refresh_cloud_ip_ranges().await;
    let _ = mw3.refresh_cloud_ip_ranges().await;

    let factory = InlineMockResponseFactory::default();
    let _ = format!("{factory:?}");
    let response = factory.create_response("c", 200);
    let _ = format!("{response:?}");
    let _ = response.status_code();
    let _ = response.headers();
    response.set_header("k", "v");
    response.remove_header("k");
    let _ = response.body();
    let redirect = factory.create_redirect_response("/u", 302);
    let _ = redirect.status_code();
}
