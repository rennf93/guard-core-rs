use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;

use guard_core_rs::core::checks::{SecurityCheck, SecurityCheckPipeline};
use guard_core_rs::error::Result;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::DynAgentHandler;
use guard_core_rs::protocols::geo_ip::DynGeoIpHandler;
use guard_core_rs::protocols::middleware::{DynGuardMiddleware, GuardMiddlewareProtocol};
use guard_core_rs::protocols::redis::DynRedisHandler;
use guard_core_rs::protocols::request::{DynGuardRequest, GuardRequest, RequestState};
use guard_core_rs::protocols::response::{
    DynGuardResponse, DynGuardResponseFactory, GuardResponse, GuardResponseFactory,
};

#[derive(Debug)]
struct StubResponse {
    status: u16,
    headers: Arc<DashMap<String, String>>,
    body: Option<Bytes>,
}

impl GuardResponse for StubResponse {
    fn status_code(&self) -> u16 {
        self.status
    }
    fn headers(&self) -> HashMap<String, String> {
        self.headers.iter().map(|e| (e.key().clone(), e.value().clone())).collect()
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

#[derive(Debug, Default)]
struct StubFactory;

impl GuardResponseFactory for StubFactory {
    fn create_response(&self, content: &str, status_code: u16) -> DynGuardResponse {
        Arc::new(StubResponse {
            status: status_code,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::copy_from_slice(content.as_bytes())),
        })
    }
    fn create_redirect_response(&self, url: &str, status_code: u16) -> DynGuardResponse {
        let r = Arc::new(StubResponse {
            status: status_code,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::new()),
        });
        r.set_header("Location", url);
        r
    }
}

struct StubMiddleware {
    config: Arc<SecurityConfig>,
    factory: DynGuardResponseFactory,
    last_refresh: Mutex<i64>,
    counts: Arc<DashMap<String, u64>>,
}

impl StubMiddleware {
    fn new(config: Arc<SecurityConfig>) -> Arc<Self> {
        Arc::new(Self {
            config,
            factory: Arc::new(StubFactory),
            last_refresh: Mutex::new(0),
            counts: Arc::new(DashMap::new()),
        })
    }
}

#[async_trait]
impl GuardMiddlewareProtocol for StubMiddleware {
    fn config(&self) -> Arc<SecurityConfig> {
        Arc::clone(&self.config)
    }
    fn last_cloud_ip_refresh(&self) -> i64 {
        *self.last_refresh.lock()
    }
    fn set_last_cloud_ip_refresh(&self, ts: i64) {
        *self.last_refresh.lock() = ts;
    }
    fn suspicious_request_counts(&self) -> Arc<DashMap<String, u64>> {
        Arc::clone(&self.counts)
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
        None
    }
    fn geo_ip_handler(&self) -> Option<DynGeoIpHandler> {
        None
    }
    fn redis_handler(&self) -> Option<DynRedisHandler> {
        None
    }
    fn guard_response_factory(&self) -> DynGuardResponseFactory {
        Arc::clone(&self.factory)
    }
    async fn create_error_response(
        &self,
        status_code: u16,
        default_message: &str,
    ) -> Result<DynGuardResponse> {
        Ok(self.factory.create_response(default_message, status_code))
    }
    async fn refresh_cloud_ip_ranges(&self) -> Result<()> {
        Ok(())
    }
}

struct ExampleRequest {
    path: String,
    headers: HashMap<String, String>,
    state: Arc<RequestState>,
}

#[async_trait]
impl GuardRequest for ExampleRequest {
    fn url_path(&self) -> String {
        self.path.clone()
    }
    fn url_scheme(&self) -> String {
        "https".into()
    }
    fn url_full(&self) -> String {
        format!("https://demo{}", self.path)
    }
    fn url_replace_scheme(&self, scheme: &str) -> String {
        format!("{scheme}://demo{}", self.path)
    }
    fn method(&self) -> String {
        "GET".into()
    }
    fn client_host(&self) -> Option<String> {
        Some("10.0.0.1".into())
    }
    fn headers(&self) -> HashMap<String, String> {
        self.headers.clone()
    }
    fn query_params(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    async fn body(&self) -> Result<Bytes> {
        Ok(Bytes::new())
    }
    fn state(&self) -> Arc<RequestState> {
        Arc::clone(&self.state)
    }
    fn scope(&self) -> HashMap<String, serde_json::Value> {
        HashMap::new()
    }
}

fn request_with_header(path: &str, name: &str, value: &str) -> DynGuardRequest {
    let mut headers = HashMap::new();
    headers.insert(name.into(), value.into());
    Arc::new(ExampleRequest {
        path: path.into(),
        headers,
        state: Arc::new(RequestState::new()),
    })
}

struct RequireCorrelationIdCheck {
    middleware: DynGuardMiddleware,
}

#[async_trait]
impl SecurityCheck for RequireCorrelationIdCheck {
    fn check_name(&self) -> &'static str {
        "require_correlation_id"
    }
    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }
    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        if request.header("X-Correlation-Id").is_none() {
            return Ok(Some(
                self.middleware
                    .create_error_response(400, "missing X-Correlation-Id header")
                    .await?,
            ));
        }
        Ok(None)
    }
}

struct BlockExpensivePathCheck {
    middleware: DynGuardMiddleware,
    forbidden_prefix: &'static str,
}

#[async_trait]
impl SecurityCheck for BlockExpensivePathCheck {
    fn check_name(&self) -> &'static str {
        "block_expensive_path"
    }
    fn middleware(&self) -> &DynGuardMiddleware {
        &self.middleware
    }
    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        if request.url_path().starts_with(self.forbidden_prefix) {
            return Ok(Some(
                self.middleware
                    .create_error_response(403, "path blocked by custom policy")
                    .await?,
            ));
        }
        Ok(None)
    }
}

#[tokio::main]
async fn main() {
    println!("guard-core-rs: custom_check example");
    println!("-----------------------------------");

    let config = Arc::new(SecurityConfig::builder().build().expect("valid config"));
    let middleware: DynGuardMiddleware = StubMiddleware::new(Arc::clone(&config));

    let mut pipeline = SecurityCheckPipeline::new();
    pipeline.add_check(Arc::new(RequireCorrelationIdCheck {
        middleware: Arc::clone(&middleware),
    }));
    pipeline.add_check(Arc::new(BlockExpensivePathCheck {
        middleware: Arc::clone(&middleware),
        forbidden_prefix: "/internal/expensive",
    }));

    println!("Custom checks registered: {:?}", pipeline.get_check_names());
    println!();

    let no_header = request_with_header("/api/users", "X-Other", "foo");
    let ok = request_with_header("/api/users", "X-Correlation-Id", "abc-123");
    let forbidden = request_with_header("/internal/expensive/report", "X-Correlation-Id", "zzz");

    for (label, req) in [
        ("missing correlation id", &no_header),
        ("with correlation id", &ok),
        ("with forbidden path", &forbidden),
    ] {
        match pipeline.execute(req).await {
            Ok(None) => println!("[{label}] allowed"),
            Ok(Some(response)) => println!(
                "[{label}] blocked with status {} body={} bytes",
                response.status_code(),
                response.body().map(|b| b.len()).unwrap_or(0)
            ),
            Err(e) => println!("[{label}] pipeline error: {e}"),
        }
    }
}
