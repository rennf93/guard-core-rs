use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::runtime::Runtime;

use guard_core_rs::core::checks::{
    IpSecurityCheck, RateLimitCheck, SecurityCheckPipeline, SuspiciousActivityCheck, UserAgentCheck,
};
use guard_core_rs::core::routing::{RouteConfigResolver, RoutingContext};
use guard_core_rs::error::Result;
use guard_core_rs::handlers::ipban::IPBanManager;
use guard_core_rs::handlers::ratelimit::RateLimitManager;
use guard_core_rs::handlers::suspatterns::SusPatternsManager;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::DynAgentHandler;
use guard_core_rs::protocols::geo_ip::DynGeoIpHandler;
use guard_core_rs::protocols::middleware::{DynGuardMiddleware, GuardMiddlewareProtocol};
use guard_core_rs::protocols::redis::DynRedisHandler;
use guard_core_rs::protocols::request::{DynGuardRequest, GuardRequest, RequestState};
use guard_core_rs::protocols::response::{
    DynGuardResponse, DynGuardResponseFactory, GuardResponse, GuardResponseFactory,
};
use guard_core_rs::utils::CLIENT_IP_KEY;

struct BenchResponse {
    status: u16,
    headers: Arc<DashMap<String, String>>,
    body: Option<Bytes>,
}

impl std::fmt::Debug for BenchResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BenchResponse").field("status", &self.status).finish()
    }
}

impl GuardResponse for BenchResponse {
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

#[derive(Default)]
struct BenchResponseFactory;

impl std::fmt::Debug for BenchResponseFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BenchResponseFactory").finish()
    }
}

impl GuardResponseFactory for BenchResponseFactory {
    fn create_response(&self, content: &str, status_code: u16) -> DynGuardResponse {
        Arc::new(BenchResponse {
            status: status_code,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::copy_from_slice(content.as_bytes())),
        })
    }
    fn create_redirect_response(&self, url: &str, status_code: u16) -> DynGuardResponse {
        let response = Arc::new(BenchResponse {
            status: status_code,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::new()),
        });
        response.set_header("Location", url);
        response
    }
}

struct BenchMiddleware {
    config: Arc<SecurityConfig>,
    response_factory: DynGuardResponseFactory,
    last_cloud_refresh: Mutex<i64>,
    suspicious_counts: Arc<DashMap<String, u64>>,
}

impl BenchMiddleware {
    fn new(config: Arc<SecurityConfig>) -> Arc<Self> {
        Arc::new(Self {
            config,
            response_factory: Arc::new(BenchResponseFactory),
            last_cloud_refresh: Mutex::new(0),
            suspicious_counts: Arc::new(DashMap::new()),
        })
    }
}

#[async_trait]
impl GuardMiddlewareProtocol for BenchMiddleware {
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
        None
    }
    fn geo_ip_handler(&self) -> Option<DynGeoIpHandler> {
        None
    }
    fn redis_handler(&self) -> Option<DynRedisHandler> {
        None
    }
    fn guard_response_factory(&self) -> DynGuardResponseFactory {
        Arc::clone(&self.response_factory)
    }
    async fn create_error_response(
        &self,
        status_code: u16,
        default_message: &str,
    ) -> Result<DynGuardResponse> {
        Ok(self.response_factory.create_response(default_message, status_code))
    }
    async fn refresh_cloud_ip_ranges(&self) -> Result<()> {
        Ok(())
    }
}

struct BenchRequest {
    path: String,
    method: String,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
    body: Bytes,
    state: Arc<RequestState>,
}

#[async_trait]
impl GuardRequest for BenchRequest {
    fn url_path(&self) -> String {
        self.path.clone()
    }
    fn url_scheme(&self) -> String {
        "https".into()
    }
    fn url_full(&self) -> String {
        format!("https://host{}", self.path)
    }
    fn url_replace_scheme(&self, scheme: &str) -> String {
        format!("{scheme}://host{}", self.path)
    }
    fn method(&self) -> String {
        self.method.clone()
    }
    fn client_host(&self) -> Option<String> {
        Some("10.0.0.1".into())
    }
    fn headers(&self) -> HashMap<String, String> {
        self.headers.clone()
    }
    fn query_params(&self) -> HashMap<String, String> {
        self.query.clone()
    }
    async fn body(&self) -> Result<Bytes> {
        Ok(self.body.clone())
    }
    fn state(&self) -> Arc<RequestState> {
        Arc::clone(&self.state)
    }
    fn scope(&self) -> HashMap<String, serde_json::Value> {
        HashMap::new()
    }
}

fn build_request(path: &str, client_ip: &str, ua: &str, body: &[u8]) -> DynGuardRequest {
    let mut headers = HashMap::new();
    headers.insert("User-Agent".into(), ua.into());
    headers.insert("Accept".into(), "application/json".into());
    let request = BenchRequest {
        path: path.into(),
        method: "POST".into(),
        headers,
        query: HashMap::new(),
        body: Bytes::copy_from_slice(body),
        state: Arc::new(RequestState::new()),
    };
    let req: DynGuardRequest = Arc::new(request);
    req.state().set_str(CLIENT_IP_KEY, client_ip);
    req
}

fn build_pipeline(config: Arc<SecurityConfig>) -> SecurityCheckPipeline {
    let middleware: DynGuardMiddleware = BenchMiddleware::new(Arc::clone(&config));
    let routing = RoutingContext::new(Arc::clone(&config));
    let resolver = Arc::new(RouteConfigResolver::new(routing));
    let ipban = Arc::new(IPBanManager::new());
    let rate_limit = RateLimitManager::new(Arc::clone(&config));
    let patterns = SusPatternsManager::arc(Some(&config));

    let mut pipeline = SecurityCheckPipeline::new();
    pipeline.add_check(Arc::new(IpSecurityCheck::new(
        Arc::clone(&middleware),
        Arc::clone(&resolver),
        Arc::clone(&ipban),
    )));
    pipeline.add_check(Arc::new(RateLimitCheck::new(
        Arc::clone(&middleware),
        Arc::clone(&resolver),
        Arc::clone(&rate_limit),
    )));
    pipeline.add_check(Arc::new(SuspiciousActivityCheck::new(
        Arc::clone(&middleware),
        Arc::clone(&resolver),
        Arc::clone(&ipban),
        Arc::clone(&patterns),
    )));
    pipeline.add_check(Arc::new(UserAgentCheck::new(
        Arc::clone(&middleware),
        Arc::clone(&resolver),
    )));
    pipeline
}

fn bench_pipeline_execute(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let config = Arc::new(
        SecurityConfig::builder()
            .enable_rate_limiting(true)
            .rate_limit(10_000)
            .rate_limit_window(60)
            .enable_ip_banning(true)
            .enable_penetration_detection(true)
            .build()
            .expect("valid"),
    );
    let pipeline = build_pipeline(config);

    let benign_body: &[u8] = b"{\"name\":\"Alice\",\"age\":30}";
    let probe_body: &[u8] = b"q=hello+world";
    let attack_body: &[u8] = b"q=<script>alert(document.cookie)</script>";

    let mut group = c.benchmark_group("pipeline_execute");
    group.bench_function("benign_request", |b| {
        b.iter(|| {
            let req = build_request("/api/v1/users", "10.0.0.1", "Mozilla/5.0", benign_body);
            rt.block_on(async {
                let _ = pipeline.execute(black_box(&req)).await;
            });
        });
    });
    group.bench_function("probe_request", |b| {
        b.iter(|| {
            let req = build_request("/api/v1/search", "10.0.0.2", "curl/7.79.1", probe_body);
            rt.block_on(async {
                let _ = pipeline.execute(black_box(&req)).await;
            });
        });
    });
    group.bench_function("attack_request", |b| {
        b.iter(|| {
            let req = build_request("/api/v1/search", "10.0.0.3", "Mozilla/5.0", attack_body);
            rt.block_on(async {
                let _ = pipeline.execute(black_box(&req)).await;
            });
        });
    });
    group.finish();
}

criterion_group!(checks_benches, bench_pipeline_execute);
criterion_main!(checks_benches);
