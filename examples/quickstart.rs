use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;

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

#[derive(Debug)]
struct ExampleResponse {
    status: u16,
    headers: Arc<DashMap<String, String>>,
    body: Option<Bytes>,
}

impl GuardResponse for ExampleResponse {
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
struct ExampleResponseFactory;

impl GuardResponseFactory for ExampleResponseFactory {
    fn create_response(&self, content: &str, status_code: u16) -> DynGuardResponse {
        Arc::new(ExampleResponse {
            status: status_code,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::copy_from_slice(content.as_bytes())),
        })
    }
    fn create_redirect_response(&self, url: &str, status_code: u16) -> DynGuardResponse {
        let response = Arc::new(ExampleResponse {
            status: status_code,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::new()),
        });
        response.set_header("Location", url);
        response
    }
}

struct ExampleMiddleware {
    config: Arc<SecurityConfig>,
    response_factory: DynGuardResponseFactory,
    last_cloud_refresh: Mutex<i64>,
    suspicious_counts: Arc<DashMap<String, u64>>,
}

impl ExampleMiddleware {
    fn new(config: Arc<SecurityConfig>) -> Arc<Self> {
        Arc::new(Self {
            config,
            response_factory: Arc::new(ExampleResponseFactory),
            last_cloud_refresh: Mutex::new(0),
            suspicious_counts: Arc::new(DashMap::new()),
        })
    }
}

#[async_trait]
impl GuardMiddlewareProtocol for ExampleMiddleware {
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

struct ExampleRequest {
    path: String,
    method: String,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
    body: Bytes,
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
        format!("https://demo.example{}", self.path)
    }
    fn url_replace_scheme(&self, scheme: &str) -> String {
        format!("{scheme}://demo.example{}", self.path)
    }
    fn method(&self) -> String {
        self.method.clone()
    }
    fn client_host(&self) -> Option<String> {
        Some("10.0.0.42".into())
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

fn make_request(path: &str, client_ip: &str, body: &[u8]) -> DynGuardRequest {
    let mut headers = HashMap::new();
    headers.insert("User-Agent".into(), "guard-core-rs-example/0.1".into());
    headers.insert("Accept".into(), "application/json".into());
    let request = ExampleRequest {
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

#[tokio::main]
async fn main() {
    println!("guard-core-rs: quickstart example");
    println!("---------------------------------");

    let config = Arc::new(
        SecurityConfig::builder()
            .passive_mode(false)
            .enable_rate_limiting(true)
            .rate_limit(100)
            .rate_limit_window(60)
            .enable_ip_banning(true)
            .enable_penetration_detection(true)
            .blocked_user_agents(vec!["sqlmap".into(), "nikto".into()])
            .build()
            .expect("valid config"),
    );

    let middleware: DynGuardMiddleware = ExampleMiddleware::new(Arc::clone(&config));
    let resolver = Arc::new(RouteConfigResolver::new(RoutingContext::new(Arc::clone(&config))));
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
    pipeline.add_check(Arc::new(UserAgentCheck::new(
        Arc::clone(&middleware),
        Arc::clone(&resolver),
    )));
    pipeline.add_check(Arc::new(SuspiciousActivityCheck::new(
        Arc::clone(&middleware),
        Arc::clone(&resolver),
        Arc::clone(&ipban),
        Arc::clone(&patterns),
    )));

    println!("Registered checks: {:?}", pipeline.get_check_names());
    println!();

    let benign = make_request("/api/v1/users", "10.0.0.42", b"{\"name\":\"Alice\"}");
    let malicious = make_request(
        "/api/v1/search",
        "10.0.0.43",
        b"q=<script>alert(document.cookie)</script>",
    );

    println!("Running benign request at POST /api/v1/users");
    match pipeline.execute(&benign).await {
        Ok(None) => println!("  -> ALLOWED (no check returned a response)"),
        Ok(Some(response)) => println!("  -> BLOCKED with status {}", response.status_code()),
        Err(e) => println!("  -> ERROR: {e}"),
    }

    println!();
    println!("Running malicious XSS request at POST /api/v1/search");
    match pipeline.execute(&malicious).await {
        Ok(None) => println!("  -> ALLOWED (unexpected)"),
        Ok(Some(response)) => println!(
            "  -> BLOCKED with status {} ({} bytes body)",
            response.status_code(),
            response.body().map(|b| b.len()).unwrap_or(0)
        ),
        Err(e) => println!("  -> ERROR: {e}"),
    }
}
