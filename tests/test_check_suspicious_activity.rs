#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::sync::Arc;

use serde_json::Value;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::SuspiciousActivityCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::handlers::ipban::IPBanManager;
use guard_core_rs::handlers::suspatterns::SusPatternsManager;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::utils::CLIENT_IP_KEY;
use mock_agent::MockAgent;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

fn resolver_with(path: &str, rc: RouteConfig) -> Arc<RouteConfigResolver> {
    let cfg = Arc::new(SecurityConfig::builder().build().expect("valid"));
    let resolver = Arc::new(RouteConfigResolver::new(RoutingContext::new(cfg)));
    resolver.register(path, rc);
    resolver
}

fn empty_resolver() -> Arc<RouteConfigResolver> {
    Arc::new(RouteConfigResolver::new(RoutingContext::new(Arc::new(
        SecurityConfig::builder().build().expect("valid"),
    ))))
}

fn config(
    passive: bool,
    enable: bool,
    ban_threshold: u32,
    enable_banning: bool,
) -> Arc<SecurityConfig> {
    let config = SecurityConfig::builder()
        .passive_mode(passive)
        .enable_penetration_detection(enable)
        .enable_ip_banning(enable_banning)
        .auto_ban_threshold(ban_threshold)
        .auto_ban_duration(300)
        .build()
        .expect("valid");
    Arc::new(config)
}

fn middleware(agent: Arc<MockAgent>, config: Arc<SecurityConfig>) -> Arc<MockMiddleware> {
    let dyn_agent: DynAgentHandler = agent as Arc<dyn AgentHandlerProtocol>;
    MockMiddleware::with_handlers(config, Some(dyn_agent), None, None)
}

fn request(path: &str, ip: Option<&str>) -> DynGuardRequest {
    let request: DynGuardRequest = Arc::new(MockRequest::builder().path(path).build());
    if let Some(ip_value) = ip {
        request.state().set_str(CLIENT_IP_KEY, ip_value);
    }
    request
}

fn malicious_request(ip: &str) -> DynGuardRequest {
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/api")
            .query("input", "<script>alert(1)</script>")
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, ip);
    request
}

#[tokio::test]
async fn suspicious_activity_whitelisted_request_bypasses() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 3, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let request: DynGuardRequest = Arc::new(MockRequest::default());
    request.state().set_bool("is_whitelisted", true);
    assert!(check.check(&request).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "suspicious_activity");
}

#[tokio::test]
async fn suspicious_activity_missing_client_ip_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 3, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    assert!(
        check
            .check(&request("/", None))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn suspicious_activity_detection_disabled_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, false, 3, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let result = check.check(&malicious_request("1.1.1.1")).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn suspicious_activity_decorator_disabled_emits_violation_and_returns_none() {
    let rc = RouteConfig::new().suspicious_detection(false);
    let resolver = resolver_with("/secure", rc);
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 3, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, resolver, ipban, patterns);
    let mut builder = MockRequest::builder().path("/secure");
    builder = builder.header("x", "<script>");
    let request: DynGuardRequest = Arc::new(builder.build());
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.2");
    let result = check.check(&request).await.expect("ok");
    assert!(result.is_none());
    assert_eq!(
        agent.events.read()[0]["action_taken"],
        Value::String("detection_disabled".into())
    );
}

#[tokio::test]
async fn suspicious_activity_bypass_penetration_returns_none() {
    let rc = RouteConfig::new().bypass(vec!["penetration".into()]);
    let resolver = resolver_with("/bypass", rc);
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 3, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, resolver, ipban, patterns);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/bypass/<script>alert(1)</script>")
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.3");
    let result = check.check(&request).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn suspicious_activity_malicious_request_active_mode_blocks_with_400() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 100, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let response = check
        .check(&malicious_request("10.0.0.4"))
        .await
        .expect("ok");
    assert!(response.is_some());
    let resp = response.expect("expected response");
    assert_eq!(resp.status_code(), 400);
}

#[tokio::test]
async fn suspicious_activity_malicious_request_passive_mode_returns_none() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(true, true, 100, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let result = check.check(&malicious_request("10.0.0.5")).await.expect("ok");
    assert!(result.is_none());
    let events = agent.events.read();
    assert!(!events.is_empty());
    assert_eq!(events[0]["event_type"], Value::String("penetration_attempt".into()));
}

#[tokio::test]
async fn suspicious_activity_triggers_ban_when_over_threshold() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 1, true);
    let middleware: Arc<MockMiddleware> = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    use guard_core_rs::protocols::middleware::GuardMiddlewareProtocol;
    GuardMiddlewareProtocol::suspicious_request_counts(middleware.as_ref())
        .insert("10.0.0.6".into(), 1);
    let dyn_middleware = Arc::clone(&middleware) as Arc<dyn GuardMiddlewareProtocol>;
    let check = SuspiciousActivityCheck::new(dyn_middleware, empty_resolver(), Arc::clone(&ipban), patterns);
    let result = check.check(&malicious_request("10.0.0.6")).await.expect("ok");
    assert!(result.is_some());
    let resp = result.expect("expected response");
    assert_eq!(resp.status_code(), 403);
    assert!(ipban.is_ip_banned("10.0.0.6").await.expect("ban"));
}

#[tokio::test]
async fn suspicious_activity_header_based_detection_blocks() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 100, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/api")
            .header("X-Search", "<script>alert(1)</script>")
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.7");
    let response = check.check(&request).await.expect("ok");
    assert!(response.is_some());
}

#[tokio::test]
async fn suspicious_activity_authorization_and_cookie_headers_ignored() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 100, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/api")
            .header("Authorization", "<script>")
            .header("Cookie", "<script>alert(1)</script>")
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.8");
    let result = check.check(&request).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn suspicious_activity_body_based_detection_blocks() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 100, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/api")
            .method("POST")
            .body(bytes::Bytes::from_static(
                b"<script>alert('xss')</script>",
            ))
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.9");
    let response = check.check(&request).await.expect("ok");
    assert!(response.is_some());
}

#[tokio::test]
async fn suspicious_activity_benign_request_is_allowed() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 100, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/api/status")
            .query("name", "alice")
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.11");
    assert!(check.check(&request).await.expect("ok").is_none());
}

#[tokio::test]
async fn suspicious_activity_path_based_detection_blocks() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 100, false);
    let middleware = middleware(Arc::clone(&agent), Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    let request: DynGuardRequest = Arc::new(
        MockRequest::builder()
            .path("/api/../etc/passwd")
            .build(),
    );
    request.state().set_str(CLIENT_IP_KEY, "10.0.0.12");
    let response = check.check(&request).await.expect("ok");
    assert!(response.is_some());
}

#[test]
fn suspicious_activity_check_debug() {
    let agent = Arc::new(MockAgent::default());
    let config_v = config(false, true, 3, false);
    let middleware = middleware(agent, Arc::clone(&config_v));
    let ipban = Arc::new(IPBanManager::new());
    let patterns = Arc::new(SusPatternsManager::new(Some(&config_v)));
    let check = SuspiciousActivityCheck::new(middleware, empty_resolver(), ipban, patterns);
    assert!(format!("{check:?}").contains("SuspiciousActivityCheck"));
}
