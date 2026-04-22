#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

#[path = "support/geo_ip.rs"]
mod mock_geo;

use std::sync::Arc;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::IpSecurityCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::handlers::ipban::IPBanManager;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::geo_ip::DynGeoIpHandler;
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::utils::CLIENT_IP_KEY;
use mock_agent::MockAgent;
use mock_geo::MockGeoIpHandler;
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

fn middleware_with_agent_and_geo(
    passive: bool,
    whitelist: Option<Vec<String>>,
    blacklist: Vec<String>,
    geo: Option<DynGeoIpHandler>,
) -> (Arc<MockAgent>, Arc<MockMiddleware>) {
    let agent = Arc::new(MockAgent::default());
    let dyn_agent: DynAgentHandler = Arc::clone(&agent) as Arc<dyn AgentHandlerProtocol>;
    let config = Arc::new(
        SecurityConfig::builder()
            .passive_mode(passive)
            .whitelist(whitelist)
            .blacklist(blacklist)
            .build()
            .expect("valid"),
    );
    (agent, MockMiddleware::with_handlers(config, Some(dyn_agent), geo, None))
}

fn request_at(path: &str, client_ip: &str) -> DynGuardRequest {
    let request: DynGuardRequest = Arc::new(MockRequest::builder().path(path).build());
    request.state().set_str(CLIENT_IP_KEY, client_ip);
    request
}

fn request_without_client_ip(path: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().path(path).build())
}

#[tokio::test]
async fn ip_security_no_client_ip_returns_none() {
    let (_a, middleware) = middleware_with_agent_and_geo(false, None, Vec::new(), None);
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, empty_resolver(), ipban);
    assert!(
        check
            .check(&request_without_client_ip("/x"))
            .await
            .expect("ok")
            .is_none()
    );
    assert_eq!(check.check_name(), "ip_security");
}

#[tokio::test]
async fn ip_security_banned_ip_blocks_with_403() {
    let (_a, middleware) = middleware_with_agent_and_geo(false, None, Vec::new(), None);
    let ipban = Arc::new(IPBanManager::new());
    ipban.ban_ip("10.0.0.9", 60, "test").await.expect("banned");
    let check = IpSecurityCheck::new(middleware, empty_resolver(), ipban);
    let response = check
        .check(&request_at("/", "10.0.0.9"))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 403);
}

#[tokio::test]
async fn ip_security_banned_ip_passive_mode_returns_none() {
    let (_a, middleware) = middleware_with_agent_and_geo(true, None, Vec::new(), None);
    let ipban = Arc::new(IPBanManager::new());
    ipban.ban_ip("10.0.0.9", 60, "t").await.expect("banned");
    let check = IpSecurityCheck::new(middleware, empty_resolver(), ipban);
    let result = check.check(&request_at("/", "10.0.0.9")).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn ip_security_banned_ip_bypassed_by_route_config() {
    let rc = RouteConfig::new().bypass(vec!["ip_ban".into()]);
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent_and_geo(false, None, Vec::new(), None);
    let ipban = Arc::new(IPBanManager::new());
    ipban.ban_ip("10.0.0.9", 60, "t").await.expect("banned");
    let check = IpSecurityCheck::new(middleware, resolver, ipban);
    let result = check.check(&request_at("/x", "10.0.0.9")).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn ip_security_bypass_check_ip_returns_none_when_route_has_bypass() {
    let rc = RouteConfig::new().bypass(vec!["ip".into()]);
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent_and_geo(
        false,
        None,
        vec!["10.0.0.99".into()],
        None,
    );
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, resolver, ipban);
    assert!(
        check
            .check(&request_at("/x", "10.0.0.99"))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn ip_security_route_blocked_ip_returns_403() {
    let rc = RouteConfig::new().require_ip(None, Some(vec!["10.0.0.5".into()]));
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent_and_geo(false, None, Vec::new(), None);
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, resolver, ipban);
    let response = check
        .check(&request_at("/x", "10.0.0.5"))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 403);
}

#[tokio::test]
async fn ip_security_route_allowed_ip_passes() {
    let rc = RouteConfig::new().require_ip(Some(vec!["10.0.0.5".into()]), None);
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent_and_geo(false, None, Vec::new(), None);
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, resolver, ipban);
    assert!(
        check
            .check(&request_at("/x", "10.0.0.5"))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn ip_security_route_blocked_ip_passive_mode_returns_none() {
    let rc = RouteConfig::new().require_ip(None, Some(vec!["10.0.0.15".into()]));
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent_and_geo(true, None, Vec::new(), None);
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, resolver, ipban);
    assert!(
        check
            .check(&request_at("/x", "10.0.0.15"))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn ip_security_global_blocklist_blocks() {
    let (agent, middleware) =
        middleware_with_agent_and_geo(false, None, vec!["10.0.0.1".into()], None);
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, empty_resolver(), ipban);
    let response = check
        .check(&request_at("/x", "10.0.0.1"))
        .await
        .expect("ok")
        .expect("blocked");
    assert_eq!(response.status_code(), 403);
    assert_eq!(
        agent.events.read()[0]["event_type"],
        serde_json::Value::String("ip_blocked".into())
    );
}

#[tokio::test]
async fn ip_security_global_blocklist_passive_mode_allows() {
    let (_a, middleware) =
        middleware_with_agent_and_geo(true, None, vec!["10.0.0.1".into()], None);
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, empty_resolver(), ipban);
    let result = check.check(&request_at("/x", "10.0.0.1")).await.expect("ok");
    assert!(result.is_none());
}

#[tokio::test]
async fn ip_security_global_allowlist_passes() {
    let (_a, middleware) = middleware_with_agent_and_geo(
        false,
        Some(vec!["10.0.0.10".into()]),
        Vec::new(),
        None,
    );
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, empty_resolver(), ipban);
    assert!(
        check
            .check(&request_at("/x", "10.0.0.10"))
            .await
            .expect("ok")
            .is_none()
    );
}

#[tokio::test]
async fn ip_security_route_with_country_via_geo_passes() {
    let geo = MockGeoIpHandler::with_mapping(&[("10.0.0.5", "US")]);
    let dyn_geo: DynGeoIpHandler = geo.dyn_handler();
    let rc = RouteConfig::new().allow_countries(vec!["US".into()]);
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) =
        middleware_with_agent_and_geo(false, None, Vec::new(), Some(dyn_geo));
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, resolver, ipban);
    assert!(
        check
            .check(&request_at("/x", "10.0.0.5"))
            .await
            .expect("ok")
            .is_none()
    );
}

#[test]
fn ip_security_check_debug() {
    let (_a, middleware) = middleware_with_agent_and_geo(false, None, Vec::new(), None);
    let ipban = Arc::new(IPBanManager::new());
    let check = IpSecurityCheck::new(middleware, empty_resolver(), ipban);
    assert!(format!("{check:?}").contains("IpSecurityCheck"));
}
