#[path = "support/request.rs"]
mod mock_request;

#[path = "support/response.rs"]
mod mock_response;

#[path = "support/middleware.rs"]
mod mock_middleware;

#[path = "support/mock_agent.rs"]
mod mock_agent;

use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use futures::future::FutureExt;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::CustomValidatorsCheck;
use guard_core_rs::core::routing::RoutingContext;
use guard_core_rs::core::routing::resolver::RouteConfigResolver;
use guard_core_rs::decorators::RouteConfig;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::protocols::response::{DynGuardResponse, GuardResponse};
use mock_agent::MockAgent;
use mock_middleware::MockMiddleware;
use mock_request::MockRequest;

struct StubResponse {
    status: u16,
}

impl std::fmt::Debug for StubResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubResponse").field("status", &self.status).finish()
    }
}

impl GuardResponse for StubResponse {
    fn status_code(&self) -> u16 {
        self.status
    }
    fn headers(&self) -> std::collections::HashMap<String, String> {
        std::collections::HashMap::new()
    }
    fn set_header(&self, _name: &str, _value: &str) {}
    fn remove_header(&self, _name: &str) {}
    fn body(&self) -> Option<Bytes> {
        None
    }
}

fn stub_response(status: u16) -> DynGuardResponse {
    Arc::new(StubResponse { status })
}

type ValidatorFn = dyn Fn(
        Arc<dyn guard_core_rs::protocols::request::GuardRequest>,
    ) -> futures::future::BoxFuture<
        'static,
        Option<Arc<dyn guard_core_rs::protocols::response::GuardResponse>>,
    > + Send
    + Sync;

fn validator_blocks() -> Arc<ValidatorFn> {
    Arc::new(|_req| async move { Some(stub_response(418)) }.boxed())
}

fn validator_allows() -> Arc<ValidatorFn> {
    Arc::new(|_req| async move { None }.boxed())
}

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

fn middleware_with_agent(passive: bool) -> (Arc<MockAgent>, Arc<MockMiddleware>) {
    let agent = Arc::new(MockAgent::default());
    let dyn_agent: DynAgentHandler = Arc::clone(&agent) as Arc<dyn AgentHandlerProtocol>;
    let config = Arc::new(
        SecurityConfig::builder()
            .passive_mode(passive)
            .build()
            .expect("valid"),
    );
    (agent, MockMiddleware::with_handlers(config, Some(dyn_agent), None, None))
}

fn request(path: &str) -> DynGuardRequest {
    Arc::new(MockRequest::builder().path(path).build())
}

#[tokio::test]
async fn custom_validators_no_route_returns_none() {
    let check = CustomValidatorsCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(check.check(&request("/")).await.expect("ok").is_none());
    assert_eq!(check.check_name(), "custom_validators");
}

#[tokio::test]
async fn custom_validators_empty_list_returns_none() {
    let resolver = resolver_with("/x", RouteConfig::new());
    let (_a, middleware) = middleware_with_agent(false);
    let check = CustomValidatorsCheck::new(middleware, resolver);
    assert!(check.check(&request("/x")).await.expect("ok").is_none());
}

#[tokio::test]
async fn custom_validators_blocking_validator_returns_response() {
    let rc = RouteConfig::new().custom_validation(validator_blocks());
    let resolver = resolver_with("/x", rc);
    let (agent, middleware) = middleware_with_agent(false);
    let check = CustomValidatorsCheck::new(middleware, resolver);
    let response = check.check(&request("/x")).await.expect("ok").expect("blocked");
    assert_eq!(response.status_code(), 418);
    let events = agent.events.read();
    assert_eq!(
        events[0]["event_type"],
        serde_json::Value::String("decorator_violation".into())
    );
}

#[tokio::test]
async fn custom_validators_passing_validators_do_not_block() {
    let rc = RouteConfig::new()
        .custom_validation(validator_allows())
        .custom_validation(validator_allows());
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = CustomValidatorsCheck::new(middleware, resolver);
    assert!(check.check(&request("/x")).await.expect("ok").is_none());
}

#[tokio::test]
async fn custom_validators_passive_mode_does_not_return_response() {
    let rc = RouteConfig::new().custom_validation(validator_blocks());
    let resolver = resolver_with("/x", rc);
    let (agent, middleware) = middleware_with_agent(true);
    let check = CustomValidatorsCheck::new(middleware, resolver);
    let result = check.check(&request("/x")).await.expect("ok");
    assert!(result.is_none());
    assert_eq!(
        agent.events.read()[0]["action_taken"],
        serde_json::Value::String("logged_only".into())
    );
}

#[tokio::test]
async fn custom_validators_counts_validators_invoked_until_block() {
    let invocation_counter: Arc<DashMap<u64, u64>> = Arc::new(DashMap::new());
    let counter = Arc::clone(&invocation_counter);
    let validator_count_then_block = Arc::new(move |_req: Arc<dyn guard_core_rs::protocols::request::GuardRequest>| {
        let c = Arc::clone(&counter);
        async move {
            c.entry(0).and_modify(|v| *v += 1).or_insert(1);
            Some(stub_response(422))
        }
        .boxed()
    });
    let rc = RouteConfig::new().custom_validation(validator_count_then_block);
    let resolver = resolver_with("/x", rc);
    let (_a, middleware) = middleware_with_agent(false);
    let check = CustomValidatorsCheck::new(middleware, resolver);
    let response = check.check(&request("/x")).await.expect("ok").expect("blocked");
    assert_eq!(response.status_code(), 422);
    assert_eq!(*invocation_counter.get(&0).expect("counted"), 1);
}

#[test]
fn custom_validators_check_debug() {
    let check = CustomValidatorsCheck::new(
        MockMiddleware::new(Arc::new(SecurityConfig::builder().build().expect("v"))),
        empty_resolver(),
    );
    assert!(format!("{check:?}").contains("CustomValidatorsCheck"));
}
