#[path = "support/mock_agent.rs"]
mod mock_agent;

#[path = "support/mock_redis.rs"]
mod mock_redis;

#[path = "support/geo_ip.rs"]
mod mock_geo;

use std::sync::Arc;

use guard_core_rs::core::initialization::handler_initializer::HandlerInitializer;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::agent::{AgentHandlerProtocol, DynAgentHandler};
use guard_core_rs::protocols::geo_ip::DynGeoIpHandler;
use guard_core_rs::protocols::redis::{DynRedisHandler, RedisHandlerProtocol};
use mock_agent::MockAgent;
use mock_geo::MockGeoIpHandler;
use mock_redis::MockRedis;

fn config() -> Arc<SecurityConfig> {
    Arc::new(SecurityConfig::builder().build().expect("valid"))
}

fn agent_handler(agent: Arc<MockAgent>) -> DynAgentHandler {
    agent as Arc<dyn AgentHandlerProtocol>
}

fn redis_handler(redis: Arc<MockRedis>) -> DynRedisHandler {
    redis as Arc<dyn RedisHandlerProtocol>
}

fn geo_handler(geo: Arc<MockGeoIpHandler>) -> DynGeoIpHandler {
    geo.dyn_handler()
}

#[test]
fn handler_initializer_stores_handlers() {
    let agent = Arc::new(MockAgent::default());
    let redis = Arc::new(MockRedis::default());
    let geo = MockGeoIpHandler::with_mapping(&[]);
    let initializer = HandlerInitializer::new(
        config(),
        Some(redis_handler(Arc::clone(&redis))),
        Some(agent_handler(Arc::clone(&agent))),
        Some(geo_handler(Arc::clone(&geo))),
    );
    assert!(initializer.redis_handler.is_some());
    assert!(initializer.agent_handler.is_some());
    assert!(initializer.geo_ip_handler.is_some());
}

#[test]
fn handler_initializer_debug_does_not_panic() {
    let initializer = HandlerInitializer::new(config(), None, None, None);
    assert!(format!("{initializer:?}").contains("HandlerInitializer"));
}

#[test]
fn handler_initializer_clone_preserves_handlers() {
    let initializer = HandlerInitializer::new(config(), None, None, None);
    let cloned = initializer.clone();
    assert!(cloned.redis_handler.is_none());
}

#[tokio::test]
async fn initialize_redis_handlers_calls_initialize_when_present() {
    let redis = Arc::new(MockRedis::default());
    let initializer = HandlerInitializer::new(
        config(),
        Some(redis_handler(Arc::clone(&redis))),
        None,
        None,
    );
    initializer.initialize_redis_handlers().await.expect("ok");
    assert!(*redis.initialized.read());
}

#[tokio::test]
async fn initialize_redis_handlers_noop_when_absent() {
    let initializer = HandlerInitializer::new(config(), None, None, None);
    initializer.initialize_redis_handlers().await.expect("ok");
}

#[tokio::test]
async fn initialize_agent_integrations_calls_agent_redis_when_both_set() {
    let agent = Arc::new(MockAgent::default());
    let redis = Arc::new(MockRedis::default());
    let initializer = HandlerInitializer::new(
        config(),
        Some(redis_handler(Arc::clone(&redis))),
        Some(agent_handler(Arc::clone(&agent))),
        None,
    );
    initializer.initialize_agent_integrations().await.expect("ok");
}

#[tokio::test]
async fn initialize_agent_integrations_geo_with_redis_and_agent() {
    let agent = Arc::new(MockAgent::default());
    let redis = Arc::new(MockRedis::default());
    let geo = MockGeoIpHandler::with_mapping(&[]);
    let initializer = HandlerInitializer::new(
        config(),
        Some(redis_handler(Arc::clone(&redis))),
        Some(agent_handler(Arc::clone(&agent))),
        Some(geo_handler(Arc::clone(&geo))),
    );
    initializer.initialize_agent_integrations().await.expect("ok");
    assert_eq!(*geo.redis_calls.read(), 1);
    assert_eq!(*geo.agent_calls.read(), 1);
}

#[tokio::test]
async fn initialize_agent_integrations_geo_without_redis_skips_redis_call() {
    let agent = Arc::new(MockAgent::default());
    let geo = MockGeoIpHandler::with_mapping(&[]);
    let initializer = HandlerInitializer::new(
        config(),
        None,
        Some(agent_handler(Arc::clone(&agent))),
        Some(geo_handler(Arc::clone(&geo))),
    );
    initializer.initialize_agent_integrations().await.expect("ok");
    assert_eq!(*geo.redis_calls.read(), 0);
    assert_eq!(*geo.agent_calls.read(), 1);
}

#[tokio::test]
async fn initialize_agent_integrations_geo_without_agent_skips_agent_call() {
    let redis = Arc::new(MockRedis::default());
    let geo = MockGeoIpHandler::with_mapping(&[]);
    let initializer = HandlerInitializer::new(
        config(),
        Some(redis_handler(Arc::clone(&redis))),
        None,
        Some(geo_handler(Arc::clone(&geo))),
    );
    initializer.initialize_agent_integrations().await.expect("ok");
    assert_eq!(*geo.redis_calls.read(), 1);
    assert_eq!(*geo.agent_calls.read(), 0);
}

#[tokio::test]
async fn initialize_agent_integrations_noop_when_no_handlers() {
    let initializer = HandlerInitializer::new(config(), None, None, None);
    initializer
        .initialize_agent_integrations()
        .await
        .expect("ok");
}
