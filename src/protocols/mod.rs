//! Framework-agnostic protocol traits implemented by Guard adapters.
//!
//! Each sub-module defines one abstract boundary between Guard Core and the
//! outside world:
//!
//! - [`crate::protocols::request`] and [`crate::protocols::response`] wrap
//!   framework-native request/response types.
//! - [`crate::protocols::middleware`] is the engine interface each adapter
//!   exposes to the pipeline.
//! - [`crate::protocols::redis`], [`crate::protocols::geo_ip`], and
//!   [`crate::protocols::agent`] describe optional external integrations.

pub mod agent;
pub mod geo_ip;
pub mod middleware;
pub mod redis;
pub mod request;
pub mod response;

pub use agent::{AgentHandlerProtocol, DynAgentHandler};
pub use geo_ip::{DynGeoIpHandler, GeoIpHandler};
pub use middleware::{DynGuardMiddleware, GuardMiddlewareProtocol};
pub use redis::{DynRedisHandler, RedisHandlerProtocol};
pub use request::{DynGuardRequest, GuardRequest, RequestState, StateValue};
pub use response::{
    DynGuardResponse, DynGuardResponseFactory, GuardResponse, GuardResponseFactory,
};
