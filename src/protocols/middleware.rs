//! Middleware protocol connecting Guard Core to each framework adapter.
//!
//! [`crate::protocols::middleware::GuardMiddlewareProtocol`] is the engine
//! interface the adapter exposes to the pipeline. It provides access to
//! configuration, component handlers, and factory helpers the checks need in
//! order to inspect requests and emit responses.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::models::SecurityConfig;
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::geo_ip::DynGeoIpHandler;
use crate::protocols::redis::DynRedisHandler;
use crate::protocols::response::{DynGuardResponse, DynGuardResponseFactory};

/// Type alias for a shared
/// [`crate::protocols::middleware::GuardMiddlewareProtocol`] implementation.
pub type DynGuardMiddleware = Arc<dyn GuardMiddlewareProtocol>;

/// Interface connecting the Guard Core pipeline to its host middleware.
///
/// Adapters implement this trait on their middleware struct to expose all
/// shared state (config, handlers, event bus, factories) to checks. Every
/// concrete [`crate::core::checks::SecurityCheck`] holds a
/// [`crate::protocols::middleware::DynGuardMiddleware`] to access these
/// resources.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::protocols::middleware::GuardMiddlewareProtocol;
///
/// fn describe_limit(middleware: Arc<dyn GuardMiddlewareProtocol>) -> u32 {
///     middleware.config().rate_limit
/// }
/// ```
#[async_trait]
pub trait GuardMiddlewareProtocol: Send + Sync {
    /// Returns the shared [`crate::models::SecurityConfig`].
    fn config(&self) -> Arc<SecurityConfig>;

    /// Returns the epoch-seconds timestamp of the last cloud IP refresh.
    fn last_cloud_ip_refresh(&self) -> i64;
    /// Updates the last cloud IP refresh timestamp.
    fn set_last_cloud_ip_refresh(&self, ts: i64);

    /// Returns the per-IP suspicious request counters used for auto-banning.
    fn suspicious_request_counts(&self) -> Arc<dashmap::DashMap<String, u64>>;

    /// Returns the event bus as an opaque
    /// [`std::any::Any`] handle; concrete adapters downcast to their type.
    fn event_bus(&self) -> Arc<dyn std::any::Any + Send + Sync>;
    /// Returns the route resolver as an opaque
    /// [`std::any::Any`] handle.
    fn route_resolver(&self) -> Arc<dyn std::any::Any + Send + Sync>;
    /// Returns the response factory as an opaque
    /// [`std::any::Any`] handle.
    fn response_factory(&self) -> Arc<dyn std::any::Any + Send + Sync>;
    /// Returns the rate-limit handler as an opaque
    /// [`std::any::Any`] handle.
    fn rate_limit_handler(&self) -> Arc<dyn std::any::Any + Send + Sync>;
    /// Returns the optional agent handler.
    fn agent_handler(&self) -> Option<DynAgentHandler>;
    /// Returns the optional GeoIP handler.
    fn geo_ip_handler(&self) -> Option<DynGeoIpHandler>;
    /// Returns the optional Redis handler.
    fn redis_handler(&self) -> Option<DynRedisHandler>;
    /// Returns the
    /// [`crate::protocols::response::GuardResponseFactory`] used to
    /// build concrete response objects.
    fn guard_response_factory(&self) -> DynGuardResponseFactory;

    /// Builds an error response with the given status code and default
    /// message.
    ///
    /// # Errors
    ///
    /// Returns any error propagated by the underlying response factory.
    async fn create_error_response(
        &self,
        status_code: u16,
        default_message: &str,
    ) -> Result<DynGuardResponse>;

    /// Refreshes the cloud provider IP ranges used by the cloud-provider check.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::CloudProvider`] when fetching
    /// any provider's IP range list fails.
    async fn refresh_cloud_ip_ranges(&self) -> Result<()>;
}
