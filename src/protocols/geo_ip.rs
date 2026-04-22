//! GeoIP protocol used to look up the country code for a client IP.
//!
//! [`crate::protocols::geo_ip::GeoIpHandler`] is the abstract interface the
//! IP-country policies depend on. The default implementation is
//! [`crate::handlers::IPInfoManager`] when the `geoip` feature is enabled.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;

/// Type alias for a shared
/// [`crate::protocols::geo_ip::GeoIpHandler`] implementation.
pub type DynGeoIpHandler = Arc<dyn GeoIpHandler>;

/// Interface providing country lookups for a client IP address.
///
/// Implementations typically wrap a MaxMind-compatible database and may
/// optionally share it through Redis for cross-instance caching.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::protocols::geo_ip::GeoIpHandler;
///
/// fn country_of(handler: Arc<dyn GeoIpHandler>, ip: &str) -> Option<String> {
///     handler.get_country(ip)
/// }
/// ```
#[async_trait]
pub trait GeoIpHandler: Send + Sync + std::fmt::Debug {
    /// Returns `true` once the backing database has been loaded.
    fn is_initialized(&self) -> bool;

    /// Loads the backing database, downloading it if necessary.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::GeoIp`] when loading or
    /// downloading fails.
    async fn initialize(&self) -> Result<()>;

    /// Wires in a [`crate::protocols::redis::DynRedisHandler`] for cache
    /// sharing.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] or
    /// [`crate::error::GuardCoreError::GeoIp`] on initialization failure.
    async fn initialize_redis(&self, redis_handler: DynRedisHandler) -> Result<()>;

    /// Wires in a [`crate::protocols::agent::DynAgentHandler`] for event
    /// forwarding.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] on initialization
    /// failure.
    async fn initialize_agent(&self, agent_handler: DynAgentHandler) -> Result<()>;

    /// Returns the ISO 3166-1 alpha-2 country code for `ip` when known.
    fn get_country(&self, ip: &str) -> Option<String>;
}
