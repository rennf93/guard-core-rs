//! Coordinated bootstrap of Redis, Agent, and GeoIP handlers.

use std::sync::Arc;

use crate::error::Result;
use crate::models::SecurityConfig;
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::geo_ip::DynGeoIpHandler;
use crate::protocols::redis::DynRedisHandler;

/// Orchestrates handler initialisation for the middleware.
///
/// Adapters construct a
/// [`crate::core::initialization::handler_initializer::HandlerInitializer`]
/// with every handler they know about and invoke the initialise methods
/// during middleware setup.
#[derive(Clone)]
pub struct HandlerInitializer {
    /// Shared security configuration.
    pub config: Arc<SecurityConfig>,
    /// Optional Redis handler.
    pub redis_handler: Option<DynRedisHandler>,
    /// Optional Guard Agent handler.
    pub agent_handler: Option<DynAgentHandler>,
    /// Optional GeoIP handler.
    pub geo_ip_handler: Option<DynGeoIpHandler>,
}

impl std::fmt::Debug for HandlerInitializer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerInitializer").finish_non_exhaustive()
    }
}

impl HandlerInitializer {
    /// Creates a new initialiser holding the supplied handlers.
    pub const fn new(
        config: Arc<SecurityConfig>,
        redis_handler: Option<DynRedisHandler>,
        agent_handler: Option<DynAgentHandler>,
        geo_ip_handler: Option<DynGeoIpHandler>,
    ) -> Self {
        Self { config, redis_handler, agent_handler, geo_ip_handler }
    }

    /// Initialises the Redis handler, if present.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when the Redis
    /// handler's
    /// [`crate::protocols::redis::RedisHandlerProtocol::initialize`] fails.
    pub async fn initialize_redis_handlers(&self) -> Result<()> {
        if let Some(redis) = &self.redis_handler {
            redis.initialize().await?;
        }
        Ok(())
    }

    /// Wires Agent → Redis and GeoIP → Redis/Agent links, depending on which
    /// handlers are present.
    ///
    /// # Errors
    ///
    /// Returns the first [`crate::error::GuardCoreError`] produced by any of
    /// the underlying initialisation calls.
    pub async fn initialize_agent_integrations(&self) -> Result<()> {
        if let (Some(agent), Some(redis)) = (&self.agent_handler, &self.redis_handler) {
            agent.initialize_redis(redis.clone()).await?;
        }
        if let Some(geo) = &self.geo_ip_handler {
            if let Some(redis) = &self.redis_handler {
                geo.initialize_redis(redis.clone()).await?;
            }
            if let Some(agent) = &self.agent_handler {
                geo.initialize_agent(agent.clone()).await?;
            }
        }
        Ok(())
    }
}
