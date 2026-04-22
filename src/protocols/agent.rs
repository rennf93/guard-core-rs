//! Agent protocol used to forward events, metrics, and fetch dynamic rules
//! from the Guard Agent service.
//!
//! [`crate::protocols::agent::AgentHandlerProtocol`] is the boundary between
//! Guard Core and the outbound telemetry pipeline. Adapters that enable the
//! `agent` feature provide an implementation that batches events and polls
//! for [`crate::models::DynamicRules`] updates.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;
use crate::models::DynamicRules;
use crate::protocols::redis::DynRedisHandler;

/// Type alias for a shared
/// [`crate::protocols::agent::AgentHandlerProtocol`] implementation.
pub type DynAgentHandler = Arc<dyn AgentHandlerProtocol>;

/// Interface that batches events/metrics to the Guard Agent and fetches
/// dynamic rules.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::protocols::agent::AgentHandlerProtocol;
///
/// async fn flush(handler: Arc<dyn AgentHandlerProtocol>) {
///     let _ = handler.flush_buffer().await;
/// }
/// ```
#[async_trait]
pub trait AgentHandlerProtocol: Send + Sync + std::fmt::Debug {
    /// Wires in a [`crate::protocols::redis::DynRedisHandler`] for cross-node
    /// event deduplication.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on initialization
    /// failure.
    async fn initialize_redis(&self, redis_handler: DynRedisHandler) -> Result<()>;

    /// Buffers a security event for eventual delivery.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] when the event cannot
    /// be enqueued.
    async fn send_event(&self, event: Value) -> Result<()>;

    /// Buffers a metric for eventual delivery.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] when the metric cannot
    /// be enqueued.
    async fn send_metric(&self, metric: Value) -> Result<()>;

    /// Starts the background flush/poll tasks.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] if the tasks cannot be
    /// started.
    async fn start(&self) -> Result<()>;

    /// Stops the background tasks and drains buffers.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] on shutdown failure.
    async fn stop(&self) -> Result<()>;

    /// Forces an immediate flush of buffered events and metrics.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] on flush failure.
    async fn flush_buffer(&self) -> Result<()>;

    /// Fetches the latest [`crate::models::DynamicRules`] payload, if
    /// available.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] on network or parsing
    /// failure.
    async fn get_dynamic_rules(&self) -> Result<Option<DynamicRules>>;

    /// Returns `Ok(true)` when the agent service is reachable and healthy.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Agent`] when the health check
    /// request itself fails.
    async fn health_check(&self) -> Result<bool>;
}
