//! Redis protocol defining the operations Guard Core expects from the backing
//! cache.
//!
//! [`crate::protocols::redis::RedisHandlerProtocol`] is implemented by
//! concrete handlers (such as [`crate::handlers::RedisManager`] when the
//! `redis-support` feature is enabled). Every operation is namespaced so the
//! handler can compose a Redis key from the shared prefix, namespace, and
//! user-supplied key segment.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;

/// Type alias for a shared
/// [`crate::protocols::redis::RedisHandlerProtocol`] implementation.
pub type DynRedisHandler = Arc<dyn RedisHandlerProtocol>;

/// Interface every Redis-like cache must implement to back distributed state.
///
/// Namespaces are prepended to every key so multiple Guard Core features can
/// share the same Redis instance without collisions.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::protocols::redis::RedisHandlerProtocol;
///
/// async fn ban(handler: Arc<dyn RedisHandlerProtocol>, ip: &str) {
///     let _ = handler.set_key("banned_ips", ip, serde_json::json!("1"), Some(3600)).await;
/// }
/// ```
#[async_trait]
pub trait RedisHandlerProtocol: Send + Sync + std::fmt::Debug {
    /// Fetches the value at `namespace:key`, or [`None`] when absent.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on connection or
    /// serialisation failure.
    async fn get_key(&self, namespace: &str, key: &str) -> Result<Option<Value>>;

    /// Stores `value` at `namespace:key` with an optional TTL in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on connection or
    /// command failure.
    async fn set_key(
        &self,
        namespace: &str,
        key: &str,
        value: Value,
        ttl: Option<u64>,
    ) -> Result<bool>;

    /// Deletes the entry at `namespace:key`, returning the number of keys
    /// removed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on command failure.
    async fn delete(&self, namespace: &str, key: &str) -> Result<u64>;

    /// Returns all keys matching the glob `pattern`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on command failure.
    async fn keys(&self, pattern: &str) -> Result<Vec<String>>;

    /// Establishes and verifies the connection to the backing Redis instance.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when the connection
    /// cannot be established.
    async fn initialize(&self) -> Result<()>;

    /// Atomically increments the counter at `namespace:key` by `amount`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on command failure.
    async fn incr(&self, namespace: &str, key: &str, amount: i64) -> Result<i64>;

    /// Sets an expiry in seconds on `namespace:key`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on command failure.
    async fn expire(&self, namespace: &str, key: &str, ttl: u64) -> Result<bool>;

    /// Runs the provided Lua `script` against Redis with the given keys and
    /// arguments, returning the decoded reply.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on evaluation failure.
    async fn run_script(&self, script: &str, keys: Vec<String>, args: Vec<String>) -> Result<Value>;

    /// Closes the underlying connection and marks the handler as shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on disconnect failure.
    async fn close(&self) -> Result<()>;
}
