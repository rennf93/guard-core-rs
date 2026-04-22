//! Stateful managers that back the security pipeline.
//!
//! Each sub-module owns a specific concern:
//!
//! - [`crate::handlers::behavior`] tracks usage/return/frequency rules.
//! - [`crate::handlers::cloud`] refreshes cloud-provider IP ranges
//!   (feature `cloud-providers`).
//! - [`crate::handlers::dynamic_rule`] polls the agent for
//!   [`crate::models::DynamicRules`].
//! - [`crate::handlers::ipban`] records banned IPs.
//! - [`crate::handlers::ipinfo`] exposes GeoIP lookups (feature `geoip`).
//! - [`crate::handlers::ratelimit`] enforces per-IP and per-endpoint limits.
//! - [`crate::handlers::redis`] wraps a Redis connection pool (feature
//!   `redis-support`).
//! - [`crate::handlers::security_headers`] assembles default and
//!   custom security headers.
//! - [`crate::handlers::suspatterns`] runs the regex + semantic threat
//!   detection.

pub mod behavior;
#[cfg(feature = "cloud-providers")]
pub mod cloud;
pub mod dynamic_rule;
pub mod ipban;
#[cfg(feature = "geoip")]
pub mod ipinfo;
pub mod ratelimit;
#[cfg(feature = "redis-support")]
pub mod redis;
pub mod security_headers;
pub mod suspatterns;

pub use behavior::{BehaviorAction, BehaviorRule, BehaviorRuleType, BehaviorTracker};
#[cfg(feature = "cloud-providers")]
pub use cloud::CloudManager;
pub use dynamic_rule::DynamicRuleManager;
pub use ipban::IPBanManager;
#[cfg(feature = "geoip")]
pub use ipinfo::IPInfoManager;
pub use ratelimit::{CheckRateLimitArgs, CreateErrorResponseFn, RateLimitManager};
#[cfg(feature = "redis-support")]
pub use redis::RedisManager;
pub use security_headers::{ConfigureOptions, PermissionsPolicySetting, SecurityHeadersManager};
