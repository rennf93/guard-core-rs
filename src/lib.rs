#![doc = include_str!("../README.md")]

/// Error types and result alias used across the crate.
///
/// See [`crate::error::GuardCoreError`] for the top-level enum and
/// [`crate::error::Result`] for the crate-wide [`std::result::Result`] alias.
pub mod error;

/// Configuration and data model types consumed by all security components.
///
/// The central type is [`crate::models::SecurityConfig`]; use
/// [`crate::models::SecurityConfigBuilder`] to construct validated
/// configurations. Dynamic rule payloads fetched from the agent are modelled
/// by [`crate::models::DynamicRules`].
pub mod models;

/// Framework-agnostic protocol traits that adapters implement.
///
/// Every framework adapter (`fastapi-guard`, `flaskapi-guard`, `djapi-guard`)
/// implements these traits to plug its native request/response objects into
/// Guard Core. See [`crate::protocols::request::GuardRequest`],
/// [`crate::protocols::response::GuardResponse`], and
/// [`crate::protocols::middleware::GuardMiddlewareProtocol`].
pub mod protocols;

/// Shared utilities for IP extraction, proxy validation, logging, and event
/// dispatch used by every check and handler.
pub mod utils;

/// Core architecture modules that compose the request pipeline.
///
/// Sub-modules include [`crate::core::checks`] (the
/// [`crate::core::checks::SecurityCheckPipeline`] and its
/// [`crate::core::checks::SecurityCheck`] implementations),
/// [`crate::core::responses`], [`crate::core::routing`],
/// [`crate::core::validation`], [`crate::core::bypass`],
/// [`crate::core::behavioral`], [`crate::core::events`], and
/// [`crate::core::initialization`].
pub mod core;

/// Route-level security decorators used to attach per-endpoint policies.
///
/// The primary entry point is [`crate::decorators::SecurityDecorator`], which
/// stores [`crate::decorators::RouteConfig`] entries keyed by route identifier.
pub mod decorators;

/// Pattern-based detection engine: regex compilation, content preprocessing,
/// semantic analysis, and performance monitoring.
pub mod detection_engine;

/// Handlers that own stateful resources: Redis, rate-limiting, IP banning,
/// GeoIP, cloud-provider IP ranges, behavioral tracking, and headers.
pub mod handlers;

/// Embedded scripts evaluated by external systems (Redis Lua scripts, etc.).
pub mod scripts;

pub use decorators::{RouteConfig, SecurityDecorator};
pub use error::{GuardCoreError, GuardRedisError, Result};
pub use models::{DynamicRules, SecurityConfig};
