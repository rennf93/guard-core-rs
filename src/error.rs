//! Error types and result alias used across the crate.
//!
//! The top-level enum is [`crate::error::GuardCoreError`]; the crate-wide
//! result alias is [`crate::error::Result`]. Redis-specific failures are
//! represented by [`crate::error::GuardRedisError`] and flow into
//! [`crate::error::GuardCoreError::Redis`] via a blanket [`From`] impl.

use std::fmt;

use thiserror::Error;

/// Crate-wide result alias parameterised by [`crate::error::GuardCoreError`].
///
/// Every fallible API in `guard-core-rs` returns `Result<T>`.
pub type Result<T> = std::result::Result<T, GuardCoreError>;

/// Top-level error enum returned by every fallible Guard Core operation.
///
/// Variants wrap the underlying crate errors that Guard Core depends on
/// ([`regex::Error`], [`std::io::Error`], [`reqwest::Error`],
/// [`serde_json::Error`]) as well as domain-specific failures (configuration,
/// validation, cloud provider, rate limiting, etc.).
#[derive(Debug, Error)]
pub enum GuardCoreError {
    /// Redis error originating from the handler layer; see
    /// [`crate::error::GuardRedisError`].
    #[error(transparent)]
    Redis(#[from] GuardRedisError),

    /// A required configuration value is missing or malformed.
    #[error("configuration error: {0}")]
    Config(String),

    /// A runtime validation check failed (invalid IP, invalid threshold, etc.).
    #[error("validation error: {0}")]
    Validation(String),

    /// A regex pattern could not be compiled by the detection engine.
    #[error("pattern compilation error: {0}")]
    Pattern(#[from] regex::Error),

    /// A regex pattern is considered unsafe (ReDoS risk) and was rejected.
    #[error("pattern is unsafe: {0}")]
    UnsafePattern(String),

    /// Pattern execution exceeded the configured timeout.
    #[error("pattern execution timed out after {0:?}")]
    PatternTimeout(std::time::Duration),

    /// An I/O error was raised while reading or writing a local resource.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An outbound HTTP call failed.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON parsing or serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A supplied IP address or CIDR literal is invalid.
    #[error("invalid ip or cidr: {0}")]
    InvalidIp(String),

    /// The GeoIP database lookup failed or the database could not be opened.
    #[error("geo ip lookup error: {0}")]
    GeoIp(String),

    /// Fetching cloud provider IP ranges failed.
    #[error("cloud provider fetch error: {0}")]
    CloudProvider(String),

    /// Rate limiting backend returned an error.
    #[error("rate limit error: {0}")]
    RateLimit(String),

    /// A behavioral rule violated an invariant.
    #[error("behavior rule error: {0}")]
    Behavior(String),

    /// The Guard Agent integration returned an error.
    #[error("agent handler error: {0}")]
    Agent(String),

    /// Prompt injection content was detected.
    #[error("prompt injection detected: {0}")]
    PromptInjection(String),

    /// A component was invoked before being initialized.
    #[error("not initialized: {0}")]
    NotInitialized(String),

    /// Catch-all variant for errors that do not fit any of the specific cases.
    #[error("{0}")]
    Other(String),
}

/// Redis-layer error with an HTTP-style status code and a detail message.
///
/// Converted into [`crate::error::GuardCoreError::Redis`] via
/// `#[from]`. Construct with [`crate::error::GuardRedisError::new`].
#[derive(Debug, Error)]
pub struct GuardRedisError {
    /// HTTP-style status code that best classifies the failure.
    pub status_code: u16,
    /// Human-readable detail message describing the failure.
    pub detail: String,
}

impl GuardRedisError {
    /// Builds a new [`crate::error::GuardRedisError`] from a status code and
    /// any value convertible into [`String`].
    pub fn new(status_code: u16, detail: impl Into<String>) -> Self {
        Self { status_code, detail: detail.into() }
    }
}

impl fmt::Display for GuardRedisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.detail)
    }
}

#[cfg(feature = "redis-support")]
impl From<redis::RedisError> for GuardCoreError {
    fn from(err: redis::RedisError) -> Self {
        Self::Redis(GuardRedisError::new(500, err.to_string()))
    }
}
