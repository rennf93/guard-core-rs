//! Configuration and data-model types used across the security engine.
//!
//! The primary types are [`crate::models::SecurityConfig`] (runtime
//! configuration) and [`crate::models::DynamicRules`] (rule payload fetched
//! from the agent). Use [`crate::models::SecurityConfigBuilder`] to construct
//! validated [`crate::models::SecurityConfig`] instances.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::{GuardCoreError, Result};
use crate::protocols::geo_ip::DynGeoIpHandler;

/// Severity level used when writing security-related log records.
///
/// Maps onto `tracing` levels in [`crate::utils::log_at_level`].
/// The default value is [`LogLevel::Warning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[derive(Default)]
pub enum LogLevel {
    /// Informational messages about routine activity.
    Info,
    /// Fine-grained messages used during development or troubleshooting.
    Debug,
    /// Default level for suspicious-but-not-fatal activity.
    #[default]
    Warning,
    /// Recoverable errors that still allow processing to continue.
    Error,
    /// Unrecoverable errors where the request must be rejected.
    Critical,
}


/// Wire format selected for log output.
///
/// Defaults to [`LogFormat::Text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogFormat {
    /// Human-readable single-line text.
    #[default]
    Text,
    /// Newline-delimited JSON suitable for log aggregators.
    Json,
}


/// Identifier for a public cloud provider whose IP ranges may be blocked.
///
/// Used by [`SecurityConfig::block_cloud_providers`] and by the
/// `cloud_provider` check to match a client IP against known ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "PascalCase")]
pub enum CloudProvider {
    /// Amazon Web Services IP ranges.
    #[serde(rename = "AWS")]
    Aws,
    /// Google Cloud Platform IP ranges.
    #[serde(rename = "GCP")]
    Gcp,
    /// Microsoft Azure IP ranges.
    Azure,
}

impl CloudProvider {
    /// Parses a cloud provider name with loose, case-insensitive matching.
    ///
    /// Returns [`None`] if the string does not correspond to a known provider.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim() {
            "AWS" | "aws" | "Aws" => Some(Self::Aws),
            "GCP" | "gcp" | "Gcp" => Some(Self::Gcp),
            "Azure" | "azure" | "AZURE" => Some(Self::Azure),
            _ => None,
        }
    }

    /// Returns the canonical uppercase label for the provider.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aws => "AWS",
            Self::Gcp => "GCP",
            Self::Azure => "Azure",
        }
    }
}

/// Parameters for the `Strict-Transport-Security` (HSTS) response header.
///
/// Controls the three HSTS directives: `max-age`, `includeSubDomains`, and
/// `preload`. See [`SecurityHeadersConfig::hsts`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsConfig {
    /// HSTS `max-age` in seconds. Defaults to one year.
    #[serde(default = "default_hsts_max_age")]
    pub max_age: u32,
    /// Whether to include the `includeSubDomains` directive. Defaults to `true`.
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    /// Whether to emit the `preload` directive. Defaults to `false`.
    #[serde(default)]
    pub preload: bool,
}

fn default_hsts_max_age() -> u32 {
    31_536_000
}
fn default_true() -> bool {
    true
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self { max_age: default_hsts_max_age(), include_subdomains: true, preload: false }
    }
}

/// Configuration for the security headers applied to every response.
///
/// Consumed by [`crate::core::responses::factory::ErrorResponseFactory`] when
/// `enabled` is `true`. Individual directives map directly to their HTTP
/// response headers. Use [`SecurityHeadersConfig::default`] for sensible,
/// strict defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    /// Master switch for header application. When `false` no headers are set.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `Strict-Transport-Security` configuration.
    #[serde(default)]
    pub hsts: HstsConfig,
    /// Optional `Content-Security-Policy` directive string.
    #[serde(default)]
    pub csp: Option<String>,
    /// Value for the `X-Frame-Options` header.
    #[serde(default = "default_frame_options")]
    pub frame_options: String,
    /// Value for the `X-Content-Type-Options` header.
    #[serde(default = "default_content_type_options")]
    pub content_type_options: String,
    /// Value for the legacy `X-XSS-Protection` header.
    #[serde(default = "default_xss_protection")]
    pub xss_protection: String,
    /// Value for the `Referrer-Policy` header.
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: String,
    /// Value for the `Permissions-Policy` header.
    #[serde(default = "default_permissions_policy")]
    pub permissions_policy: String,
    /// Additional custom headers applied verbatim after the known directives.
    #[serde(default)]
    pub custom: Option<HashMap<String, String>>,
}

fn default_frame_options() -> String {
    "SAMEORIGIN".into()
}
fn default_content_type_options() -> String {
    "nosniff".into()
}
fn default_xss_protection() -> String {
    "1; mode=block".into()
}
fn default_referrer_policy() -> String {
    "strict-origin-when-cross-origin".into()
}
fn default_permissions_policy() -> String {
    "geolocation=(), microphone=(), camera=()".into()
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hsts: HstsConfig::default(),
            csp: None,
            frame_options: default_frame_options(),
            content_type_options: default_content_type_options(),
            xss_protection: default_xss_protection(),
            referrer_policy: default_referrer_policy(),
            permissions_policy: default_permissions_policy(),
            custom: None,
        }
    }
}

/// Configuration for the optional Guard Agent integration.
///
/// Built by [`SecurityConfig::to_agent_config`] when the agent is enabled.
/// Adapters forward this struct to `guard-agent` for telemetry, dynamic
/// rules, and event streaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// API key used to authenticate with the Guard Agent endpoint.
    pub api_key: String,
    /// Base URL of the Guard Agent endpoint.
    #[serde(default = "default_agent_endpoint")]
    pub endpoint: String,
    /// Optional project identifier used for multi-tenant routing.
    pub project_id: Option<String>,
    /// Maximum number of buffered events before a forced flush.
    #[serde(default = "default_agent_buffer")]
    pub buffer_size: u32,
    /// Interval in seconds between periodic buffer flushes.
    #[serde(default = "default_agent_flush")]
    pub flush_interval: u32,
    /// Whether security events are forwarded to the agent.
    #[serde(default = "default_true")]
    pub enable_events: bool,
    /// Whether request metrics are forwarded to the agent.
    #[serde(default = "default_true")]
    pub enable_metrics: bool,
    /// HTTP timeout in seconds for agent requests.
    #[serde(default = "default_agent_timeout")]
    pub timeout: u32,
    /// Number of retry attempts for transient agent failures.
    #[serde(default = "default_agent_retries")]
    pub retry_attempts: u32,
}

fn default_agent_endpoint() -> String {
    "https://api.fastapi-guard.com".into()
}
fn default_agent_buffer() -> u32 {
    100
}
fn default_agent_flush() -> u32 {
    30
}
fn default_agent_timeout() -> u32 {
    30
}
fn default_agent_retries() -> u32 {
    3
}

/// Runtime configuration for the security engine.
///
/// Construct via [`crate::models::SecurityConfig::builder`] or
/// [`crate::models::SecurityConfigBuilder::build`]; the builder sets sensible
/// defaults and runs [`crate::models::SecurityConfig::validate`] before
/// producing a config. Fields are intentionally public so adapters can
/// assemble configs directly when a builder is insufficient.
///
/// # Examples
///
/// ```no_run
/// use guard_core_rs::models::SecurityConfig;
///
/// let config = SecurityConfig::builder()
///     .rate_limit(100)
///     .rate_limit_window(60)
///     .enforce_https(true)
///     .build()
///     .expect("valid config");
/// ```
#[derive(Clone, Default)]
pub struct SecurityConfig {
    /// Trusted proxy IPs or CIDR ranges for `X-Forwarded-For` parsing.
    pub trusted_proxies: Vec<String>,
    /// Expected depth of the `X-Forwarded-For` chain (minimum 1).
    pub trusted_proxy_depth: u32,
    /// Whether to honour `X-Forwarded-Proto` for HTTPS detection.
    pub trust_x_forwarded_proto: bool,

    /// Log-only mode. When `true`, checks emit events but never block.
    pub passive_mode: bool,

    /// Optional GeoIP handler used for country-based policies.
    pub geo_ip_handler: Option<DynGeoIpHandler>,

    /// Master switch for Redis-backed distributed state.
    pub enable_redis: bool,
    /// Redis connection URL, e.g. `redis://localhost:6379`.
    pub redis_url: Option<String>,
    /// Key prefix applied to every Redis entry written by Guard Core.
    pub redis_prefix: String,

    /// Optional IP whitelist. `None` means no whitelist is enforced.
    pub whitelist: Option<Vec<String>>,
    /// IP blacklist applied globally.
    pub blacklist: Vec<String>,

    /// ISO 3166-1 alpha-2 codes permitted unconditionally.
    pub whitelist_countries: Vec<String>,
    /// ISO 3166-1 alpha-2 codes rejected unconditionally.
    pub blocked_countries: Vec<String>,

    /// Regex patterns (case-insensitive) matched against the `User-Agent`.
    pub blocked_user_agents: Vec<String>,

    /// Number of suspicious requests before auto-banning the IP.
    pub auto_ban_threshold: u32,
    /// Auto-ban duration in seconds.
    pub auto_ban_duration: u64,

    /// Optional path for a dedicated security log file.
    pub custom_log_file: Option<String>,
    /// Log level for suspicious-activity events.
    pub log_suspicious_level: Option<LogLevel>,
    /// Log level for request-logging events.
    pub log_request_level: Option<LogLevel>,
    /// Log output format.
    pub log_format: LogFormat,

    /// Map of HTTP status code → custom error body.
    pub custom_error_responses: HashMap<u16, String>,

    /// Global rate-limit threshold (requests per window).
    pub rate_limit: u32,
    /// Global rate-limit window in seconds.
    pub rate_limit_window: u64,

    /// Force HTTPS by rejecting plain-HTTP requests.
    pub enforce_https: bool,

    /// Optional security headers applied to responses.
    pub security_headers: Option<SecurityHeadersConfig>,

    /// Callback executed for every request before other checks.
    pub custom_request_check: Option<CustomRequestCheck>,
    /// Callback that may post-process any outgoing response.
    pub custom_response_modifier: Option<CustomResponseModifier>,

    /// Master switch for CORS processing.
    pub enable_cors: bool,
    /// Origins permitted by CORS.
    pub cors_allow_origins: Vec<String>,
    /// Methods permitted by CORS.
    pub cors_allow_methods: Vec<String>,
    /// Request headers permitted by CORS.
    pub cors_allow_headers: Vec<String>,
    /// Whether CORS credentials are allowed.
    pub cors_allow_credentials: bool,
    /// Response headers exposed to browser scripts.
    pub cors_expose_headers: Vec<String>,
    /// `Access-Control-Max-Age` value in seconds.
    pub cors_max_age: u32,

    /// Cloud providers whose IP ranges are blocked (optional).
    pub block_cloud_providers: Option<HashSet<CloudProvider>>,
    /// Seconds between cloud IP-range refreshes (60-86400).
    pub cloud_ip_refresh_interval: u64,

    /// Paths that bypass the security pipeline entirely.
    pub exclude_paths: Vec<String>,

    /// Master switch for IP banning.
    pub enable_ip_banning: bool,
    /// Master switch for rate limiting.
    pub enable_rate_limiting: bool,
    /// Master switch for penetration/suspicious-pattern detection.
    pub enable_penetration_detection: bool,

    /// Optional IPInfo API token for GeoIP lookups.
    pub ipinfo_token: Option<String>,
    /// Path to a local IPInfo MaxMind-compatible database.
    pub ipinfo_db_path: Option<PathBuf>,

    /// Enables the Guard Agent integration.
    pub enable_agent: bool,
    /// API key for the Guard Agent.
    pub agent_api_key: Option<String>,
    /// Guard Agent endpoint URL.
    pub agent_endpoint: String,
    /// Optional Guard Agent project identifier.
    pub agent_project_id: Option<String>,
    /// Event buffer size before flush.
    pub agent_buffer_size: u32,
    /// Seconds between periodic agent flushes.
    pub agent_flush_interval: u32,
    /// Forward events to the agent.
    pub agent_enable_events: bool,
    /// Forward metrics to the agent.
    pub agent_enable_metrics: bool,
    /// Agent HTTP timeout in seconds.
    pub agent_timeout: u32,
    /// Agent retry attempts for transient failures.
    pub agent_retry_attempts: u32,

    /// Master switch for dynamic-rule fetching (requires agent).
    pub enable_dynamic_rules: bool,
    /// Seconds between dynamic-rule refreshes.
    pub dynamic_rule_interval: u64,
    /// Emergency mode short-circuits to whitelist-only access.
    pub emergency_mode: bool,
    /// IPs permitted while [`SecurityConfig::emergency_mode`] is active.
    pub emergency_whitelist: Vec<String>,
    /// Per-endpoint rate limits: `endpoint` → `(limit, window_secs)`.
    pub endpoint_rate_limits: HashMap<String, (u32, u64)>,

    /// Detection pattern compile timeout (0.1-10.0 seconds).
    pub detection_compiler_timeout: f64,
    /// Maximum content length fed into the detection engine.
    pub detection_max_content_length: usize,
    /// Preserve attack regions when truncating large bodies.
    pub detection_preserve_attack_patterns: bool,
    /// Semantic threat-score threshold (0.0-1.0).
    pub detection_semantic_threshold: f64,
    /// Z-score cut-off for statistical anomalies (1.0-10.0).
    pub detection_anomaly_threshold: f64,
    /// Slow-pattern threshold in seconds (0.01-1.0).
    pub detection_slow_pattern_threshold: f64,
    /// Sliding-window size for pattern performance monitoring.
    pub detection_monitor_history_size: usize,
    /// Maximum number of tracked patterns in the monitor.
    pub detection_max_tracked_patterns: usize,
}

/// Async function signature used by the `custom_request_check` pipeline hook.
///
/// Receives the incoming [`crate::protocols::request::GuardRequest`] and
/// optionally returns a short-circuit
/// [`crate::protocols::response::GuardResponse`].
pub type CustomRequestCheckFn = dyn Fn(
        Arc<dyn crate::protocols::request::GuardRequest>,
    ) -> futures::future::BoxFuture<'static, Option<Arc<dyn crate::protocols::response::GuardResponse>>>
    + Send
    + Sync;

/// Async function signature used to post-process outgoing responses.
///
/// Receives the pipeline-produced [`crate::protocols::response::GuardResponse`]
/// and returns the possibly-modified replacement.
pub type CustomResponseModifierFn = dyn Fn(
        Arc<dyn crate::protocols::response::GuardResponse>,
    ) -> futures::future::BoxFuture<'static, Arc<dyn crate::protocols::response::GuardResponse>>
    + Send
    + Sync;

/// Cloneable wrapper around an [`Arc`]-ed
/// [`crate::models::CustomRequestCheckFn`].
#[derive(Clone)]
pub struct CustomRequestCheck(pub Arc<CustomRequestCheckFn>);

impl std::fmt::Debug for CustomRequestCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomRequestCheck").finish()
    }
}

/// Cloneable wrapper around an [`Arc`]-ed
/// [`crate::models::CustomResponseModifierFn`].
#[derive(Clone)]
pub struct CustomResponseModifier(pub Arc<CustomResponseModifierFn>);

impl std::fmt::Debug for CustomResponseModifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomResponseModifier").finish()
    }
}

impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("passive_mode", &self.passive_mode)
            .field("enable_redis", &self.enable_redis)
            .field("redis_prefix", &self.redis_prefix)
            .field("rate_limit", &self.rate_limit)
            .field("rate_limit_window", &self.rate_limit_window)
            .field("enforce_https", &self.enforce_https)
            .field("blocked_countries", &self.blocked_countries)
            .field("whitelist_countries", &self.whitelist_countries)
            .field("enable_agent", &self.enable_agent)
            .field("emergency_mode", &self.emergency_mode)
            .finish_non_exhaustive()
    }
}

impl SecurityConfig {
    /// Returns a fresh [`crate::models::SecurityConfigBuilder`] with default
    /// values pre-applied.
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::default()
    }

    /// Validates every field and returns [`crate::error::GuardCoreError::Validation`]
    /// on the first invariant violation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Validation`] or
    /// [`crate::error::GuardCoreError::InvalidIp`] when a proxy list, IP list,
    /// range, or numeric threshold is out of bounds.
    pub fn validate(&self) -> Result<()> {
        for entry in &self.trusted_proxies {
            validate_ip_or_cidr(entry).map_err(|_| {
                GuardCoreError::Validation(format!("Invalid proxy IP or CIDR range: {entry}"))
            })?;
        }
        if let Some(wl) = &self.whitelist {
            for entry in wl {
                validate_ip_or_cidr(entry).map_err(|_| {
                    GuardCoreError::Validation(format!("Invalid IP or CIDR range: {entry}"))
                })?;
            }
        }
        for entry in &self.blacklist {
            validate_ip_or_cidr(entry).map_err(|_| {
                GuardCoreError::Validation(format!("Invalid IP or CIDR range: {entry}"))
            })?;
        }
        if self.trusted_proxy_depth < 1 {
            return Err(GuardCoreError::Validation(
                "trusted_proxy_depth must be at least 1".into(),
            ));
        }
        if self.geo_ip_handler.is_none()
            && (!self.blocked_countries.is_empty() || !self.whitelist_countries.is_empty())
            && self.ipinfo_token.is_none()
        {
            return Err(GuardCoreError::Validation(
                "geo_ip_handler is required if blocked_countries or whitelist_countries is set"
                    .into(),
            ));
        }
        if self.enable_agent && self.agent_api_key.is_none() {
            return Err(GuardCoreError::Validation(
                "agent_api_key is required when enable_agent is True".into(),
            ));
        }
        if self.enable_dynamic_rules && !self.enable_agent {
            return Err(GuardCoreError::Validation(
                "enable_agent must be True when enable_dynamic_rules is True".into(),
            ));
        }
        if !(0.1..=10.0).contains(&self.detection_compiler_timeout) {
            return Err(GuardCoreError::Validation(
                "detection_compiler_timeout must be between 0.1 and 10.0".into(),
            ));
        }
        if !(1_000..=100_000).contains(&self.detection_max_content_length) {
            return Err(GuardCoreError::Validation(
                "detection_max_content_length must be between 1000 and 100000".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.detection_semantic_threshold) {
            return Err(GuardCoreError::Validation(
                "detection_semantic_threshold must be between 0.0 and 1.0".into(),
            ));
        }
        if !(1.0..=10.0).contains(&self.detection_anomaly_threshold) {
            return Err(GuardCoreError::Validation(
                "detection_anomaly_threshold must be between 1.0 and 10.0".into(),
            ));
        }
        if !(0.01..=1.0).contains(&self.detection_slow_pattern_threshold) {
            return Err(GuardCoreError::Validation(
                "detection_slow_pattern_threshold must be between 0.01 and 1.0".into(),
            ));
        }
        if !(100..=10_000).contains(&self.detection_monitor_history_size) {
            return Err(GuardCoreError::Validation(
                "detection_monitor_history_size must be between 100 and 10000".into(),
            ));
        }
        if !(100..=5_000).contains(&self.detection_max_tracked_patterns) {
            return Err(GuardCoreError::Validation(
                "detection_max_tracked_patterns must be between 100 and 5000".into(),
            ));
        }
        if !(60..=86_400).contains(&self.cloud_ip_refresh_interval) {
            return Err(GuardCoreError::Validation(
                "cloud_ip_refresh_interval must be between 60 and 86400".into(),
            ));
        }
        Ok(())
    }

    /// Converts this config into a [`crate::models::AgentConfig`] suitable for
    /// the Guard Agent handler, or returns [`None`] when the agent is disabled
    /// or no API key is set.
    pub fn to_agent_config(&self) -> Option<AgentConfig> {
        if !self.enable_agent {
            return None;
        }
        let api_key = self.agent_api_key.clone()?;
        Some(AgentConfig {
            api_key,
            endpoint: self.agent_endpoint.clone(),
            project_id: self.agent_project_id.clone(),
            buffer_size: self.agent_buffer_size,
            flush_interval: self.agent_flush_interval,
            enable_events: self.agent_enable_events,
            enable_metrics: self.agent_enable_metrics,
            timeout: self.agent_timeout,
            retry_attempts: self.agent_retry_attempts,
        })
    }
}

/// Parses an IP address or CIDR block and returns its canonical string form.
///
/// Useful for normalising user-supplied proxy/blacklist/whitelist entries
/// before storing them in [`crate::models::SecurityConfig`].
///
/// # Errors
///
/// Returns [`crate::error::GuardCoreError::InvalidIp`] if `entry` is not a
/// parseable [`std::net::IpAddr`] or [`ipnet::IpNet`] literal.
pub fn validate_ip_or_cidr(entry: &str) -> Result<String> {
    if entry.contains('/') {
        let net: IpNet = entry
            .parse()
            .map_err(|_| GuardCoreError::InvalidIp(entry.to_string()))?;
        Ok(net.to_string())
    } else {
        let ip: std::net::IpAddr = entry
            .parse()
            .map_err(|_| GuardCoreError::InvalidIp(entry.to_string()))?;
        Ok(ip.to_string())
    }
}

/// Fluent builder that assembles a [`crate::models::SecurityConfig`].
///
/// Every field has a sensible default; only the options you call on the
/// builder will deviate from those defaults. [`crate::models::SecurityConfigBuilder::build`]
/// validates the resulting configuration.
///
/// # Examples
///
/// ```no_run
/// use guard_core_rs::models::SecurityConfigBuilder;
///
/// let config = SecurityConfigBuilder::default()
///     .rate_limit(100)
///     .rate_limit_window(60)
///     .enforce_https(true)
///     .build()
///     .expect("valid config");
/// ```
#[derive(Debug, Default, Clone)]
pub struct SecurityConfigBuilder {
    config: SecurityConfigData,
}

#[derive(Debug, Default, Clone)]
struct SecurityConfigData {
    trusted_proxies: Option<Vec<String>>,
    trusted_proxy_depth: Option<u32>,
    trust_x_forwarded_proto: Option<bool>,
    passive_mode: Option<bool>,
    enable_redis: Option<bool>,
    redis_url: Option<Option<String>>,
    redis_prefix: Option<String>,
    whitelist: Option<Option<Vec<String>>>,
    blacklist: Option<Vec<String>>,
    whitelist_countries: Option<Vec<String>>,
    blocked_countries: Option<Vec<String>>,
    blocked_user_agents: Option<Vec<String>>,
    auto_ban_threshold: Option<u32>,
    auto_ban_duration: Option<u64>,
    rate_limit: Option<u32>,
    rate_limit_window: Option<u64>,
    enforce_https: Option<bool>,
    enable_ip_banning: Option<bool>,
    enable_rate_limiting: Option<bool>,
    enable_penetration_detection: Option<bool>,
    enable_agent: Option<bool>,
    agent_api_key: Option<Option<String>>,
    enable_dynamic_rules: Option<bool>,
    block_cloud_providers: Option<Option<HashSet<CloudProvider>>>,
}

impl SecurityConfigBuilder {
    /// Sets the trusted proxy IPs or CIDR ranges used when parsing
    /// `X-Forwarded-For`.
    pub fn trusted_proxies(mut self, v: Vec<String>) -> Self {
        self.config.trusted_proxies = Some(v);
        self
    }
    /// Sets the expected depth of the `X-Forwarded-For` chain (minimum `1`).
    pub fn trusted_proxy_depth(mut self, v: u32) -> Self {
        self.config.trusted_proxy_depth = Some(v);
        self
    }
    /// Sets whether `X-Forwarded-Proto` is trusted for HTTPS detection.
    pub fn trust_x_forwarded_proto(mut self, v: bool) -> Self {
        self.config.trust_x_forwarded_proto = Some(v);
        self
    }
    /// Enables log-only mode; when `true`, checks emit events but never block.
    pub fn passive_mode(mut self, v: bool) -> Self {
        self.config.passive_mode = Some(v);
        self
    }
    /// Master switch for Redis-backed distributed state.
    pub fn enable_redis(mut self, v: bool) -> Self {
        self.config.enable_redis = Some(v);
        self
    }
    /// Redis connection URL (e.g. `redis://localhost:6379`), or `None` to
    /// disable the connection.
    pub fn redis_url(mut self, v: Option<String>) -> Self {
        self.config.redis_url = Some(v);
        self
    }
    /// Key prefix applied to every Redis entry written by Guard Core.
    pub fn redis_prefix(mut self, v: impl Into<String>) -> Self {
        self.config.redis_prefix = Some(v.into());
        self
    }
    /// Sets the optional global IP whitelist. `None` disables the whitelist.
    pub fn whitelist(mut self, v: Option<Vec<String>>) -> Self {
        self.config.whitelist = Some(v);
        self
    }
    /// Sets the global IP blacklist.
    pub fn blacklist(mut self, v: Vec<String>) -> Self {
        self.config.blacklist = Some(v);
        self
    }
    /// Sets the ISO 3166-1 alpha-2 codes allowed unconditionally.
    pub fn whitelist_countries(mut self, v: Vec<String>) -> Self {
        self.config.whitelist_countries = Some(v);
        self
    }
    /// Sets the ISO 3166-1 alpha-2 codes rejected unconditionally.
    pub fn blocked_countries(mut self, v: Vec<String>) -> Self {
        self.config.blocked_countries = Some(v);
        self
    }
    /// Sets the case-insensitive regex patterns applied to the `User-Agent`.
    pub fn blocked_user_agents(mut self, v: Vec<String>) -> Self {
        self.config.blocked_user_agents = Some(v);
        self
    }
    /// Number of suspicious requests tolerated before auto-banning an IP.
    pub fn auto_ban_threshold(mut self, v: u32) -> Self {
        self.config.auto_ban_threshold = Some(v);
        self
    }
    /// Auto-ban duration in seconds.
    pub fn auto_ban_duration(mut self, v: u64) -> Self {
        self.config.auto_ban_duration = Some(v);
        self
    }
    /// Global rate-limit threshold (requests per window).
    pub fn rate_limit(mut self, v: u32) -> Self {
        self.config.rate_limit = Some(v);
        self
    }
    /// Global rate-limit window in seconds.
    pub fn rate_limit_window(mut self, v: u64) -> Self {
        self.config.rate_limit_window = Some(v);
        self
    }
    /// Forces plain HTTP requests to be rejected or redirected.
    pub fn enforce_https(mut self, v: bool) -> Self {
        self.config.enforce_https = Some(v);
        self
    }
    /// Master switch for IP banning.
    pub fn enable_ip_banning(mut self, v: bool) -> Self {
        self.config.enable_ip_banning = Some(v);
        self
    }
    /// Master switch for rate limiting.
    pub fn enable_rate_limiting(mut self, v: bool) -> Self {
        self.config.enable_rate_limiting = Some(v);
        self
    }
    /// Master switch for penetration and suspicious-pattern detection.
    pub fn enable_penetration_detection(mut self, v: bool) -> Self {
        self.config.enable_penetration_detection = Some(v);
        self
    }
    /// Enables the Guard Agent integration. An `agent_api_key` must also be
    /// provided when `true`.
    pub fn enable_agent(mut self, v: bool) -> Self {
        self.config.enable_agent = Some(v);
        self
    }
    /// Sets the Guard Agent API key used to authenticate outbound traffic.
    pub fn agent_api_key(mut self, v: Option<String>) -> Self {
        self.config.agent_api_key = Some(v);
        self
    }
    /// Enables periodic fetching of dynamic rules from the agent.
    pub fn enable_dynamic_rules(mut self, v: bool) -> Self {
        self.config.enable_dynamic_rules = Some(v);
        self
    }
    /// Cloud providers whose IP ranges should be blocked.
    pub fn block_cloud_providers(mut self, v: Option<HashSet<CloudProvider>>) -> Self {
        self.config.block_cloud_providers = Some(v);
        self
    }

    /// Consumes the builder and returns a validated
    /// [`crate::models::SecurityConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Validation`] or
    /// [`crate::error::GuardCoreError::InvalidIp`] if any configured value
    /// fails [`crate::models::SecurityConfig::validate`] or IP normalisation.
    pub fn build(self) -> Result<SecurityConfig> {
        let d = self.config;
        let config = SecurityConfig {
            trusted_proxies: normalize_ip_list(d.trusted_proxies.unwrap_or_default())?,
            trusted_proxy_depth: d.trusted_proxy_depth.unwrap_or(1),
            trust_x_forwarded_proto: d.trust_x_forwarded_proto.unwrap_or(false),
            passive_mode: d.passive_mode.unwrap_or(false),
            geo_ip_handler: None,
            enable_redis: d.enable_redis.unwrap_or(true),
            redis_url: d
                .redis_url
                .unwrap_or_else(|| Some("redis://localhost:6379".into())),
            redis_prefix: d.redis_prefix.unwrap_or_else(|| "guard_core:".into()),
            whitelist: match d.whitelist {
                Some(Some(v)) => Some(normalize_ip_list(v)?),
                Some(None) => None,
                None => None,
            },
            blacklist: normalize_ip_list(d.blacklist.unwrap_or_default())?,
            whitelist_countries: d.whitelist_countries.unwrap_or_default(),
            blocked_countries: d.blocked_countries.unwrap_or_default(),
            blocked_user_agents: d.blocked_user_agents.unwrap_or_default(),
            auto_ban_threshold: d.auto_ban_threshold.unwrap_or(10),
            auto_ban_duration: d.auto_ban_duration.unwrap_or(3600),
            custom_log_file: None,
            log_suspicious_level: Some(LogLevel::Warning),
            log_request_level: None,
            log_format: LogFormat::Text,
            custom_error_responses: HashMap::new(),
            rate_limit: d.rate_limit.unwrap_or(10),
            rate_limit_window: d.rate_limit_window.unwrap_or(60),
            enforce_https: d.enforce_https.unwrap_or(false),
            security_headers: Some(SecurityHeadersConfig::default()),
            custom_request_check: None,
            custom_response_modifier: None,
            enable_cors: false,
            cors_allow_origins: vec!["*".into()],
            cors_allow_methods: vec![
                "GET".into(),
                "POST".into(),
                "PUT".into(),
                "PATCH".into(),
                "DELETE".into(),
                "OPTIONS".into(),
            ],
            cors_allow_headers: vec!["*".into()],
            cors_allow_credentials: false,
            cors_expose_headers: Vec::new(),
            cors_max_age: 600,
            block_cloud_providers: d.block_cloud_providers.unwrap_or(None),
            cloud_ip_refresh_interval: 3600,
            exclude_paths: vec![
                "/docs".into(),
                "/redoc".into(),
                "/openapi.json".into(),
                "/openapi.yaml".into(),
                "/favicon.ico".into(),
                "/static".into(),
            ],
            enable_ip_banning: d.enable_ip_banning.unwrap_or(true),
            enable_rate_limiting: d.enable_rate_limiting.unwrap_or(true),
            enable_penetration_detection: d.enable_penetration_detection.unwrap_or(true),
            ipinfo_token: None,
            ipinfo_db_path: Some(PathBuf::from("data/ipinfo/country_asn.mmdb")),
            enable_agent: d.enable_agent.unwrap_or(false),
            agent_api_key: d.agent_api_key.unwrap_or(None),
            agent_endpoint: "https://api.fastapi-guard.com".into(),
            agent_project_id: None,
            agent_buffer_size: 100,
            agent_flush_interval: 30,
            agent_enable_events: true,
            agent_enable_metrics: true,
            agent_timeout: 30,
            agent_retry_attempts: 3,
            enable_dynamic_rules: d.enable_dynamic_rules.unwrap_or(false),
            dynamic_rule_interval: 300,
            emergency_mode: false,
            emergency_whitelist: Vec::new(),
            endpoint_rate_limits: HashMap::new(),
            detection_compiler_timeout: 2.0,
            detection_max_content_length: 10_000,
            detection_preserve_attack_patterns: true,
            detection_semantic_threshold: 0.7,
            detection_anomaly_threshold: 3.0,
            detection_slow_pattern_threshold: 0.1,
            detection_monitor_history_size: 1000,
            detection_max_tracked_patterns: 1000,
        };
        config.validate()?;
        Ok(config)
    }
}

fn normalize_ip_list(entries: Vec<String>) -> Result<Vec<String>> {
    entries.into_iter().map(|e| validate_ip_or_cidr(&e)).collect()
}

/// Runtime-pushed rule payload sourced from the Guard Agent.
///
/// Parsed from the agent response and applied by the
/// [`crate::handlers::DynamicRuleManager`]. Every field is optional on the
/// wire; missing fields fall back to [`Default`].
///
/// # Examples
///
/// ```no_run
/// use guard_core_rs::models::DynamicRules;
///
/// let rules: DynamicRules = serde_json::from_str(r#"{
///     "rule_id": "ddos-2024-04",
///     "version": 3,
///     "timestamp": "2024-04-21T00:00:00Z"
/// }"#).expect("parseable");
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicRules {
    /// Identifier of the rule set; unique per agent deployment.
    pub rule_id: String,
    /// Monotonically increasing version; higher values supersede lower ones.
    pub version: i64,
    /// UTC timestamp when the rules were produced.
    pub timestamp: DateTime<Utc>,
    /// Optional expiration timestamp.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Time-to-live in seconds applied to the rules when cached in Redis.
    #[serde(default = "default_ttl")]
    pub ttl: u64,

    /// IP addresses or CIDRs to be banned immediately.
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
    /// IP addresses or CIDRs to be unbanned or whitelisted.
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    /// Ban duration in seconds applied to `ip_blacklist` entries.
    #[serde(default = "default_ban_duration")]
    pub ip_ban_duration: u64,

    /// ISO 3166-1 alpha-2 codes added to the blocked-country list.
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    /// ISO 3166-1 alpha-2 codes added to the whitelist-country list.
    #[serde(default)]
    pub whitelist_countries: Vec<String>,

    /// Optional override for the global rate-limit threshold.
    #[serde(default)]
    pub global_rate_limit: Option<u32>,
    /// Optional override for the global rate-limit window.
    #[serde(default)]
    pub global_rate_window: Option<u64>,
    /// Endpoint-specific `(limit, window_secs)` overrides.
    #[serde(default)]
    pub endpoint_rate_limits: HashMap<String, (u32, u64)>,

    /// Cloud provider names (`"AWS"`, `"GCP"`, `"Azure"`) to be blocked.
    #[serde(default)]
    pub blocked_cloud_providers: HashSet<String>,

    /// User-agent regex patterns to add to the blocklist.
    #[serde(default)]
    pub blocked_user_agents: Vec<String>,

    /// Additional suspicious-detection regex patterns.
    #[serde(default)]
    pub suspicious_patterns: Vec<String>,

    /// Optional runtime toggle for penetration detection.
    #[serde(default)]
    pub enable_penetration_detection: Option<bool>,
    /// Optional runtime toggle for IP banning.
    #[serde(default)]
    pub enable_ip_banning: Option<bool>,
    /// Optional runtime toggle for rate limiting.
    #[serde(default)]
    pub enable_rate_limiting: Option<bool>,

    /// When `true`, emergency mode is activated by this rule push.
    #[serde(default)]
    pub emergency_mode: bool,
    /// IPs permitted while emergency mode is active.
    #[serde(default)]
    pub emergency_whitelist: Vec<String>,
}

fn default_ttl() -> u64 {
    300
}
fn default_ban_duration() -> u64 {
    3600
}
