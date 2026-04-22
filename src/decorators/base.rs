//! Per-route security policy definitions and registry.
//!
//! Framework adapters attach a [`crate::decorators::base::RouteConfig`] to
//! each route and register it with the
//! [`crate::decorators::base::SecurityDecorator`]. Pipeline checks then fetch
//! the active config via [`crate::decorators::base::get_route_decorator_config`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::NaiveTime;
use dashmap::DashMap;
use serde_json::{Value, json};
use tracing::error;

use crate::handlers::behavior::{BehaviorRule, BehaviorTracker};
use crate::handlers::ipban::IPBanManager;
use crate::models::{CloudProvider, SecurityConfig};
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;
use crate::protocols::request::DynGuardRequest;
use crate::utils::{extract_client_ip, get_pipeline_response_time};

/// Per-route security policy attached to a single endpoint.
///
/// Every field overrides the equivalent global setting in
/// [`crate::models::SecurityConfig`]. Configure via the fluent methods
/// ([`crate::decorators::base::RouteConfig::require_ip`],
/// [`crate::decorators::base::RouteConfig::rate_limit`], etc.) and register
/// with a [`crate::decorators::base::SecurityDecorator`].
///
/// # Examples
///
/// ```no_run
/// use guard_core_rs::decorators::base::RouteConfig;
///
/// let config = RouteConfig::new()
///     .rate_limit(100, 60)
///     .require_https();
/// assert_eq!(config.rate_limit, Some(100));
/// ```
#[derive(Clone, Default)]
pub struct RouteConfig {
    /// Per-route rate-limit threshold (requests per window).
    pub rate_limit: Option<u32>,
    /// Per-route rate-limit window in seconds.
    pub rate_limit_window: Option<u64>,
    /// IPs or CIDRs whitelisted for this route; `None` disables the list.
    pub allowed_ips: Option<Vec<String>>,
    /// IPs or CIDRs blacklisted for this route.
    pub blocked_ips: Vec<String>,
    /// ISO 3166-1 alpha-2 country codes blocked for this route.
    pub blocked_countries: Vec<String>,
    /// ISO 3166-1 alpha-2 country codes allowed for this route.
    pub allowed_countries: Vec<String>,
    /// Check names bypassed for this route (e.g. `"rate_limit"`, `"ip"`).
    pub bypassed_checks: Vec<String>,
    /// Require HTTPS for this route regardless of global setting.
    pub require_https: bool,
    /// Authentication scheme required (`"bearer"`, `"basic"`, ...).
    pub auth_required: Option<String>,
    /// Require an API key in the header specified by `required_headers`.
    pub api_key_required: bool,
    /// Header name → expected value map. Value of `"required"` signals
    /// presence-only validation.
    pub required_headers: HashMap<String, String>,
    /// User-agent regex patterns blocked for this route.
    pub blocked_user_agents: Vec<String>,
    /// Behavioural rules evaluated by the behaviour tracker.
    pub behavior_rules: Vec<BehaviorRule>,
    /// Cloud providers blocked for this route (overrides global setting).
    pub block_cloud_providers: Option<HashSet<CloudProvider>>,
    /// Maximum request size in bytes.
    pub max_request_size: Option<u64>,
    /// Allowed `Content-Type` values.
    pub allowed_content_types: Option<Vec<String>>,
    /// Start of the allowed time window.
    pub time_window_start: Option<NaiveTime>,
    /// End of the allowed time window.
    pub time_window_end: Option<NaiveTime>,
    /// Timezone name for the time window.
    pub time_window_timezone: Option<String>,
    /// Whether pattern-based suspicious detection is enabled for the route.
    pub enable_suspicious_detection: bool,
    /// Allowed referrer domains; `None` disables the check.
    pub require_referrer: Option<Vec<String>>,
    /// Per-session concurrency/usage limits.
    pub session_limits: Option<HashMap<String, u32>>,
    /// Geo-aware rate limits keyed by country code or `"*"`.
    pub geo_rate_limits: Option<HashMap<String, (u32, u64)>>,
    /// Custom async validators executed alongside the pipeline.
    pub custom_validators: Vec<CustomValidator>,
    /// Optional override for the `Referrer-Policy` response header.
    pub referrer_policy: Option<String>,
    /// Opaque metadata consumed by downstream adapters.
    pub custom_metadata: HashMap<String, Value>,
}

/// Async validator invoked once per matching route before the main pipeline
/// runs.
pub type CustomValidator = Arc<
    dyn Fn(
            Arc<dyn crate::protocols::request::GuardRequest>,
        ) -> futures::future::BoxFuture<
            'static,
            Option<Arc<dyn crate::protocols::response::GuardResponse>>,
        >
        + Send
        + Sync,
>;

impl std::fmt::Debug for RouteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteConfig")
            .field("rate_limit", &self.rate_limit)
            .field("rate_limit_window", &self.rate_limit_window)
            .field("allowed_ips", &self.allowed_ips)
            .field("blocked_ips", &self.blocked_ips)
            .field("blocked_countries", &self.blocked_countries)
            .field("allowed_countries", &self.allowed_countries)
            .field("bypassed_checks", &self.bypassed_checks)
            .field("require_https", &self.require_https)
            .field("auth_required", &self.auth_required)
            .field("api_key_required", &self.api_key_required)
            .field("required_headers", &self.required_headers)
            .field("blocked_user_agents", &self.blocked_user_agents)
            .field("behavior_rules", &self.behavior_rules)
            .field("block_cloud_providers", &self.block_cloud_providers)
            .field("max_request_size", &self.max_request_size)
            .field("allowed_content_types", &self.allowed_content_types)
            .field("enable_suspicious_detection", &self.enable_suspicious_detection)
            .field("require_referrer", &self.require_referrer)
            .finish_non_exhaustive()
    }
}

impl RouteConfig {
    /// Creates a default [`crate::decorators::base::RouteConfig`] with
    /// suspicious detection enabled.
    pub fn new() -> Self {
        Self { enable_suspicious_detection: true, ..Default::default() }
    }

    /// Sets optional IP whitelist and/or blacklist for the route.
    pub fn require_ip(
        mut self,
        whitelist: Option<Vec<String>>,
        blacklist: Option<Vec<String>>,
    ) -> Self {
        if let Some(w) = whitelist {
            self.allowed_ips = Some(w);
        }
        if let Some(b) = blacklist {
            self.blocked_ips = b;
        }
        self
    }

    /// Blocks the supplied country codes.
    pub fn block_countries(mut self, countries: Vec<String>) -> Self {
        self.blocked_countries = countries;
        self
    }

    /// Limits access to the supplied country codes.
    pub fn allow_countries(mut self, countries: Vec<String>) -> Self {
        self.allowed_countries = countries;
        self
    }

    /// Blocks specific cloud providers, or all known providers when `providers`
    /// is [`None`].
    pub fn block_clouds(mut self, providers: Option<Vec<CloudProvider>>) -> Self {
        self.block_cloud_providers = Some(providers.map_or_else(
            || HashSet::from([CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure]),
            HashSet::from_iter,
        ));
        self
    }

    /// Appends check names to the route's bypass list.
    pub fn bypass(mut self, checks: Vec<String>) -> Self {
        for check in checks {
            if !self.bypassed_checks.contains(&check) {
                self.bypassed_checks.push(check);
            }
        }
        self
    }

    /// Configures the per-route rate limit.
    pub fn rate_limit(mut self, requests: u32, window: u64) -> Self {
        self.rate_limit = Some(requests);
        self.rate_limit_window = Some(window);
        self
    }

    /// Sets country-keyed rate limits. Use `"*"` as a wildcard country.
    pub fn geo_rate_limit(mut self, limits: HashMap<String, (u32, u64)>) -> Self {
        self.geo_rate_limits = Some(limits);
        self
    }

    /// Forces HTTPS for the route.
    pub fn require_https(mut self) -> Self {
        self.require_https = true;
        self
    }

    /// Requires the caller to authenticate using `scheme`.
    pub fn require_auth(mut self, scheme: impl Into<String>) -> Self {
        self.auth_required = Some(scheme.into());
        self
    }

    /// Marks `header_name` as a required API-key header for the route.
    pub fn api_key_auth(mut self, header_name: impl Into<String>) -> Self {
        self.api_key_required = true;
        self.required_headers.insert(header_name.into(), "required".into());
        self
    }

    /// Adds `headers` to the required-headers map.
    pub fn require_headers(mut self, headers: HashMap<String, String>) -> Self {
        for (k, v) in headers {
            self.required_headers.insert(k, v);
        }
        self
    }

    /// Adds an endpoint-usage behavioural rule.
    pub fn usage_monitor(
        mut self,
        max_calls: u32,
        window: u64,
        action: crate::handlers::behavior::BehaviorAction,
    ) -> Self {
        self.behavior_rules.push(BehaviorRule::new(
            crate::handlers::behavior::BehaviorRuleType::Usage,
            max_calls,
            window,
            None,
            action,
        ));
        self
    }

    /// Adds a response-pattern monitoring rule (`pattern` is matched against
    /// the outgoing body, status code, or JSON).
    pub fn return_monitor(
        mut self,
        pattern: impl Into<String>,
        max_occurrences: u32,
        window: u64,
        action: crate::handlers::behavior::BehaviorAction,
    ) -> Self {
        self.behavior_rules.push(BehaviorRule::new(
            crate::handlers::behavior::BehaviorRuleType::ReturnPattern,
            max_occurrences,
            window,
            Some(pattern.into()),
            action,
        ));
        self
    }

    /// Appends a bulk set of
    /// [`crate::handlers::behavior::BehaviorRule`] entries.
    pub fn behavior_analysis(mut self, rules: Vec<BehaviorRule>) -> Self {
        self.behavior_rules.extend(rules);
        self
    }

    /// Adds a frequency-based behavioural rule measured as `max_frequency`
    /// calls per second across `window` seconds.
    pub fn suspicious_frequency(
        mut self,
        max_frequency: f64,
        window: u64,
        action: crate::handlers::behavior::BehaviorAction,
    ) -> Self {
        let max_calls = (max_frequency * window as f64) as u32;
        self.behavior_rules.push(BehaviorRule::new(
            crate::handlers::behavior::BehaviorRuleType::Frequency,
            max_calls,
            window,
            None,
            action,
        ));
        self
    }

    /// Appends user-agent regex patterns to the route's blocklist.
    pub fn block_user_agents(mut self, patterns: Vec<String>) -> Self {
        self.blocked_user_agents.extend(patterns);
        self
    }

    /// Restricts requests to the supplied `Content-Type` values.
    pub fn content_type_filter(mut self, allowed_types: Vec<String>) -> Self {
        self.allowed_content_types = Some(allowed_types);
        self
    }

    /// Caps the request body size in bytes.
    pub fn max_request_size(mut self, size_bytes: u64) -> Self {
        self.max_request_size = Some(size_bytes);
        self
    }

    /// Restricts requests to those whose referrer host matches any of
    /// `allowed_domains`.
    pub fn require_referrer(mut self, allowed_domains: Vec<String>) -> Self {
        self.require_referrer = Some(allowed_domains);
        self
    }

    /// Registers an async validator executed by the custom-validators check.
    pub fn custom_validation(mut self, validator: CustomValidator) -> Self {
        self.custom_validators.push(validator);
        self
    }

    /// Restricts access to requests received within the `[start, end]`
    /// window in `timezone`.
    pub fn time_window(
        mut self,
        start: NaiveTime,
        end: NaiveTime,
        timezone: impl Into<String>,
    ) -> Self {
        self.time_window_start = Some(start);
        self.time_window_end = Some(end);
        self.time_window_timezone = Some(timezone.into());
        self
    }

    /// Toggles suspicious-detection for the route.
    pub fn suspicious_detection(mut self, enabled: bool) -> Self {
        self.enable_suspicious_detection = enabled;
        self.custom_metadata
            .insert("enable_suspicious_detection".into(), json!(enabled));
        self
    }
}

/// Mixin trait exposing read/write access to a
/// [`crate::decorators::base::RouteConfig`].
///
/// Implemented by decorator types that wrap a
/// [`crate::decorators::base::RouteConfig`] and want to forward builder-style
/// mutators to the inner value.
pub trait BaseSecurityMixin {
    /// Returns a shared reference to the wrapped
    /// [`crate::decorators::base::RouteConfig`].
    fn route_config(&self) -> &RouteConfig;
    /// Returns an exclusive reference to the wrapped
    /// [`crate::decorators::base::RouteConfig`].
    fn route_config_mut(&mut self) -> &mut RouteConfig;
}

/// Minimal decorator wrapping a
/// [`crate::decorators::base::RouteConfig`] and implementing
/// [`crate::decorators::base::BaseSecurityMixin`].
#[derive(Clone, Default, Debug)]
pub struct BaseSecurityDecorator {
    /// The wrapped [`crate::decorators::base::RouteConfig`].
    pub config: RouteConfig,
}

impl BaseSecurityDecorator {
    /// Wraps `config` in a new [`crate::decorators::base::BaseSecurityDecorator`].
    pub const fn new(config: RouteConfig) -> Self {
        Self { config }
    }
}

impl BaseSecurityMixin for BaseSecurityDecorator {
    fn route_config(&self) -> &RouteConfig {
        &self.config
    }
    fn route_config_mut(&mut self) -> &mut RouteConfig {
        &mut self.config
    }
}

/// [`crate::protocols::request::RequestState`] key storing the route
/// identifier propagated by adapters.
pub const ROUTE_ID_STATE_KEY: &str = "guard_route_id";

/// Registry and event dispatcher for route-level policies.
///
/// Stores [`crate::decorators::base::RouteConfig`] entries keyed by route
/// identifier, owns the shared
/// [`crate::handlers::behavior::BehaviorTracker`], and forwards events to the
/// agent.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::decorators::base::{RouteConfig, SecurityDecorator};
/// use guard_core_rs::models::SecurityConfig;
///
/// let decorator = SecurityDecorator::new(Arc::new(SecurityConfig::default()));
/// decorator.register("GET:/health", RouteConfig::new());
/// assert!(decorator.get_route_config("GET:/health").is_some());
/// ```
pub struct SecurityDecorator {
    config: Arc<SecurityConfig>,
    route_configs: Arc<DashMap<String, RouteConfig>>,
    behavior_tracker: Arc<BehaviorTracker>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
}

impl std::fmt::Debug for SecurityDecorator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityDecorator")
            .field("routes", &self.route_configs.len())
            .finish_non_exhaustive()
    }
}

impl SecurityDecorator {
    /// Builds a fresh [`crate::decorators::base::SecurityDecorator`] bound to
    /// `config`, creating an empty route registry.
    pub fn new(config: Arc<SecurityConfig>) -> Self {
        let behavior_tracker = Arc::new(BehaviorTracker::new(Arc::clone(&config)));
        Self {
            config,
            route_configs: Arc::new(DashMap::new()),
            behavior_tracker,
            agent_handler: parking_lot::RwLock::new(None),
        }
    }

    /// Returns the shared
    /// [`crate::handlers::behavior::BehaviorTracker`].
    pub fn behavior_tracker(&self) -> Arc<BehaviorTracker> {
        Arc::clone(&self.behavior_tracker)
    }

    /// Associates `route_id` with `config` in the registry.
    pub fn register(&self, route_id: impl Into<String>, config: RouteConfig) {
        self.route_configs.insert(route_id.into(), config);
    }

    /// Removes the [`crate::decorators::base::RouteConfig`] stored under
    /// `route_id`, if any.
    pub fn unregister(&self, route_id: &str) {
        self.route_configs.remove(route_id);
    }

    /// Returns a clone of the [`crate::decorators::base::RouteConfig`] stored
    /// under `route_id`.
    pub fn get_route_config(&self, route_id: &str) -> Option<RouteConfig> {
        self.route_configs.get(route_id).map(|entry| entry.value().clone())
    }

    /// Propagates a Redis handler into the shared
    /// [`crate::handlers::behavior::BehaviorTracker`].
    pub async fn initialize_behavior_tracking(&self, redis: Option<DynRedisHandler>) {
        if let Some(redis) = redis {
            self.behavior_tracker.initialize_redis(redis).await;
        }
    }

    /// Wires in the agent handler and optional
    /// [`crate::handlers::ipban::IPBanManager`] used for behavioural bans.
    pub async fn initialize_agent(&self, agent: DynAgentHandler, ipban: Option<Arc<IPBanManager>>) {
        *self.agent_handler.write() = Some(agent.clone());
        self.behavior_tracker.initialize_agent(agent).await;
        if let Some(ban) = ipban {
            self.behavior_tracker.set_ipban_manager(ban);
        }
    }

    /// Low-level helper that builds a decorator event and forwards it to the
    /// agent.
    pub async fn send_decorator_event(
        &self,
        event_type: &str,
        request: &DynGuardRequest,
        action_taken: &str,
        reason: &str,
        decorator_type: &str,
        metadata: serde_json::Map<String, Value>,
    ) {
        let agent = self.agent_handler.read().clone();
        let Some(agent) = agent else { return };
        let client_ip = extract_client_ip(request, &self.config, Some(&agent)).await;
        let event = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": event_type,
            "ip_address": client_ip,
            "user_agent": request.header("User-Agent"),
            "action_taken": action_taken,
            "reason": reason,
            "endpoint": request.url_path(),
            "method": request.method(),
            "response_time": get_pipeline_response_time(Some(request)),
            "decorator_type": decorator_type,
            "metadata": metadata,
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send decorator event to agent: {e}");
        }
    }

    /// Sends a generic `access_denied` decorator event.
    pub async fn send_access_denied_event(
        &self,
        request: &DynGuardRequest,
        reason: &str,
        decorator_type: &str,
        metadata: serde_json::Map<String, Value>,
    ) {
        self.send_decorator_event(
            "access_denied",
            request,
            "blocked",
            reason,
            decorator_type,
            metadata,
        )
        .await;
    }

    /// Sends an authentication-failure decorator event.
    pub async fn send_authentication_failed_event(
        &self,
        request: &DynGuardRequest,
        reason: &str,
        auth_type: &str,
        metadata: serde_json::Map<String, Value>,
    ) {
        let mut meta = metadata;
        meta.insert("auth_type".into(), json!(auth_type));
        self.send_decorator_event(
            "authentication_failed",
            request,
            "blocked",
            reason,
            "authentication",
            meta,
        )
        .await;
    }

    /// Sends a rate-limit decorator event including the offending limits.
    pub async fn send_rate_limit_event(
        &self,
        request: &DynGuardRequest,
        limit: u32,
        window: u64,
        metadata: serde_json::Map<String, Value>,
    ) {
        let mut meta = metadata;
        meta.insert("limit".into(), json!(limit));
        meta.insert("window".into(), json!(window));
        self.send_decorator_event(
            "rate_limited",
            request,
            "blocked",
            &format!("Rate limit exceeded: {limit} requests per {window}s"),
            "rate_limiting",
            meta,
        )
        .await;
    }

    /// Sends a generic `decorator_violation` event.
    pub async fn send_decorator_violation_event(
        &self,
        request: &DynGuardRequest,
        violation_type: &str,
        reason: &str,
        metadata: serde_json::Map<String, Value>,
    ) {
        self.send_decorator_event(
            "decorator_violation",
            request,
            "blocked",
            reason,
            violation_type,
            metadata,
        )
        .await;
    }
}

/// Helper returning the
/// [`crate::decorators::base::RouteConfig`] associated with `request`.
///
/// Reads the route identifier from
/// [`crate::decorators::base::ROUTE_ID_STATE_KEY`] on the request state and
/// looks it up in `decorator`.
pub fn get_route_decorator_config(
    request: &DynGuardRequest,
    decorator: &SecurityDecorator,
) -> Option<RouteConfig> {
    request
        .state()
        .get_str(ROUTE_ID_STATE_KEY)
        .and_then(|route_id| decorator.get_route_config(&route_id))
}
