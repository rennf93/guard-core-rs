//! Dynamic security-header manager used by both error and success responses.

use std::collections::HashMap;
use std::sync::Arc;

use moka::future::Cache;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

use crate::error::{GuardCoreError, Result};
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;

/// Runtime representation of an HSTS configuration used by
/// [`crate::handlers::security_headers::SecurityHeadersManager`].
#[derive(Clone, Debug)]
pub struct HstsRuntimeConfig {
    /// `max-age` value in seconds.
    pub max_age: u32,
    /// Whether the `includeSubDomains` directive should be emitted.
    pub include_subdomains: bool,
    /// Whether the `preload` directive should be emitted.
    pub preload: bool,
}

/// Runtime CORS configuration applied by
/// [`crate::handlers::security_headers::SecurityHeadersManager::get_cors_headers`].
#[derive(Clone, Debug, Default)]
pub struct CorsRuntimeConfig {
    /// Allowed origins (`"*"` acts as a wildcard).
    pub origins: Vec<String>,
    /// Whether `Access-Control-Allow-Credentials` should be advertised.
    pub allow_credentials: bool,
    /// Allowed methods.
    pub allow_methods: Vec<String>,
    /// Allowed request headers.
    pub allow_headers: Vec<String>,
}

/// Builds security-related response headers (CSP, HSTS, X-Frame-Options, ...)
/// and caches per-path variants.
pub struct SecurityHeadersManager {
    enabled: parking_lot::RwLock<bool>,
    default_headers: RwLock<HashMap<String, String>>,
    custom_headers: RwLock<HashMap<String, String>>,
    csp_config: RwLock<Option<HashMap<String, Vec<String>>>>,
    hsts_config: RwLock<Option<HstsRuntimeConfig>>,
    cors_config: RwLock<Option<CorsRuntimeConfig>>,
    headers_cache: Cache<String, HashMap<String, String>>,
    redis_handler: parking_lot::RwLock<Option<DynRedisHandler>>,
    agent_handler: parking_lot::RwLock<Option<DynAgentHandler>>,
}

impl std::fmt::Debug for SecurityHeadersManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityHeadersManager").finish_non_exhaustive()
    }
}

impl Default for SecurityHeadersManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the static default header table applied when the manager is
/// fresh.
pub fn built_in_defaults() -> HashMap<String, String> {
    let pairs: &[(&str, &str)] = &[
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "SAMEORIGIN"),
        ("X-XSS-Protection", "1; mode=block"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
        ("X-Permitted-Cross-Domain-Policies", "none"),
        ("X-Download-Options", "noopen"),
        ("Cross-Origin-Embedder-Policy", "require-corp"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
    ];
    pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

impl SecurityHeadersManager {
    /// Creates a manager populated with
    /// [`crate::handlers::security_headers::built_in_defaults`].
    pub fn new() -> Self {
        Self {
            enabled: parking_lot::RwLock::new(true),
            default_headers: RwLock::new(built_in_defaults()),
            custom_headers: RwLock::new(HashMap::new()),
            csp_config: RwLock::new(None),
            hsts_config: RwLock::new(None),
            cors_config: RwLock::new(None),
            headers_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_live(std::time::Duration::from_secs(300))
                .build(),
            redis_handler: parking_lot::RwLock::new(None),
            agent_handler: parking_lot::RwLock::new(None),
        }
    }

    fn validate_header_value(value: &str) -> Result<String> {
        if value.contains('\r') || value.contains('\n') {
            return Err(GuardCoreError::Validation(format!(
                "Invalid header value contains newline: {value}"
            )));
        }
        if value.len() > 8192 {
            return Err(GuardCoreError::Validation(format!(
                "Header value too long: {} bytes",
                value.len()
            )));
        }
        Ok(value
            .chars()
            .filter(|c| (*c as u32) >= 32 || *c == '\t')
            .collect())
    }

    fn generate_cache_key(path: Option<&str>) -> String {
        let Some(path) = path else { return "default".into() };
        let normalized: String = path.to_ascii_lowercase().trim_matches('/').into();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        normalized.hash(&mut hasher);
        format!("path_{:016x}", hasher.finish())
    }

    /// Installs the Redis handler, loading cached configuration and
    /// persisting any existing settings.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] on connection or
    /// serialization failure.
    pub async fn initialize_redis(&self, redis: DynRedisHandler) -> Result<()> {
        *self.redis_handler.write() = Some(redis);
        self.load_cached_config().await;
        self.cache_configuration().await;
        Ok(())
    }

    /// Installs the Guard Agent handler used to emit header-related events.
    pub async fn initialize_agent(&self, agent: DynAgentHandler) {
        *self.agent_handler.write() = Some(agent);
    }

    async fn load_cached_config(&self) {
        let redis = self.redis_handler.read().clone();
        let Some(redis) = redis else { return };
        if let Ok(Some(value)) = redis.get_key("security_headers", "csp_config").await
            && let Ok(parsed) = serde_json::from_value::<HashMap<String, Vec<String>>>(value)
        {
            *self.csp_config.write().await = Some(parsed);
        }
        if let Ok(Some(value)) = redis.get_key("security_headers", "hsts_config").await
            && let Ok(parsed) = serde_json::from_value::<HstsJson>(value)
        {
            *self.hsts_config.write().await = Some(HstsRuntimeConfig {
                max_age: parsed.max_age,
                include_subdomains: parsed.include_subdomains,
                preload: parsed.preload,
            });
        }
        if let Ok(Some(value)) = redis.get_key("security_headers", "custom_headers").await
            && let Ok(parsed) = serde_json::from_value::<HashMap<String, String>>(value)
        {
            *self.custom_headers.write().await = parsed;
        }
    }

    async fn cache_configuration(&self) {
        let redis = self.redis_handler.read().clone();
        let Some(redis) = redis else { return };
        if let Some(csp) = self.csp_config.read().await.clone() {
            let _ = redis
                .set_key(
                    "security_headers",
                    "csp_config",
                    serde_json::to_value(&csp).unwrap_or(Value::Null),
                    Some(86_400),
                )
                .await;
        }
        if let Some(hsts) = self.hsts_config.read().await.clone() {
            let value = json!({
                "max_age": hsts.max_age,
                "include_subdomains": hsts.include_subdomains,
                "preload": hsts.preload,
            });
            let _ = redis
                .set_key("security_headers", "hsts_config", value, Some(86_400))
                .await;
        }
        let custom = self.custom_headers.read().await.clone();
        if !custom.is_empty() {
            let _ = redis
                .set_key(
                    "security_headers",
                    "custom_headers",
                    serde_json::to_value(&custom).unwrap_or(Value::Null),
                    Some(86_400),
                )
                .await;
        }
    }

    /// Applies a new configuration snapshot, replacing the defaults/CSP/HSTS
    /// and custom-header maps.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Validation`] when a supplied
    /// header value contains newlines or exceeds 8192 bytes.
    pub async fn configure(&self, opts: ConfigureOptions) -> Result<()> {
        *self.enabled.write() = opts.enabled;
        if let Some(csp) = opts.csp {
            for (dir, sources) in &csp {
                if sources.iter().any(|s| s == "'unsafe-inline'" || s == "'unsafe-eval'") {
                    warn!("CSP directive '{dir}' contains unsafe sources");
                }
            }
            *self.csp_config.write().await = Some(csp);
        }
        if let Some(max_age) = opts.hsts_max_age {
            let mut preload = opts.hsts_preload;
            let mut include_subdomains = opts.hsts_include_subdomains;
            if preload {
                if max_age < 31_536_000 {
                    warn!("HSTS preload requires max_age >= 31536000");
                    preload = false;
                }
                if !include_subdomains {
                    warn!("HSTS preload requires includeSubDomains");
                    include_subdomains = true;
                }
            }
            *self.hsts_config.write().await =
                Some(HstsRuntimeConfig { max_age, include_subdomains, preload });
        }
        if let Some(origins) = opts.cors_origins {
            let mut allow_credentials = opts.cors_allow_credentials;
            if origins.iter().any(|o| o == "*") && allow_credentials {
                error!("CORS config error: Wildcard origin disallowed with credentials");
                allow_credentials = false;
            }
            *self.cors_config.write().await = Some(CorsRuntimeConfig {
                origins,
                allow_credentials,
                allow_methods: opts
                    .cors_allow_methods
                    .unwrap_or_else(|| vec!["GET".into(), "POST".into()]),
                allow_headers: opts
                    .cors_allow_headers
                    .unwrap_or_else(|| vec!["*".into()]),
            });
        }

        let mut defaults = self.default_headers.write().await;
        if let Some(v) = opts.frame_options {
            defaults.insert("X-Frame-Options".into(), Self::validate_header_value(&v)?);
        }
        if let Some(v) = opts.content_type_options {
            defaults.insert(
                "X-Content-Type-Options".into(),
                Self::validate_header_value(&v)?,
            );
        }
        if let Some(v) = opts.xss_protection {
            defaults.insert("X-XSS-Protection".into(), Self::validate_header_value(&v)?);
        }
        if let Some(v) = opts.referrer_policy {
            defaults.insert("Referrer-Policy".into(), Self::validate_header_value(&v)?);
        }
        match opts.permissions_policy {
            PermissionsPolicySetting::Unset => {}
            PermissionsPolicySetting::Remove => {
                defaults.remove("Permissions-Policy");
            }
            PermissionsPolicySetting::Value(v) => {
                defaults.insert(
                    "Permissions-Policy".into(),
                    Self::validate_header_value(&v)?,
                );
            }
        }
        drop(defaults);
        if let Some(custom) = opts.custom_headers {
            let mut target = self.custom_headers.write().await;
            for (name, value) in custom {
                target.insert(name, Self::validate_header_value(&value)?);
            }
        }
        Ok(())
    }

    /// Returns the header map to apply to a response, optionally keyed by
    /// `request_path` for per-path variants.
    pub async fn get_headers(&self, request_path: Option<&str>) -> HashMap<String, String> {
        if !*self.enabled.read() {
            return HashMap::new();
        }
        let cache_key = Self::generate_cache_key(request_path);
        if let Some(cached) = self.headers_cache.get(&cache_key).await {
            return cached;
        }
        let mut headers = self.default_headers.read().await.clone();
        if let Some(csp) = self.csp_config.read().await.clone() {
            headers.insert("Content-Security-Policy".into(), build_csp(&csp));
        }
        if let Some(hsts) = self.hsts_config.read().await.clone() {
            headers.insert("Strict-Transport-Security".into(), build_hsts(&hsts));
        }
        let custom = self.custom_headers.read().await.clone();
        for (k, v) in custom {
            headers.insert(k, v);
        }
        self.headers_cache.insert(cache_key, headers.clone()).await;

        let agent = self.agent_handler.read().clone();
        if let Some(path) = request_path
            && let Some(agent) = agent
        {
            let event = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event_type": "security_headers_applied",
                "action_taken": "headers_added",
                "metadata": {
                    "path": path,
                    "headers_count": headers.len(),
                    "has_csp": headers.contains_key("Content-Security-Policy"),
                    "has_hsts": headers.contains_key("Strict-Transport-Security"),
                },
            });
            if let Err(e) = agent.send_event(event).await {
                debug!("Failed to send headers event to agent: {e}");
            }
        }
        headers
    }

    /// Returns the CORS response headers to apply for a preflight or actual
    /// request originating from `origin`.
    pub async fn get_cors_headers(&self, origin: &str) -> HashMap<String, String> {
        let Some(cors) = self.cors_config.read().await.clone() else {
            return HashMap::new();
        };
        if cors.origins.iter().any(|o| o == "*") && cors.allow_credentials {
            warn!("Credentials cannot be used with wildcard origin - blocking CORS");
            return HashMap::new();
        }
        if !cors.origins.iter().any(|o| o == "*") && !cors.origins.contains(&origin.to_string()) {
            return HashMap::new();
        }
        let allow_origin = if cors.origins.contains(&origin.to_string()) {
            origin.to_string()
        } else {
            "*".into()
        };
        let mut out = HashMap::new();
        out.insert("Access-Control-Allow-Origin".into(), allow_origin);
        out.insert(
            "Access-Control-Allow-Methods".into(),
            cors.allow_methods.join(", "),
        );
        out.insert(
            "Access-Control-Allow-Headers".into(),
            cors.allow_headers.join(", "),
        );
        out.insert("Access-Control-Max-Age".into(), "3600".into());
        if cors.allow_credentials {
            out.insert("Access-Control-Allow-Credentials".into(), "true".into());
        }
        out
    }

    /// Validates a browser-submitted CSP violation report and forwards it as
    /// a `csp_violation` agent event.
    pub async fn validate_csp_report(&self, report: &Value) -> bool {
        let Some(csp_report) = report.get("csp-report") else { return false };
        let required = ["document-uri", "violated-directive", "blocked-uri"];
        for field in required {
            if csp_report.get(field).is_none() {
                return false;
            }
        }
        warn!(
            "CSP Violation: {} blocked {} on {}",
            csp_report.get("violated-directive").and_then(|v| v.as_str()).unwrap_or("?"),
            csp_report.get("blocked-uri").and_then(|v| v.as_str()).unwrap_or("?"),
            csp_report.get("document-uri").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        let agent = self.agent_handler.read().clone();
        if let Some(agent) = agent {
            let event = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event_type": "csp_violation",
                "action_taken": "logged",
                "metadata": {
                    "document_uri": csp_report.get("document-uri"),
                    "violated_directive": csp_report.get("violated-directive"),
                    "blocked_uri": csp_report.get("blocked-uri"),
                    "source_file": csp_report.get("source-file"),
                    "line_number": csp_report.get("line-number"),
                },
            });
            if let Err(e) = agent.send_event(event).await {
                debug!("Failed to send CSP violation event to agent: {e}");
            }
        }
        true
    }

    /// Clears every dynamic override, reverting to
    /// [`crate::handlers::security_headers::built_in_defaults`].
    pub async fn reset(&self) {
        self.headers_cache.invalidate_all();
        self.headers_cache.run_pending_tasks().await;
        self.custom_headers.write().await.clear();
        *self.csp_config.write().await = None;
        *self.hsts_config.write().await = None;
        *self.cors_config.write().await = None;
        *self.enabled.write() = true;
        *self.default_headers.write().await = built_in_defaults();
    }
}

/// Options passed to
/// [`crate::handlers::security_headers::SecurityHeadersManager::configure`].
#[derive(Clone, Debug, Default)]
pub struct ConfigureOptions {
    /// Master switch for header application.
    pub enabled: bool,
    /// Optional CSP directive → source list map.
    pub csp: Option<HashMap<String, Vec<String>>>,
    /// Optional HSTS `max-age` in seconds. `None` disables HSTS.
    pub hsts_max_age: Option<u32>,
    /// Whether `includeSubDomains` should be emitted.
    pub hsts_include_subdomains: bool,
    /// Whether `preload` should be emitted.
    pub hsts_preload: bool,
    /// Optional override for `X-Frame-Options`.
    pub frame_options: Option<String>,
    /// Optional override for `X-Content-Type-Options`.
    pub content_type_options: Option<String>,
    /// Optional override for `X-XSS-Protection`.
    pub xss_protection: Option<String>,
    /// Optional override for `Referrer-Policy`.
    pub referrer_policy: Option<String>,
    /// Override policy for `Permissions-Policy`.
    pub permissions_policy: PermissionsPolicySetting,
    /// Optional custom headers applied after the default set.
    pub custom_headers: Option<HashMap<String, String>>,
    /// CORS origins. `None` disables the CORS block.
    pub cors_origins: Option<Vec<String>>,
    /// Whether CORS credentials should be allowed.
    pub cors_allow_credentials: bool,
    /// CORS methods.
    pub cors_allow_methods: Option<Vec<String>>,
    /// CORS headers.
    pub cors_allow_headers: Option<Vec<String>>,
}

/// Three-state setting for the `Permissions-Policy` header.
#[derive(Clone, Debug, Default)]
pub enum PermissionsPolicySetting {
    /// Leave the previous value in place.
    #[default]
    Unset,
    /// Remove the header from the defaults.
    Remove,
    /// Replace the header with the supplied value.
    Value(String),
}

#[derive(serde::Deserialize)]
struct HstsJson {
    max_age: u32,
    #[serde(default = "default_true")]
    include_subdomains: bool,
    #[serde(default)]
    preload: bool,
}

fn default_true() -> bool {
    true
}

fn build_csp(csp_config: &HashMap<String, Vec<String>>) -> String {
    let parts: Vec<String> = csp_config
        .iter()
        .map(|(dir, sources)| {
            if sources.is_empty() {
                dir.clone()
            } else {
                format!("{dir} {}", sources.join(" "))
            }
        })
        .collect();
    parts.join("; ")
}

fn build_hsts(cfg: &HstsRuntimeConfig) -> String {
    let mut parts = vec![format!("max-age={}", cfg.max_age)];
    if cfg.include_subdomains {
        parts.push("includeSubDomains".into());
    }
    if cfg.preload {
        parts.push("preload".into());
    }
    parts.join("; ")
}

impl SecurityHeadersManager {
    /// Convenience constructor wrapping
    /// [`crate::handlers::security_headers::SecurityHeadersManager::new`] in
    /// an [`Arc`].
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}
