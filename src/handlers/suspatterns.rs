//! Suspicious-pattern detection manager combining regex and semantic
//! analysis.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock as SyncRwLock;
use regex::Regex;
use serde_json::{Map, Value, json};
use tokio::sync::RwLock;
use tracing::{error, warn};

use crate::detection_engine::{
    ContentPreprocessor, PatternCompiler, PerformanceMonitor, RegexFlags, SemanticAnalyzer,
};
use crate::error::Result;
use crate::models::SecurityConfig;
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::redis::DynRedisHandler;

/// Context tag used for query-string content.
pub const CTX_QUERY_PARAM: &str = "query_param";
/// Context tag used for header values.
pub const CTX_HEADER: &str = "header";
/// Context tag used for the URL path component.
pub const CTX_URL_PATH: &str = "url_path";
/// Context tag used for request-body content.
pub const CTX_REQUEST_BODY: &str = "request_body";
/// Context tag used when the source is unknown or untyped.
pub const CTX_UNKNOWN: &str = "unknown";

fn ctx(items: &[&'static str]) -> HashSet<&'static str> {
    items.iter().copied().collect()
}

fn ctx_xss() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_HEADER, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_sqli() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_dir_traversal() -> HashSet<&'static str> {
    ctx(&[CTX_URL_PATH, CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_cmd_injection() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_file_inclusion() -> HashSet<&'static str> {
    ctx(&[CTX_URL_PATH, CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_ldap() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_xml() -> HashSet<&'static str> {
    ctx(&[CTX_HEADER, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_ssrf() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_nosql() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_file_upload() -> HashSet<&'static str> {
    ctx(&[CTX_HEADER, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_path_traversal() -> HashSet<&'static str> {
    ctx(&[CTX_URL_PATH, CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_template() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_http_split() -> HashSet<&'static str> {
    ctx(&[CTX_HEADER, CTX_QUERY_PARAM, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_sensitive_file() -> HashSet<&'static str> {
    ctx(&[CTX_URL_PATH, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_cms_probing() -> HashSet<&'static str> {
    ctx(&[CTX_URL_PATH, CTX_REQUEST_BODY, CTX_UNKNOWN])
}
fn ctx_recon() -> HashSet<&'static str> {
    ctx(&[CTX_URL_PATH, CTX_UNKNOWN])
}
fn ctx_all() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_HEADER, CTX_URL_PATH, CTX_REQUEST_BODY, CTX_UNKNOWN])
}

fn known_contexts() -> HashSet<&'static str> {
    ctx(&[CTX_QUERY_PARAM, CTX_HEADER, CTX_URL_PATH, CTX_REQUEST_BODY, CTX_UNKNOWN])
}

fn pattern_definitions() -> Vec<(&'static str, HashSet<&'static str>)> {
    vec![
        (r"<script[^>]*>[^<]*</script\s*>", ctx_xss()),
        (r"javascript:\s*[^\s]+", ctx_xss()),
        (
            r#"(?:on(?:error|load|click|mouseover|submit|mouse|unload|change|focus|blur|drag))=(?:["'][^"']*["']|[^\s>]+)"#,
            ctx_xss(),
        ),
        (
            r#"(?:<[^>]+\s+(?:href|src|data|action)\s*=[\s"']*(?:javascript|vbscript|data):)"#,
            ctx_xss(),
        ),
        (
            r#"(?:<[^>]+style\s*=[\s"']*[^>"']*(?:expression|behavior|url)\s*\([^)]*\))"#,
            ctx_xss(),
        ),
        (r"(?:<object[^>]*>[\s\S]*</object\s*>)", ctx_xss()),
        (r"(?:<embed[^>]*>[\s\S]*</embed\s*>)", ctx_xss()),
        (r"(?:<applet[^>]*>[\s\S]*</applet\s*>)", ctx_xss()),
        (r"(?i)SELECT\s+[\w\s,\*]+\s+FROM\s+[\w\s\._]+", ctx_sqli()),
        (r"(?i)UNION\s+(?:ALL\s+)?SELECT", ctx_sqli()),
        (
            r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?[\d\w]+\s*(?:=|LIKE|<|>|<=|>=)\s*[\(\s]*'?[\d\w]+)",
            ctx_sqli(),
        ),
        (
            r"(?i)(UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL[,\s]*)+|\(\s*SELECT\s+(?:@@|VERSION))",
            ctx_sqli(),
        ),
        (r"(?i)(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+'[^']+')", ctx_sqli()),
        (r"(?i)(?:LOAD_FILE\s*\([^)]+\))", ctx_sqli()),
        (r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,)", ctx_sqli()),
        (r"(?i)(?:SLEEP\s*\(\s*\d+\s*\))", ctx_sqli()),
        (
            r"(?i)(?:/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\b)",
            ctx_sqli(),
        ),
        (r"(?:\.\./|\.\.\\)(?:\.\./|\.\.\\)+", ctx_dir_traversal()),
        (
            r"(?:/etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\.cnf|ssh/ssh_config)$)",
            ctx_dir_traversal(),
        ),
        (r"(?:boot\.ini|win\.ini|system\.ini|config\.sys)\s*$", ctx_dir_traversal()),
        (r"(?:/proc/self/environ$)", ctx_dir_traversal()),
        (r"(?:/var/log/[^/]+$)", ctx_dir_traversal()),
        (
            r";\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\s+-[a-zA-Z]+\s+",
            ctx_cmd_injection(),
        ),
        (r"\|\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\s+", ctx_cmd_injection()),
        (r"(?:[;&|`]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))", ctx_cmd_injection()),
        (
            r"(?:^|;)\s*(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+",
            ctx_cmd_injection(),
        ),
        (
            r"\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
            ctx_cmd_injection(),
        ),
        (
            r"(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|rar|ogg|expect)://[^\s]+",
            ctx_file_inclusion(),
        ),
        (
            r"(?://[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:[0-9]+)?(?:/?)(?:[a-zA-Z0-9\-\.\?,'/\\\+&amp;%\$#_]*)?)",
            ctx_file_inclusion(),
        ),
        (r"\(\s*[|&]\s*\(\s*[^)]+=[*]", ctx_ldap()),
        (r"(?:\*(?:[\s\d\w]+\s*=|=\s*[\d\w\s]+))", ctx_ldap()),
        (r"(?:\(\s*[&|]\s*)", ctx_ldap()),
        (r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", ctx_xml()),
        (r"(?:<!\[CDATA\[.*?\]\]>)", ctx_xml()),
        (r"(?:<\?xml.*?\?>)", ctx_xml()),
        (
            r"(?:^|\s|/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::(?:\d*)\]|(?:169\.254|192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d+)(?:\s|$|/)",
            ctx_ssrf(),
        ),
        (r"(?:file|dict|gopher|jar|tftp)://[^\s]+", ctx_ssrf()),
        (
            r"\{\s*\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|options):",
            ctx_nosql(),
        ),
        (r"(?:\{\s*\$[a-zA-Z]+\s*:\s*(?:\{|\[))", ctx_nosql()),
        (
            r#"(?i)filename=["'].*?\.(?:php\d*|phar|phtml|exe|jsp|asp|aspx|sh|bash|rb|py|pl|cgi|com|bat|cmd|vbs|vbe|js|ws|wsf|msi|hta)["']"#,
            ctx_file_upload(),
        ),
        (
            r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae%e0%80%ae|%25c0%25ae)/",
            ctx_path_traversal(),
        ),
        (
            r"\{\{\s*[^\}]+(?:system|exec|popen|eval|require|include)\s*\}\}",
            ctx_template(),
        ),
        (
            r"\{%\s*[^%]+(?:system|exec|popen|eval|require|include)\s*%\}",
            ctx_template(),
        ),
        (r"[\r\n]\s*(?:HTTP/[0-9.]+|Location:|Set-Cookie:)", ctx_http_split()),
        (r"(?:^|/)\.env(?:\.\w+)?(?:\?|$|/)", ctx_sensitive_file()),
        (
            r"(?:^|/)[\w-]*config[\w-]*\.(?:env|yml|yaml|json|toml|ini|xml|conf)(?:\?|$)",
            ctx_sensitive_file(),
        ),
        (r"(?:^|/)[\w./-]*\.map(?:\?|$)", ctx_sensitive_file()),
        (
            r"(?:^|/)[\w./-]*\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:\?|$)",
            ctx_sensitive_file(),
        ),
        (r"(?:^|/)\.(?:git|svn|hg|bzr)(?:/|$)", ctx_sensitive_file()),
        (
            r"(?:^|/)(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\.?(?:php)?(?:/|$|\?)",
            ctx_cms_probing(),
        ),
        (r"(?:^|/)(?:phpinfo|info|test|php_info)\.php(?:\?|$)", ctx_cms_probing()),
        (
            r"(?:^|/)[\w./-]*\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:\?|$)",
            ctx_cms_probing(),
        ),
        (
            r"(?:^|/)(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db|\.npmrc|\.dockerenv|web\.config)(?:\?|$)",
            ctx_cms_probing(),
        ),
        (
            r"(?:^|/)[\w./-]*\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action|lua|inc|woa|nsf|esp)(?:\?|$)",
            ctx_recon(),
        ),
        (
            r"^/(?:management|system|version|config_dump|credentials)(?:/|$|\?)",
            ctx_recon(),
        ),
        (r"(?:^|/)(?:actuator|server-status|telescope)(?:/|$|\?)", ctx_recon()),
        (
            r"(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login|myvpn|vpntunnel|versa/login)",
            ctx_recon(),
        ),
        (
            r"(?:^|/)(?:geoserver|confluence|nifi|ScadaBR|pandora_console|centreon|kylin|decisioncenter|evox|MagicInfo|metasys|officescan|helpdesk|ignite)(?:/|$|\?|\.|-)",
            ctx_recon(),
        ),
        (r"(?:^|/)cgi-(?:bin|mod)/", ctx_recon()),
        (r"(?:^|/)(?:HNAP1|IPCamDesc\.xml|SDK/webLanguage)(?:\?|$|/)", ctx_recon()),
        (r"^/(?:language|languages)/", ctx_recon()),
        (
            r"(?:^|/)(?:robots\.txt|sitemap\.xml|security\.txt|readme\.txt|README\.md|CHANGELOG|pom\.xml|build\.gradle|appsettings\.json|crossdomain\.xml)(?:\?|$|\.)",
            ctx_recon(),
        ),
        (
            r"(?:^|/)(?:sap|ise|nidp|cslu|rustfs|developmentserver|fog/management|lms/db|json/login_session|sms_mp|plugin/webs_model|wsman|am_bin)(?:/|$|\?)",
            ctx_recon(),
        ),
        (r"(?:nmaplowercheck|nice\s+ports|Trinity\.txt)", ctx_recon()),
        (r"(?:^|/)\.(?:openclaw|clawdbot)(?:/|$)", ctx_recon()),
        (r"^/(?:default|inicio|indice|localstart)(?:\.|/|$|\?)", ctx_recon()),
        (
            r"(?:^|/)(?:\.streamlit|\.gpt-pilot|\.aider|\.cursor|\.windsurf|\.copilot|\.devcontainer)(?:/|$)",
            ctx_recon(),
        ),
        (
            r"(?:^|/)(?:docker-compose|Dockerfile|Makefile|Vagrantfile|Jenkinsfile|Procfile)(?:\.ya?ml)?(?:\?|$)",
            ctx_recon(),
        ),
        (
            r"(?:^|/)[\w./-]*(?:secrets?|credentials?)\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)(?:\?|$)",
            ctx_recon(),
        ),
        (r"(?:^|/)autodiscover/", ctx_recon()),
        (r"^/dns-query(?:\?|$)", ctx_recon()),
        (r"(?:^|/)\.git/(?:refs|index|HEAD|objects|logs)(?:/|$)", ctx_recon()),
    ]
}

/// Compiled default pattern paired with the contexts it applies to.
pub type CompiledPattern = (Regex, HashSet<&'static str>);
/// Compiled custom pattern paired with the source string and contexts.
pub type CompiledCustomPattern = (Regex, String, HashSet<&'static str>);

/// Combined regex and semantic pattern manager driving suspicious-activity
/// detection.
pub struct SusPatternsManager {
    patterns: RwLock<Vec<String>>,
    custom_patterns: RwLock<HashSet<String>>,
    compiled_patterns: RwLock<Vec<CompiledPattern>>,
    compiled_custom_patterns: RwLock<Vec<CompiledCustomPattern>>,
    redis_handler: SyncRwLock<Option<DynRedisHandler>>,
    agent_handler: SyncRwLock<Option<DynAgentHandler>>,
    compiler: Option<Arc<PatternCompiler>>,
    preprocessor: Option<Arc<ContentPreprocessor>>,
    semantic_analyzer: Option<Arc<SemanticAnalyzer>>,
    performance_monitor: Option<Arc<PerformanceMonitor>>,
    semantic_threshold: SyncRwLock<f64>,
}

impl std::fmt::Debug for SusPatternsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SusPatternsManager")
            .field("semantic_threshold", &*self.semantic_threshold.read())
            .field("compiler", &self.compiler.is_some())
            .field("preprocessor", &self.preprocessor.is_some())
            .field("semantic_analyzer", &self.semantic_analyzer.is_some())
            .field("performance_monitor", &self.performance_monitor.is_some())
            .finish()
    }
}

impl Default for SusPatternsManager {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Per-request detection outcome produced by
/// [`crate::handlers::suspatterns::SusPatternsManager::detect`].
pub struct DetectionResult {
    /// Whether any regex or semantic match was found.
    pub is_threat: bool,
    /// Aggregate threat score in the range 0.0-1.0.
    pub threat_score: f64,
    /// Raw regex and semantic threats that contributed to the score.
    pub threats: Vec<Value>,
    /// Context tag supplied by the caller (path, header, ...).
    pub context: String,
    /// Original input length in bytes.
    pub original_length: usize,
    /// Length of the input after preprocessing.
    pub processed_length: usize,
    /// Total execution time in seconds.
    pub execution_time: f64,
    /// Marker indicating whether the enhanced engine ran or the legacy path.
    pub detection_method: &'static str,
    /// Patterns that timed out during evaluation.
    pub timeouts: Vec<String>,
    /// Optional correlation id propagated into events.
    pub correlation_id: Option<String>,
}

impl std::fmt::Debug for DetectionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetectionResult")
            .field("is_threat", &self.is_threat)
            .field("threat_score", &self.threat_score)
            .field("context", &self.context)
            .field("original_length", &self.original_length)
            .field("processed_length", &self.processed_length)
            .field("execution_time", &self.execution_time)
            .field("detection_method", &self.detection_method)
            .field("timeouts", &self.timeouts)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

impl DetectionResult {
    /// Converts the result into a JSON payload suitable for telemetry.
    pub fn to_value(&self) -> Value {
        json!({
            "is_threat": self.is_threat,
            "threat_score": self.threat_score,
            "threats": self.threats,
            "context": self.context,
            "original_length": self.original_length,
            "processed_length": self.processed_length,
            "execution_time": self.execution_time,
            "detection_method": self.detection_method,
            "timeouts": self.timeouts,
            "correlation_id": self.correlation_id,
        })
    }
}

struct ThreatEventArgs<'a> {
    matched_patterns: &'a [String],
    semantic_threats: &'a [Value],
    ip_address: &'a str,
    context: &'a str,
    content: &'a str,
    threat_score: f64,
    threats: &'a [Value],
    regex_threats: &'a [Value],
    timeouts: &'a [String],
    execution_time: f64,
    correlation_id: Option<&'a str>,
}

impl SusPatternsManager {
    /// Creates a new manager from the supplied (optional) security config.
    ///
    /// The enhanced engine components (compiler, preprocessor, semantic
    /// analyser, monitor) are instantiated only when `config` is provided.
    pub fn new(config: Option<&SecurityConfig>) -> Self {
        let defs = pattern_definitions();
        let patterns: Vec<String> = defs.iter().map(|(p, _)| (*p).to_string()).collect();
        let compiled_patterns: Vec<CompiledPattern> = defs
            .iter()
            .filter_map(|(pat, ctxs)| {
                PatternCompiler::default()
                    .compile_pattern_sync(pat, RegexFlags::default_flags())
                    .ok()
                    .map(|re| (re, ctxs.clone()))
            })
            .collect();

        let (compiler, preprocessor, semantic_analyzer, performance_monitor, semantic_threshold) =
            match config {
                Some(cfg) => (
                    Some(Arc::new(PatternCompiler::new(
                        Duration::from_secs_f64(cfg.detection_compiler_timeout),
                        cfg.detection_max_tracked_patterns,
                    ))),
                    Some(Arc::new(ContentPreprocessor::new(
                        cfg.detection_max_content_length,
                        cfg.detection_preserve_attack_patterns,
                        None,
                        None,
                    ))),
                    Some(Arc::new(SemanticAnalyzer::new())),
                    Some(Arc::new(PerformanceMonitor::new(
                        cfg.detection_anomaly_threshold,
                        cfg.detection_slow_pattern_threshold,
                        cfg.detection_monitor_history_size,
                        cfg.detection_max_tracked_patterns,
                    ))),
                    cfg.detection_semantic_threshold,
                ),
                None => (None, None, None, None, 0.7),
            };

        Self {
            patterns: RwLock::new(patterns),
            custom_patterns: RwLock::new(HashSet::new()),
            compiled_patterns: RwLock::new(compiled_patterns),
            compiled_custom_patterns: RwLock::new(Vec::new()),
            redis_handler: SyncRwLock::new(None),
            agent_handler: SyncRwLock::new(None),
            compiler,
            preprocessor,
            semantic_analyzer,
            performance_monitor,
            semantic_threshold: SyncRwLock::new(semantic_threshold),
        }
    }

    /// Convenience constructor returning an
    /// [`Arc`]-wrapped manager.
    pub fn arc(config: Option<&SecurityConfig>) -> Arc<Self> {
        Arc::new(Self::new(config))
    }

    /// Wires in the Redis handler and replays any persisted custom patterns.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when the cached
    /// pattern set cannot be read.
    pub async fn initialize_redis(self: &Arc<Self>, redis_handler: DynRedisHandler) -> Result<()> {
        *self.redis_handler.write() = Some(redis_handler.clone());
        if let Some(Value::String(cached)) = redis_handler.get_key("patterns", "custom").await? {
            let existing: HashSet<String> = self.custom_patterns.read().await.clone();
            for pattern in cached.split(',') {
                if pattern.is_empty() {
                    continue;
                }
                if !existing.contains(pattern) {
                    self.add_pattern(pattern, true).await?;
                }
            }
        }
        Ok(())
    }

    /// Installs the Guard Agent handler used for threat events.
    pub async fn initialize_agent(&self, agent_handler: DynAgentHandler) {
        *self.agent_handler.write() = Some(agent_handler);
    }

    async fn send_pattern_event(
        &self,
        event_type: &str,
        ip_address: &str,
        action_taken: &str,
        reason: &str,
        metadata: Map<String, Value>,
    ) {
        let Some(agent) = self.agent_handler.read().clone() else {
            return;
        };
        let event = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": event_type,
            "ip_address": ip_address,
            "action_taken": action_taken,
            "reason": reason,
            "metadata": metadata,
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send pattern event to agent: {e}");
        }
    }

    async fn preprocess_content(&self, content: &str, correlation_id: Option<&str>) -> String {
        let Some(pre) = &self.preprocessor else {
            return content.to_string();
        };
        let agent = self.agent_handler.read().clone();
        let context_preprocessor = ContentPreprocessor::new(
            pre.max_content_length,
            pre.preserve_attack_patterns,
            agent,
            correlation_id.map(String::from),
        );
        context_preprocessor.preprocess(content).await
    }

    async fn check_regex_pattern(
        &self,
        pattern: &Regex,
        pattern_str: &str,
        content: &str,
        pattern_start: Instant,
    ) -> (Option<Value>, bool) {
        if let Some(compiler) = &self.compiler {
            let compiled = match compiler
                .compile_pattern(pattern_str, RegexFlags::default_flags())
                .await
            {
                Ok(re) => re,
                Err(_) => pattern.clone(),
            };
            let content_owned = content.to_string();
            let timeout_duration = compiler.default_timeout();
            let search_result = tokio::time::timeout(
                timeout_duration,
                tokio::task::spawn_blocking(move || {
                    compiled.find(&content_owned).map(|m| (m.as_str().to_string(), m.start()))
                }),
            )
            .await;
            match search_result {
                Ok(Ok(Some((matched, start)))) => {
                    let execution_time = pattern_start.elapsed().as_secs_f64();
                    (
                        Some(json!({
                            "type": "regex",
                            "pattern": pattern_str,
                            "match": matched,
                            "position": start,
                            "execution_time": execution_time,
                        })),
                        false,
                    )
                }
                Ok(Ok(None)) => {
                    let elapsed = pattern_start.elapsed().as_secs_f64();
                    let timeout_occurred = elapsed >= 0.9 * 2.0;
                    if timeout_occurred {
                        warn!("Pattern timeout: {}...", truncate_for_log(pattern_str, 50));
                    }
                    (None, timeout_occurred)
                }
                _ => {
                    warn!("Pattern timeout: {}...", truncate_for_log(pattern_str, 50));
                    (None, true)
                }
            }
        } else {
            self.check_pattern_with_timeout(pattern, pattern_str, content, pattern_start)
                .await
        }
    }

    async fn check_pattern_with_timeout(
        &self,
        pattern: &Regex,
        pattern_str: &str,
        content: &str,
        pattern_start: Instant,
    ) -> (Option<Value>, bool) {
        let pattern_clone = pattern.clone();
        let content_owned = content.to_string();
        let result = tokio::time::timeout(
            Duration::from_secs_f64(2.0),
            tokio::task::spawn_blocking(move || {
                pattern_clone
                    .find(&content_owned)
                    .map(|m| (m.as_str().to_string(), m.start()))
            }),
        )
        .await;
        match result {
            Ok(Ok(Some((matched, start)))) => {
                let execution_time = pattern_start.elapsed().as_secs_f64();
                (
                    Some(json!({
                        "type": "regex",
                        "pattern": pattern_str,
                        "match": matched,
                        "position": start,
                        "execution_time": execution_time,
                    })),
                    false,
                )
            }
            Ok(Ok(None)) => (None, false),
            Ok(Err(e)) => {
                error!(
                    "Error in regex search for pattern {}...: {e}",
                    truncate_for_log(pattern_str, 50)
                );
                (None, false)
            }
            Err(_) => {
                warn!(
                    "Regex timeout exceeded for pattern: {}... Potential ReDoS attack blocked.",
                    truncate_for_log(pattern_str, 50)
                );
                (None, true)
            }
        }
    }

    fn normalize_context(context: &str) -> String {
        let normalized = context.split_once(':').map_or(context, |(head, _)| head);
        if known_contexts().contains(normalized) {
            normalized.to_string()
        } else {
            CTX_UNKNOWN.to_string()
        }
    }

    async fn check_regex_patterns(
        &self,
        content: &str,
        correlation_id: Option<&str>,
        context: &str,
    ) -> (Vec<Value>, Vec<String>, Vec<String>) {
        let mut threats: Vec<Value> = Vec::new();
        let mut matched_patterns: Vec<String> = Vec::new();
        let mut timeouts: Vec<String> = Vec::new();

        let all_patterns = self.get_all_compiled_patterns().await;
        let normalized = Self::normalize_context(context);
        let skip_filter = normalized == CTX_UNKNOWN || normalized == CTX_REQUEST_BODY;

        for (pattern, contexts) in &all_patterns {
            if !skip_filter && !contexts.contains(normalized.as_str()) {
                continue;
            }

            let pattern_str = pattern.as_str().to_string();
            let pattern_start = Instant::now();

            let (threat, timeout_occurred) = self
                .check_regex_pattern(pattern, &pattern_str, content, pattern_start)
                .await;

            if timeout_occurred {
                timeouts.push(pattern_str.clone());
            }

            let matched = threat.is_some();
            if let Some(threat) = threat {
                threats.push(threat);
                matched_patterns.push(pattern_str.clone());
            }

            if let Some(monitor) = &self.performance_monitor {
                let agent = self.agent_handler.read().clone();
                monitor
                    .record_metric(crate::detection_engine::RecordMetricInput {
                        pattern: &pattern_str,
                        execution_time: pattern_start.elapsed().as_secs_f64(),
                        content_length: content.len(),
                        matched,
                        timeout: timeout_occurred,
                        agent_handler: agent.as_ref(),
                        correlation_id,
                    })
                    .await;
            }
        }

        (threats, matched_patterns, timeouts)
    }

    async fn check_semantic_threats(&self, content: &str) -> (Vec<Value>, f64) {
        let Some(analyzer) = &self.semantic_analyzer else {
            return (Vec::new(), 0.0);
        };
        let analysis = analyzer.analyze(content);
        let semantic_score = analyzer.get_threat_score(&analysis);
        let threshold = *self.semantic_threshold.read();
        let mut threats: Vec<Value> = Vec::new();

        if semantic_score > threshold {
            if let Some(probs) = analysis
                .get("attack_probabilities")
                .and_then(Value::as_object)
            {
                for (attack_type, prob_val) in probs {
                    let probability = prob_val.as_f64().unwrap_or(0.0);
                    if probability >= threshold {
                        threats.push(json!({
                            "type": "semantic",
                            "attack_type": attack_type,
                            "probability": probability,
                            "analysis": analysis,
                        }));
                    }
                }
            }

            if threats.is_empty() && semantic_score >= threshold {
                threats.push(json!({
                    "type": "semantic",
                    "attack_type": "suspicious",
                    "threat_score": semantic_score,
                    "analysis": analysis,
                }));
            }
        }

        (threats, semantic_score)
    }

    fn calculate_threat_score(regex_threats: &[Value], semantic_threats: &[Value]) -> f64 {
        if regex_threats.is_empty() && semantic_threats.is_empty() {
            return 0.0;
        }
        let regex_score: f64 = if regex_threats.is_empty() { 0.0 } else { 1.0 };
        let semantic_max: f64 = semantic_threats
            .iter()
            .map(|t| {
                t.get("probability")
                    .and_then(Value::as_f64)
                    .or_else(|| t.get("threat_score").and_then(Value::as_f64))
                    .unwrap_or(0.0)
            })
            .fold(0.0_f64, f64::max);
        f64::max(regex_score, semantic_max)
    }

    /// Runs every enabled detection layer against `content`.
    pub async fn detect(
        &self,
        content: &str,
        ip_address: &str,
        context: &str,
        correlation_id: Option<&str>,
    ) -> DetectionResult {
        let original_length = content.len();
        let execution_start = Instant::now();

        let processed_content = self.preprocess_content(content, correlation_id).await;

        let (regex_threats, matched_patterns, timeouts) = self
            .check_regex_patterns(&processed_content, correlation_id, context)
            .await;

        let (semantic_threats, _semantic_score) =
            self.check_semantic_threats(&processed_content).await;

        let mut threats = regex_threats.clone();
        threats.extend(semantic_threats.clone());
        let is_threat = !threats.is_empty();

        let threat_score = Self::calculate_threat_score(&regex_threats, &semantic_threats);
        let total_execution_time = execution_start.elapsed().as_secs_f64();
        let detection_method = if self.compiler.is_some() { "enhanced" } else { "legacy" };

        if let Some(monitor) = &self.performance_monitor {
            let agent = self.agent_handler.read().clone();
            monitor
                .record_metric(crate::detection_engine::RecordMetricInput {
                    pattern: "overall_detection",
                    execution_time: total_execution_time,
                    content_length: content.len(),
                    matched: is_threat,
                    timeout: false,
                    agent_handler: agent.as_ref(),
                    correlation_id,
                })
                .await;
        }

        if is_threat {
            self.send_threat_event(ThreatEventArgs {
                matched_patterns: &matched_patterns,
                semantic_threats: &semantic_threats,
                ip_address,
                context,
                content,
                threat_score,
                threats: &threats,
                regex_threats: &regex_threats,
                timeouts: &timeouts,
                execution_time: total_execution_time,
                correlation_id,
            })
            .await;
        }

        DetectionResult {
            is_threat,
            threat_score,
            threats,
            context: context.to_string(),
            original_length,
            processed_length: processed_content.len(),
            execution_time: total_execution_time,
            detection_method,
            timeouts,
            correlation_id: correlation_id.map(String::from),
        }
    }

    async fn send_threat_event(&self, args: ThreatEventArgs<'_>) {
        let pattern_info = if let Some(first) = args.matched_patterns.first() {
            first.clone()
        } else if let Some(first) = args.semantic_threats.first() {
            let attack_type = first
                .get("attack_type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            format!("semantic:{attack_type}")
        } else {
            "unknown".to_string()
        };

        let detection_method = if self.compiler.is_some() { "enhanced" } else { "legacy" };
        let content_preview = if args.content.len() > 100 {
            &args.content[..100]
        } else {
            args.content
        };

        let mut metadata = Map::new();
        metadata.insert("pattern".into(), json!(pattern_info));
        metadata.insert("context".into(), json!(args.context));
        metadata.insert("content_preview".into(), json!(content_preview));
        metadata.insert("threat_score".into(), json!(args.threat_score));
        metadata.insert("threats".into(), json!(args.threats.len()));
        metadata.insert("regex_threats".into(), json!(args.regex_threats.len()));
        metadata.insert("semantic_threats".into(), json!(args.semantic_threats.len()));
        metadata.insert("timeouts".into(), json!(args.timeouts.len()));
        metadata.insert("detection_method".into(), json!(detection_method));
        metadata.insert(
            "execution_time_ms".into(),
            json!((args.execution_time * 1000.0) as i64),
        );
        metadata.insert("correlation_id".into(), json!(args.correlation_id));

        let reason = format!("Threat detected in {}", args.context);
        self.send_pattern_event(
            "pattern_detected",
            args.ip_address,
            "threat_detected",
            &reason,
            metadata,
        )
        .await;
    }

    /// Convenience wrapper around
    /// [`crate::handlers::suspatterns::SusPatternsManager::detect`] that
    /// returns `(is_threat, trigger_info)`.
    pub async fn detect_pattern_match(
        &self,
        content: &str,
        ip_address: &str,
        context: &str,
        correlation_id: Option<&str>,
    ) -> (bool, Option<String>) {
        let result = self.detect(content, ip_address, context, correlation_id).await;

        if result.is_threat {
            if let Some(first) = result.threats.first() {
                let threat_type = first.get("type").and_then(Value::as_str).unwrap_or("");
                if threat_type == "regex" {
                    let pattern = first
                        .get("pattern")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    return (true, Some(pattern));
                }
                if threat_type == "semantic" {
                    let attack_type = first
                        .get("attack_type")
                        .and_then(Value::as_str)
                        .unwrap_or("suspicious");
                    return (true, Some(format!("semantic:{attack_type}")));
                }
            }
            return (true, Some("unknown".to_string()));
        }

        (false, None)
    }

    /// Registers an additional regex `pattern`. When `custom` is `true` the
    /// pattern is persisted to Redis and exported to agent events.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Pattern`] on compilation
    /// failure or [`crate::error::GuardCoreError::Redis`] on Redis error.
    pub async fn add_pattern(self: &Arc<Self>, pattern: &str, custom: bool) -> Result<()> {
        let compiled = PatternCompiler::default()
            .compile_pattern_sync(pattern, RegexFlags::default_flags())?;
        let contexts = ctx_all();

        if custom {
            let mut compiled_custom = self.compiled_custom_patterns.write().await;
            if !compiled_custom.iter().any(|(_, p, _)| p == pattern) {
                compiled_custom.push((compiled, pattern.to_string(), contexts));
            }
            drop(compiled_custom);

            let mut custom_set = self.custom_patterns.write().await;
            custom_set.insert(pattern.to_string());
            let joined = custom_set
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            drop(custom_set);

            let redis = self.redis_handler.read().clone();
            if let Some(redis) = redis {
                redis
                    .set_key("patterns", "custom", Value::String(joined), None)
                    .await?;
            }
        } else {
            self.compiled_patterns.write().await.push((compiled, contexts));
            self.patterns.write().await.push(pattern.to_string());
        }

        if let Some(compiler) = &self.compiler {
            compiler.clear_cache().await;
        }

        if self.agent_handler.read().is_some() {
            let pattern_kind = if custom { "Custom" } else { "Default" };
            let pattern_type = if custom { "custom" } else { "default" };
            let total_patterns = if custom {
                self.custom_patterns.read().await.len()
            } else {
                self.patterns.read().await.len()
            };
            let mut metadata = Map::new();
            metadata.insert("pattern".into(), json!(pattern));
            metadata.insert("pattern_type".into(), json!(pattern_type));
            metadata.insert("total_patterns".into(), json!(total_patterns));
            let reason = format!("{pattern_kind} pattern added to detection system");
            self.send_pattern_event(
                "pattern_added",
                "system",
                "pattern_added",
                &reason,
                metadata,
            )
            .await;
        }

        Ok(())
    }

    async fn remove_custom_pattern(&self, pattern: &str) -> Result<bool> {
        let mut custom_set = self.custom_patterns.write().await;
        if !custom_set.contains(pattern) {
            return Ok(false);
        }
        custom_set.remove(pattern);
        let joined = custom_set.iter().cloned().collect::<Vec<_>>().join(",");
        drop(custom_set);

        let mut compiled_custom = self.compiled_custom_patterns.write().await;
        compiled_custom.retain(|(_, p, _)| p != pattern);
        drop(compiled_custom);

        let redis = self.redis_handler.read().clone();
        if let Some(redis) = redis {
            redis
                .set_key("patterns", "custom", Value::String(joined), None)
                .await?;
        }

        Ok(true)
    }

    async fn remove_default_pattern(&self, pattern: &str) -> bool {
        let mut patterns = self.patterns.write().await;
        let Some(index) = patterns.iter().position(|p| p == pattern) else {
            return false;
        };
        patterns.remove(index);
        drop(patterns);

        let mut compiled = self.compiled_patterns.write().await;
        if index < compiled.len() {
            compiled.remove(index);
            true
        } else {
            false
        }
    }

    async fn clear_pattern_caches(&self, pattern: &str) {
        if let Some(compiler) = &self.compiler {
            compiler.clear_cache().await;
        }
        if let Some(monitor) = &self.performance_monitor {
            monitor.remove_pattern_stats(pattern).await;
        }
    }

    async fn send_pattern_removal_event(&self, pattern: &str, custom: bool, total_patterns: usize) {
        if self.agent_handler.read().is_none() {
            return;
        }
        let pattern_kind = if custom { "Custom" } else { "Default" };
        let pattern_type = if custom { "custom" } else { "default" };
        let mut metadata = Map::new();
        metadata.insert("pattern".into(), json!(pattern));
        metadata.insert("pattern_type".into(), json!(pattern_type));
        metadata.insert("total_patterns".into(), json!(total_patterns));
        let reason = format!("{pattern_kind} pattern removed from detection system");
        self.send_pattern_event(
            "pattern_removed",
            "system",
            "pattern_removed",
            &reason,
            metadata,
        )
        .await;
    }

    /// Removes a registered pattern. Returns `true` if it was present.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Redis`] when persistence
    /// fails.
    pub async fn remove_pattern(&self, pattern: &str, custom: bool) -> Result<bool> {
        let removed = if custom {
            self.remove_custom_pattern(pattern).await?
        } else {
            self.remove_default_pattern(pattern).await
        };

        if removed {
            self.clear_pattern_caches(pattern).await;
            let total_patterns = if custom {
                self.custom_patterns.read().await.len()
            } else {
                self.patterns.read().await.len()
            };
            self.send_pattern_removal_event(pattern, custom, total_patterns)
                .await;
        }

        Ok(removed)
    }

    /// Returns the default pattern list (source strings).
    pub async fn get_default_patterns(&self) -> Vec<String> {
        self.patterns.read().await.clone()
    }

    /// Returns the user-supplied custom pattern list.
    pub async fn get_custom_patterns(&self) -> Vec<String> {
        self.custom_patterns.read().await.iter().cloned().collect()
    }

    /// Returns defaults concatenated with custom patterns.
    pub async fn get_all_patterns(&self) -> Vec<String> {
        let mut out = self.patterns.read().await.clone();
        for p in self.custom_patterns.read().await.iter() {
            out.push(p.clone());
        }
        out
    }

    /// Returns the default compiled patterns with their applicable contexts.
    pub async fn get_default_compiled_patterns(&self) -> Vec<CompiledPattern> {
        self.compiled_patterns.read().await.clone()
    }

    /// Returns the compiled custom patterns with their applicable contexts.
    pub async fn get_custom_compiled_patterns(&self) -> Vec<CompiledPattern> {
        self.compiled_custom_patterns
            .read()
            .await
            .iter()
            .map(|(re, _, ctx)| (re.clone(), ctx.clone()))
            .collect()
    }

    /// Returns defaults concatenated with custom compiled patterns.
    pub async fn get_all_compiled_patterns(&self) -> Vec<CompiledPattern> {
        let mut out = self.compiled_patterns.read().await.clone();
        for (re, _, ctx) in self.compiled_custom_patterns.read().await.iter() {
            out.push((re.clone(), ctx.clone()));
        }
        out
    }

    /// Returns a JSON snapshot of the monitor stats (when the enhanced engine
    /// is configured).
    pub async fn get_performance_stats(&self) -> Option<Value> {
        let monitor = self.performance_monitor.as_ref()?;
        Some(json!({
            "summary": monitor.get_summary_stats().await,
            "slow_patterns": monitor.get_slow_patterns(10).await,
            "problematic_patterns": monitor.get_problematic_patterns().await,
        }))
    }

    /// Returns a JSON map describing which enhanced-engine components are
    /// enabled.
    pub fn get_component_status(&self) -> Value {
        json!({
            "compiler": self.compiler.is_some(),
            "preprocessor": self.preprocessor.is_some(),
            "semantic_analyzer": self.semantic_analyzer.is_some(),
            "performance_monitor": self.performance_monitor.is_some(),
        })
    }

    /// Updates the semantic threshold. Values outside `0.0..=1.0` are
    /// clamped.
    pub async fn configure_semantic_threshold(&self, threshold: f64) {
        let clamped = threshold.clamp(0.0, 1.0);
        *self.semantic_threshold.write() = clamped;
    }

    /// Clears custom patterns, Redis/agent handles, compiled caches, and
    /// pattern stats.
    ///
    /// # Errors
    ///
    /// This implementation never errors; the [`Result`] return preserves
    /// API compatibility.
    pub async fn reset(&self) -> Result<()> {
        self.custom_patterns.write().await.clear();
        self.compiled_custom_patterns.write().await.clear();
        *self.redis_handler.write() = None;
        *self.agent_handler.write() = None;

        if let Some(compiler) = &self.compiler {
            compiler.clear_cache().await;
        }
        if let Some(monitor) = &self.performance_monitor {
            monitor.clear_stats().await;
        }
        Ok(())
    }
}

fn truncate_for_log(input: &str, max: usize) -> &str {
    if input.len() <= max {
        input
    } else {
        let mut end = max;
        while !input.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        &input[..end]
    }
}
