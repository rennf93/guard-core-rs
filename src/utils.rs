//! Shared utility functions used by every check and handler.
//!
//! Includes client IP extraction, proxy trust validation, logging helpers,
//! and agent event dispatch. State keys such as
//! [`crate::utils::CLIENT_IP_KEY`] and
//! [`crate::utils::PIPELINE_START_KEY`] are consumed by
//! [`crate::protocols::request::RequestState`] during the request lifecycle.

use std::net::IpAddr;

use chrono::Utc;
use ipnet::IpNet;
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::error::Result;
use crate::models::{LogLevel, SecurityConfig};
use crate::protocols::agent::DynAgentHandler;
use crate::protocols::geo_ip::DynGeoIpHandler;
use crate::protocols::request::{DynGuardRequest, StateValue};

/// [`crate::protocols::request::RequestState`] key storing the pipeline start
/// timestamp (milliseconds since epoch).
pub const PIPELINE_START_KEY: &str = "_guard_pipeline_start";
/// [`crate::protocols::request::RequestState`] key storing the extracted
/// client IP.
pub const CLIENT_IP_KEY: &str = "client_ip";

/// Escapes control characters in `value` so the result is safe to log.
///
/// Newlines, carriage returns, tabs, and other control characters are replaced
/// by printable escape sequences.
pub fn sanitize_for_log(value: &str) -> String {
    if value.is_empty() {
        return value.into();
    }
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Returns the pipeline response time in seconds, seeding
/// [`crate::utils::PIPELINE_START_KEY`] on the first call.
///
/// Returns [`None`] when `request` is [`None`].
pub fn get_pipeline_response_time(request: Option<&DynGuardRequest>) -> Option<f64> {
    let request = request?;
    let state = request.state();
    let start_epoch_ms = state.get_f64(PIPELINE_START_KEY).unwrap_or_else(|| {
        let now = epoch_ms();
        state.set_f64(PIPELINE_START_KEY, now);
        now
    });
    let now = epoch_ms();
    Some((now - start_epoch_ms) / 1000.0)
}

fn epoch_ms() -> f64 {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    duration.as_secs_f64() * 1000.0
}

/// Builds and dispatches an agent event describing a security action.
///
/// Does nothing when `agent_handler` is [`None`]. Errors raised by the agent
/// are logged and swallowed so security decisions are never blocked by
/// telemetry failures.
pub async fn send_agent_event(
    agent_handler: Option<&DynAgentHandler>,
    event_type: &str,
    ip_address: &str,
    action_taken: &str,
    reason: &str,
    request: Option<&DynGuardRequest>,
    extra: serde_json::Map<String, Value>,
) {
    let Some(agent) = agent_handler else { return };

    let (endpoint, method, user_agent) = if let Some(req) = request {
        (
            Some(req.url_path()),
            Some(req.method()),
            req.header("User-Agent"),
        )
    } else {
        (None, None, None)
    };

    let response_time = get_pipeline_response_time(request);

    let mut event = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "event_type": event_type,
        "ip_address": ip_address,
        "action_taken": action_taken,
        "reason": reason,
        "endpoint": endpoint,
        "method": method,
        "user_agent": user_agent,
        "response_time": response_time,
    });

    if let Value::Object(ref mut map) = event {
        for (k, v) in extra {
            map.insert(k, v);
        }
    }

    if let Err(e) = agent.send_event(event).await {
        error!("Failed to send agent event: {e}");
    }
}

/// Returns `true` when `connecting_ip` matches any configured trusted proxy
/// IP or CIDR range.
pub fn is_trusted_proxy(connecting_ip: &str, trusted_proxies: &[String]) -> bool {
    let Ok(ip) = connecting_ip.parse::<IpAddr>() else {
        return false;
    };
    for proxy in trusted_proxies {
        if proxy.contains('/') {
            if let Ok(net) = proxy.parse::<IpNet>()
                && net.contains(&ip)
            {
                return true;
            }
        } else if connecting_ip == proxy {
            return true;
        }
    }
    false
}

/// Extracts the originating client IP from an `X-Forwarded-For` header.
///
/// Returns [`None`] if the header is empty or does not contain at least
/// `proxy_depth` entries.
pub fn extract_from_forwarded_header(forwarded_for: &str, proxy_depth: u32) -> Option<String> {
    if forwarded_for.is_empty() {
        return None;
    }
    let ips: Vec<&str> = forwarded_for.split(',').map(str::trim).collect();
    if (ips.len() as u32) >= proxy_depth {
        Some(ips[0].to_string())
    } else {
        None
    }
}

/// Returns the effective client IP for a request, honouring trusted proxies.
///
/// Caches the result in [`crate::protocols::request::RequestState`] under
/// [`crate::utils::CLIENT_IP_KEY`]. When `X-Forwarded-For` is supplied from
/// an untrusted IP, the attempt is logged and forwarded to the agent as a
/// spoofing event.
pub async fn extract_client_ip(
    request: &DynGuardRequest,
    config: &SecurityConfig,
    agent_handler: Option<&DynAgentHandler>,
) -> String {
    let state = request.state();
    if let Some(cached) = state.get_str(CLIENT_IP_KEY) {
        return cached;
    }

    let Some(connecting_ip) = request.client_host() else {
        return "unknown".into();
    };

    let forwarded_for = request.header("X-Forwarded-For");

    if config.trusted_proxies.is_empty() {
        return connecting_ip;
    }

    let trusted = is_trusted_proxy(&connecting_ip, &config.trusted_proxies);

    if !trusted {
        if let Some(fwd) = forwarded_for.as_deref() {
            let safe = sanitize_for_log(fwd);
            warn!(
                "Potential IP spoof attempt: X-Forwarded-For header ({safe}) received from untrusted IP {connecting_ip}"
            );
            let mut extra = serde_json::Map::new();
            extra.insert("x_forwarded_for".into(), Value::String(fwd.to_string()));
            send_agent_event(
                agent_handler,
                "suspicious_request",
                &connecting_ip,
                "spoofing_detected",
                &format!("Potential IP spoof attempt: X-Forwarded-For header {fwd}"),
                Some(request),
                extra,
            )
            .await;
        }
        return connecting_ip;
    }

    if let Some(fwd) = forwarded_for
        && let Some(client_ip) = extract_from_forwarded_header(&fwd, config.trusted_proxy_depth)
    {
        return client_ip;
    }

    connecting_ip
}

/// Returns `true` when the `user_agent` string is not blocked by any pattern
/// in `config.blocked_user_agents`.
pub fn is_user_agent_allowed(user_agent: &str, config: &SecurityConfig) -> bool {
    for pattern in &config.blocked_user_agents {
        let Ok(re) = regex::RegexBuilder::new(pattern).case_insensitive(true).build() else {
            continue;
        };
        if re.is_match(user_agent) {
            return false;
        }
    }
    true
}

/// Resolves `ip` against the configured country allow- and block-lists.
///
/// Returns `Ok(true)` when the country is explicitly blocked.
///
/// # Errors
///
/// Returns [`crate::error::GuardCoreError::GeoIp`] when the GeoIP database
/// cannot be initialised.
pub async fn check_ip_country(
    ip: &str,
    config: &SecurityConfig,
    geo_ip_handler: &DynGeoIpHandler,
) -> Result<bool> {
    if !has_country_rules(config) {
        warn!("No countries blocked or whitelisted {ip} - No countries blocked or whitelisted");
        return Ok(false);
    }

    if !geo_ip_handler.is_initialized() {
        geo_ip_handler.initialize().await?;
    }

    let Some(country) = geo_ip_handler.get_country(ip) else {
        warn!("IP not geolocated {ip} - IP geolocation failed");
        return Ok(false);
    };

    if config.whitelist_countries.contains(&country) {
        info!("IP from whitelisted country {ip} - {country} - IP from whitelisted country");
        return Ok(false);
    }
    if config.blocked_countries.contains(&country) {
        warn!("IP from blocked country {ip} - {country} - IP from blocked country");
        return Ok(true);
    }
    info!(
        "IP not from blocked or whitelisted country {ip} - {country} - IP not from blocked or whitelisted country"
    );
    Ok(false)
}

fn has_country_rules(config: &SecurityConfig) -> bool {
    !config.blocked_countries.is_empty() || !config.whitelist_countries.is_empty()
}

/// Returns `true` when `ip` is permitted by the global allow/block lists.
///
/// Combines the IP blacklist, IP whitelist, and country rules. A parse
/// failure on `ip` produces `false`.
pub async fn is_ip_allowed(
    ip: &str,
    config: &SecurityConfig,
    geo_ip_handler: Option<&DynGeoIpHandler>,
) -> bool {
    let Ok(ip_addr) = ip.parse::<IpAddr>() else {
        return false;
    };

    if !check_blacklist(&ip_addr, ip, config) {
        return false;
    }
    if !check_whitelist(&ip_addr, ip, config) {
        return false;
    }
    if let Some(handler) = geo_ip_handler
        && !config.blocked_countries.is_empty()
    {
        match check_ip_country(ip, config, handler).await {
            Ok(true) => return false,
            Ok(false) => {}
            Err(e) => {
                error!("Error checking country for IP {ip}: {e}");
                return true;
            }
        }
    }
    true
}

fn check_blacklist(ip_addr: &IpAddr, ip: &str, config: &SecurityConfig) -> bool {
    for blocked in &config.blacklist {
        if blocked.contains('/') {
            if let Ok(net) = blocked.parse::<IpNet>()
                && net.contains(ip_addr)
            {
                return false;
            }
        } else if ip == blocked {
            return false;
        }
    }
    true
}

fn check_whitelist(ip_addr: &IpAddr, ip: &str, config: &SecurityConfig) -> bool {
    let Some(whitelist) = &config.whitelist else {
        return true;
    };
    for allowed in whitelist {
        if allowed.contains('/') {
            if let Ok(net) = allowed.parse::<IpNet>()
                && net.contains(ip_addr)
            {
                return true;
            }
        } else if ip == allowed {
            return true;
        }
    }
    false
}

/// Emits `msg` at the [`tracing`] level equivalent to [`crate::models::LogLevel`].
pub fn log_at_level(level: LogLevel, msg: &str) {
    match level {
        LogLevel::Info => info!("{msg}"),
        LogLevel::Debug => debug!("{msg}"),
        LogLevel::Warning => warn!("{msg}"),
        LogLevel::Error | LogLevel::Critical => error!("{msg}"),
    }
}

/// Snapshot of request metadata used by the logging helpers.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Connecting client's IP address or `"unknown"`.
    pub client_ip: String,
    /// HTTP method.
    pub method: String,
    /// Full URL.
    pub url: String,
    /// All request headers.
    pub headers: std::collections::HashMap<String, String>,
}

/// Collects the fields of the request into a
/// [`crate::utils::RequestContext`].
pub fn extract_request_context(request: &DynGuardRequest) -> RequestContext {
    RequestContext {
        client_ip: request.client_host().unwrap_or_else(|| "unknown".into()),
        method: request.method(),
        url: request.url_full(),
        headers: request.headers(),
    }
}

/// Logs a request-, suspicious-, or generic-activity record at `level`.
///
/// Silently skips when `level` is [`None`]. [`crate::utils::LogType::Suspicious`]
/// entries include trigger information and honour passive-mode semantics.
pub async fn log_activity(
    request: &DynGuardRequest,
    log_type: LogType<'_>,
    level: Option<LogLevel>,
) {
    let Some(level) = level else { return };
    let context = extract_request_context(request);
    let (details, reason_message) = match log_type {
        LogType::Request => {
            let details = format!(
                "Request from {}: {} {}",
                context.client_ip, context.method, context.url
            );
            let reason = format!("Headers: {:?}", context.headers);
            (details, reason)
        }
        LogType::Suspicious { reason, passive_mode, trigger_info } => {
            if passive_mode {
                let details = format!(
                    "[PASSIVE MODE] Penetration attempt detected from {}: {} {}",
                    context.client_ip, context.method, context.url
                );
                let reason_message = if trigger_info.is_empty() {
                    format!("Headers: {:?}", context.headers)
                } else {
                    format!("Trigger: {trigger_info} - Headers: {:?}", context.headers)
                };
                (details, reason_message)
            } else {
                let details = format!(
                    "Suspicious activity detected from {}: {} {}",
                    context.client_ip, context.method, context.url
                );
                let reason_message = format!("Reason: {reason} - Headers: {:?}", context.headers);
                (details, reason_message)
            }
        }
        LogType::Generic { log_type, reason } => {
            let capitalized = capitalize_first(log_type);
            let details = format!(
                "{capitalized} from {}: {} {}",
                context.client_ip, context.method, context.url
            );
            let reason = format!("Details: {reason} - Headers: {:?}", context.headers);
            (details, reason)
        }
    };

    let msg = format!("{details} - {reason_message}");
    log_at_level(level, &msg);
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Tagged union describing the flavour of record
/// [`crate::utils::log_activity`] should emit.
#[derive(Debug)]
pub enum LogType<'a> {
    /// Plain informational request log.
    Request,
    /// Suspicious-activity log with trigger/reason metadata.
    Suspicious {
        /// Reason surface by the check.
        reason: &'a str,
        /// `true` when the pipeline is in passive mode.
        passive_mode: bool,
        /// Additional trigger detail, e.g. matched pattern.
        trigger_info: &'a str,
    },
    /// Generic decorator or handler log.
    Generic {
        /// Short label describing the log category.
        log_type: &'a str,
        /// Human-readable explanation.
        reason: &'a str,
    },
}

/// Generates a fresh UUIDv4 correlation identifier for tracing events.
pub fn new_correlation_id() -> String {
    Uuid::new_v4().to_string()
}

/// Produces a [`crate::protocols::request::StateValue::Float`] containing the
/// current epoch-millisecond timestamp.
pub fn new_state_start() -> StateValue {
    StateValue::Float(epoch_ms())
}

/// Logger name used by Guard Core's tracing spans.
pub const LOGGER_NAME: &str = "guard_core";
