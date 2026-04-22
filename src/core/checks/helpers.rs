//! Shared helper functions used by the concrete
//! [`crate::core::checks::base::SecurityCheck`] implementations.

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use regex::RegexBuilder;
use url::Url;

use crate::decorators::RouteConfig;
use crate::models::SecurityConfig;
use crate::protocols::geo_ip::DynGeoIpHandler;
use crate::protocols::request::DynGuardRequest;
use crate::utils::is_user_agent_allowed as global_user_agent_check;

/// Returns `true` when `header_value` looks like a supported authentication
/// scheme (Basic/Bearer/Digest/APIKey/Token) after trimming.
pub fn validate_auth_header(header_value: &str) -> bool {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("basic ")
        || lower.starts_with("bearer ")
        || lower.starts_with("digest ")
        || lower.starts_with("apikey ")
        || lower.starts_with("token ")
}

/// Validates `auth_header` against the required `auth_type`, returning
/// `(is_valid, reason)`.
pub fn validate_auth_header_for_scheme(auth_header: &str, auth_type: &str) -> (bool, &'static str) {
    match auth_type {
        "bearer" => {
            if auth_header.starts_with("Bearer ") {
                (true, "")
            } else {
                (false, "Missing or invalid Bearer token")
            }
        }
        "basic" => {
            if auth_header.starts_with("Basic ") {
                (true, "")
            } else {
                (false, "Missing or invalid Basic authentication")
            }
        }
        _ => {
            if auth_header.is_empty() {
                (false, "Missing authentication")
            } else {
                (true, "")
            }
        }
    }
}

/// Returns `true` when `path` equals any entry of `excluded` or is a
/// sub-path of one.
pub fn request_path_excluded(path: &str, excluded: &[String]) -> bool {
    for entry in excluded {
        if path == entry || path.starts_with(&format!("{entry}/")) {
            return true;
        }
    }
    false
}

/// Returns the request's `Content-Type` header value, if present.
pub fn get_request_content_type(request: &DynGuardRequest) -> Option<String> {
    request.header("Content-Type")
}

/// Returns the request's `Content-Length` header parsed as [`u64`].
pub fn get_request_content_length(request: &DynGuardRequest) -> Option<u64> {
    request.header("Content-Length").and_then(|v| v.parse().ok())
}

/// Returns `true` when `client_ip`/`ip_addr` is contained by any entry of
/// `blacklist`.
pub fn is_ip_in_blacklist(client_ip: &str, ip_addr: &IpAddr, blacklist: &[String]) -> bool {
    for blocked in blacklist {
        if blocked.contains('/') {
            if let Ok(net) = blocked.parse::<IpNet>()
                && net.contains(ip_addr)
            {
                return true;
            }
        } else if client_ip == blocked {
            return true;
        }
    }
    false
}

/// Returns `Some(true/false)` when a whitelist is configured, or [`None`]
/// when the whitelist is empty and the check should be skipped.
pub fn is_ip_in_whitelist(
    client_ip: &str,
    ip_addr: &IpAddr,
    whitelist: &[String],
) -> Option<bool> {
    if whitelist.is_empty() {
        return None;
    }
    for allowed in whitelist {
        if allowed.contains('/') {
            if let Ok(net) = allowed.parse::<IpNet>()
                && net.contains(ip_addr)
            {
                return Some(true);
            }
        } else if client_ip == allowed {
            return Some(true);
        }
    }
    Some(false)
}

/// Evaluates `client_ip`'s country against the route-level allow/block lists.
///
/// Returns [`None`] when no GeoIP handler is configured or no country rules
/// are attached, otherwise `Some(is_allowed)`.
pub fn check_country_access(
    client_ip: &str,
    route_config: &RouteConfig,
    geo_ip_handler: Option<&DynGeoIpHandler>,
) -> Option<bool> {
    let handler = geo_ip_handler?;
    let mut country: Option<String> = None;
    if !route_config.blocked_countries.is_empty() {
        country = handler.get_country(client_ip);
        if let Some(c) = country.as_deref()
            && route_config.blocked_countries.contains(&c.to_string())
        {
            return Some(false);
        }
    }
    if !route_config.allowed_countries.is_empty() {
        if country.is_none() {
            country = handler.get_country(client_ip);
        }
        if let Some(c) = country {
            return Some(route_config.allowed_countries.contains(&c));
        }
        return Some(false);
    }
    None
}

/// Combines IP blacklist, whitelist, and country checks for a route config.
pub fn check_route_ip_access(
    client_ip: &str,
    route_config: &RouteConfig,
    geo_ip_handler: Option<&DynGeoIpHandler>,
) -> Option<bool> {
    let Ok(ip_addr) = client_ip.parse::<IpAddr>() else {
        return Some(false);
    };

    if !route_config.blocked_ips.is_empty()
        && is_ip_in_blacklist(client_ip, &ip_addr, &route_config.blocked_ips)
    {
        return Some(false);
    }

    if let Some(whitelist) = &route_config.allowed_ips
        && let Some(result) = is_ip_in_whitelist(client_ip, &ip_addr, whitelist)
    {
        return Some(result);
    }

    check_country_access(client_ip, route_config, geo_ip_handler)
}

/// Returns `true` when `user_agent` is not rejected by the route- or
/// global-level blocklist.
pub fn check_user_agent_allowed(
    user_agent: &str,
    route_config: Option<&RouteConfig>,
    config: &SecurityConfig,
) -> bool {
    if let Some(rc) = route_config
        && !rc.blocked_user_agents.is_empty()
    {
        for pattern in &rc.blocked_user_agents {
            if let Ok(re) = RegexBuilder::new(pattern).case_insensitive(true).build()
                && re.is_match(user_agent)
            {
                return false;
            }
        }
    }
    global_user_agent_check(user_agent, config)
}

/// Returns `true` when the host of `referrer` matches any of
/// `allowed_domains` exactly or as a sub-domain.
pub fn is_referrer_domain_allowed(referrer: &str, allowed_domains: &[String]) -> bool {
    let Ok(url) = Url::parse(referrer) else { return false };
    let Some(host) = url.host_str() else { return false };
    let host_lower = host.to_ascii_lowercase();
    for allowed in allowed_domains {
        let allowed_lower = allowed.to_ascii_lowercase();
        if host_lower == allowed_lower || host_lower.ends_with(&format!(".{allowed_lower}")) {
            return true;
        }
    }
    false
}

/// Returns `(effective_enabled, route_level_override)` for the
/// penetration-detection feature, resolving route-level metadata first.
pub fn get_effective_penetration_setting(
    config: &SecurityConfig,
    route_config: Option<&RouteConfig>,
) -> (bool, Option<bool>) {
    let route_specific = route_config.and_then(|rc| {
        rc.custom_metadata
            .get("enable_suspicious_detection")
            .and_then(|v| v.as_bool())
    });
    let penetration_enabled = route_specific.unwrap_or(config.enable_penetration_detection);
    (penetration_enabled, route_specific)
}

/// Returns the human-readable reason string for why detection was skipped.
pub fn get_detection_disabled_reason(
    config: &SecurityConfig,
    route_specific: Option<bool>,
) -> &'static str {
    if route_specific == Some(false) && config.enable_penetration_detection {
        "disabled_by_decorator"
    } else {
        "not_enabled"
    }
}

/// Async penetration-detection callback used by checks that need a custom
/// detection path.
pub type DetectPenetrationFn = Arc<
    dyn Fn(
            Arc<dyn crate::protocols::request::GuardRequest>,
        )
            -> futures::future::BoxFuture<'static, (bool, String)>
        + Send
        + Sync,
>;
