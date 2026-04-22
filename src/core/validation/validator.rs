//! Validation helpers invoked by the pipeline and individual checks.

use chrono::{NaiveTime, Timelike, Utc};

use crate::core::checks::helpers::request_path_excluded;
use crate::core::validation::context::ValidationContext;
use crate::protocols::request::DynGuardRequest;
use crate::utils::is_trusted_proxy;

/// Validates request-level properties (HTTPS, trusted proxy, time window,
/// path exclusion).
#[derive(Clone, Debug)]
pub struct RequestValidator {
    context: ValidationContext,
}

impl RequestValidator {
    /// Creates a validator bound to `context`.
    pub const fn new(context: ValidationContext) -> Self {
        Self { context }
    }

    /// Returns `true` when `request` is HTTPS (directly or via trusted
    /// `X-Forwarded-Proto`).
    pub fn is_request_https(&self, request: &DynGuardRequest) -> bool {
        if request.url_scheme() == "https" {
            return true;
        }
        if self.context.config.trust_x_forwarded_proto
            && let Some(proto) = request.header("X-Forwarded-Proto")
            && proto.eq_ignore_ascii_case("https")
        {
            return true;
        }
        false
    }

    /// Returns `true` when `ip` is listed in
    /// [`crate::models::SecurityConfig::trusted_proxies`].
    pub fn is_trusted_proxy(&self, ip: &str) -> bool {
        is_trusted_proxy(ip, &self.context.config.trusted_proxies)
    }

    /// Returns `true` when the current UTC time falls within the
    /// `[start, end]` window (inclusive of wrap-around).
    pub fn check_time_window(&self, start: NaiveTime, end: NaiveTime) -> bool {
        let now = Utc::now().time();
        let now_s = now.num_seconds_from_midnight();
        let s = start.num_seconds_from_midnight();
        let e = end.num_seconds_from_midnight();
        if s <= e {
            now_s >= s && now_s <= e
        } else {
            now_s >= s || now_s <= e
        }
    }

    /// Returns `true` when the request's path matches any entry of
    /// [`crate::models::SecurityConfig::exclude_paths`].
    pub fn is_path_excluded(&self, request: &DynGuardRequest) -> bool {
        request_path_excluded(&request.url_path(), &self.context.config.exclude_paths)
    }
}
