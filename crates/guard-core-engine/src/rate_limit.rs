//! The sliding-window rate limiter: per client IP, global scope or per
//! endpoint.
//!
//! This is the Rust family's in-memory port of the reference engine's rate
//! limiter (`guard_core/handlers/ratelimit_handler.py`, via the Go port's
//! `ratelimit.go`). One call, [`RateLimiter::check`], records one request
//! into the window for `(client IP, scope)` and decides it:
//!
//! ```text
//! evict every recorded timestamp at or before (now - window)
//! count   = requests still inside the window (before this one is recorded)
//! record  now
//! allowed = count < rate_limit
//! ```
//!
//! ## Counting semantics
//!
//! The reference keeps a sliding log of request timestamps per key. The
//! in-memory store compares the pre-recording count against the limit
//! (`allowed = count < limit`), the Redis store compares the post-recording
//! rank against it (`allowed = count <= limit`, one Lua/ZSET pipeline keyed
//! `rate_limit:rate:{ip}[:{endpoint hash}]`); the boundary is the same, this
//! port mirrors the in-memory formulation because Redis is out of scope here:
//! the store is process-local, exactly what the reference falls back to when
//! Redis is off, and the same `workers x rate_limit` caveat applies to
//! multi-process deployments. The count reported on a block includes the
//! current request (`count + 1`), matching what both references log.
//!
//! Blocked callers retry after the configured window: the reference attaches
//! `Retry-After: <window seconds>` to its `429 Too many requests`, and
//! [`RateLimitDecision::retry_after`] carries the same value.
//!
//! ## Scope
//!
//! The global scope keys the window by client IP alone (every endpoint
//! shares one budget per IP, the reference's default pipeline tier). The
//! endpoint scope keys it by `(client IP, endpoint path)` - an isolated
//! budget per endpoint, the reference's `endpoint_path`-keyed tier. Keys are
//! structured (IP + path fields), so no separator collision exists by
//! construction; the reference hashes the endpoint segment for its joined
//! Redis keys, a concern the in-memory store does not have.
//!
//! ## Honesty
//!
//! No Redis: the distributed mode (shared budgets across workers, script
//! reload handling) is a follow-up. The window store is an LRU capped at
//! 10 000 keys (`maxTrackedRateLimitKeys` in the Go port,
//! `_MAX_TRACKED_RATE_LIMIT_KEYS` in the reference), so abusive key
//! cardinality cannot grow the store without bound.
//!
//! # Example
//!
//! ```
//! use std::net::IpAddr;
//! use std::str::FromStr;
//!
//! use guard_core_engine::rate_limit::{RateLimitConfig, RateLimiter};
//!
//! let limiter = RateLimiter::new(RateLimitConfig {
//!     enable_rate_limiting: true,
//!     rate_limit: 2,
//!     ..RateLimitConfig::default()
//! })
//! .expect("valid config");
//! let ip = IpAddr::from_str("192.0.2.1").unwrap();
//!
//! assert!(limiter.check(ip, None).allowed);
//! assert!(limiter.check(ip, None).allowed);
//! // The third request inside the window crosses the limit.
//! let blocked = limiter.check(ip, None);
//! assert!(!blocked.allowed);
//! assert_eq!(blocked.retry_after(), 60);
//! ```
//!
//! A disabled limiter is inert: `check` allows without recording.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

use crate::ip_gate::canonical;

/// The reference default for `rate_limit` (maximum requests per window).
pub const DEFAULT_RATE_LIMIT: u32 = 10;
/// The reference default for `rate_limit_window` (seconds).
pub const DEFAULT_RATE_LIMIT_WINDOW: u64 = 60;
/// The window store's key cap (`_MAX_TRACKED_RATE_LIMIT_KEYS` /
/// `maxTrackedRateLimitKeys` in the references).
pub const MAX_TRACKED_RATE_LIMIT_KEYS: usize = 10_000;

/// The rate-limiting knobs (the reference `enable_rate_limiting` /
/// `rate_limit` / `rate_limit_window` / `enable_rate_limit_auto_ban` group).
///
/// The engine defaults are the opt-in pair: rate limiting off (`false`,
/// zero behavior change unless enabled - the adapters only install the stage
/// when the config asks for it) with the reference thresholds for when it is
/// turned on. Note the Python `SecurityConfig` defaults `enable_rate_limiting`
/// to `true`; the Rust family pins the conservative `false` so an adapter
/// upgrade never starts shedding traffic uninvited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// `enable_rate_limiting`. `false` makes every [`RateLimiter::check`]
    /// an unconditional allow that records nothing.
    pub enable_rate_limiting: bool,
    /// `rate_limit`: maximum requests per client IP inside
    /// `rate_limit_window` seconds.
    pub rate_limit: u32,
    /// `rate_limit_window`: the window length in seconds.
    pub rate_limit_window: u64,
    /// `enable_rate_limit_auto_ban`: feed rate-limit crossings into the
    /// auto-ban engine (the `rate_limit` category of the violation counters)
    /// when the pipeline stage runs with IP banning enabled.
    pub enable_rate_limit_auto_ban: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enable_rate_limiting: false,
            rate_limit: DEFAULT_RATE_LIMIT,
            rate_limit_window: DEFAULT_RATE_LIMIT_WINDOW,
            enable_rate_limit_auto_ban: false,
        }
    }
}

/// An invalid [`RateLimitConfig`]: the config error
/// [`RateLimiter::new`] fails closed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfigError {
    /// The rejected field (`rate_limit` or `rate_limit_window`).
    pub field: &'static str,
    /// What the field must be instead.
    pub reason: &'static str,
}

impl core::fmt::Display for RateLimitConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for RateLimitConfigError {}

/// The outcome of one rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    /// `false` when the request crossed the limit and must be answered with
    /// the family's `429 Too many requests` carrying
    /// [`RateLimitDecision::retry_after`].
    pub allowed: bool,
    /// Requests observed inside the window including this one (the count
    /// both references report when they block).
    pub count: u64,
    /// The window length the decision was made under (seconds), so callers
    /// can render `Retry-After` without re-reading the config.
    pub window: u64,
}

impl RateLimitDecision {
    /// The `Retry-After` header value for a blocked request: the window
    /// length, exactly what the reference sets.
    #[must_use]
    pub const fn retry_after(self) -> u64 {
        self.window
    }
}

/// The monotonic-ish wall clock, in seconds since the Unix epoch. Injectable
/// so expiry behavior (window sliding) is testable without sleeping.
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

#[derive(Debug, PartialEq, Eq, Hash)]
struct WindowKey {
    ip: IpAddr,
    endpoint: Option<String>,
}

/// The sliding-window rate limiter over one shared in-memory store.
///
/// Build it once at startup with [`RateLimiter::new`] (fail closed on a
/// non-positive limit or window) and share the handle across requests; the
/// internal store is a mutex-guarded LRU, safe for concurrent services.
pub struct RateLimiter {
    config: RateLimitConfig,
    windows: Mutex<LruCache<WindowKey, VecDeque<f64>>>,
    clock: Clock,
}

impl core::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn system_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

impl RateLimiter {
    /// Validate the config and build the limiter.
    ///
    /// # Errors
    ///
    /// Fails closed with a [`RateLimitConfigError`] when `rate_limit` or
    /// `rate_limit_window` is zero (the reference rejects both with
    /// `ge=1`); nothing but `RateLimitConfig::default`-shaped values is
    /// substituted silently.
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitConfigError> {
        if config.rate_limit == 0 {
            return Err(RateLimitConfigError {
                field: "rate_limit",
                reason: "must be at least 1 request per window",
            });
        }
        if config.rate_limit_window == 0 {
            return Err(RateLimitConfigError {
                field: "rate_limit_window",
                reason: "must be at least 1 second",
            });
        }
        Ok(Self {
            config,
            windows: Mutex::new(LruCache::new(
                NonZeroUsize::new(MAX_TRACKED_RATE_LIMIT_KEYS).expect("constant above zero"),
            )),
            clock: Arc::new(system_clock),
        })
    }

    /// Swap the wall clock. Test seam: production builds use the system
    /// clock; deterministic window-sliding coverage injects a fake.
    #[must_use]
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            config: RateLimitConfig::default(),
            windows: Mutex::new(LruCache::new(
                NonZeroUsize::new(MAX_TRACKED_RATE_LIMIT_KEYS).expect("constant above zero"),
            )),
            clock,
        }
    }

    /// The validated config the limiter decides under.
    #[must_use]
    pub const fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Record one request for `ip` and decide it.
    ///
    /// `endpoint` selects the scope: `None` is the global per-IP window,
    /// `Some(path)` the per-endpoint window keyed by `(ip, path)`. A
    /// disabled limiter allows without recording. The returned decision's
    /// `count` includes the request just recorded, so a block reports the
    /// crossing count exactly as the references log it.
    // The store lock must outlive the eviction loop and the push (both
    // mutate through the `timestamps` reference the guard produced); the
    // nursery lint cannot see through that reference and wants it dropped
    // early. The lock scope below already ends before the decision is built.
    #[allow(clippy::significant_drop_tightening)]
    #[must_use]
    pub fn check(&self, ip: IpAddr, endpoint: Option<&str>) -> RateLimitDecision {
        if !self.config.enable_rate_limiting {
            return RateLimitDecision {
                allowed: true,
                count: 0,
                window: self.config.rate_limit_window,
            };
        }
        // u64 -> f64 rounds to nearest; at window lengths where that loses a
        // second the boundary shift is far below any real clock resolution.
        #[allow(clippy::cast_precision_loss)]
        let window = self.config.rate_limit_window as f64;
        let now = (self.clock)();
        let window_start = now - window;
        let key = WindowKey {
            ip: canonical(ip),
            endpoint: endpoint.map(str::to_owned),
        };
        // The lock scope ends at the block: the decision is built unlocked.
        let inside = {
            let mut windows = self.windows.lock().expect("rate window store");
            let timestamps = windows
                .try_get_or_insert_mut(key, || Ok::<_, core::convert::Infallible>(VecDeque::new()))
                .expect("key capacity just reserved");
            while timestamps
                .front()
                .is_some_and(|&recorded| recorded <= window_start)
            {
                timestamps.pop_front();
            }
            let inside = timestamps.len();
            timestamps.push_back(now);
            inside
        };
        RateLimitDecision {
            allowed: inside < usize::try_from(self.config.rate_limit).unwrap_or(usize::MAX),
            count: u64::try_from(inside + 1).unwrap_or(u64::MAX),
            window: self.config.rate_limit_window,
        }
    }

    /// Drop every window, every recorded request included (`reset` in the
    /// references; test harnesses use it to isolate cases).
    pub fn reset(&self) {
        self.windows.lock().expect("rate window store").clear();
    }

    /// How many windows the store currently tracks (test/observability
    /// seam for the LRU cap).
    #[must_use]
    pub fn tracked_windows(&self) -> usize {
        self.windows.lock().expect("rate window store").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fake clock: f64 unix seconds starting at `1_000.0`, advanced by
    /// `advance`.
    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn advance(&self, seconds: u64) {
            self.0.fetch_add(seconds, Ordering::Relaxed);
        }

        fn clock(&self) -> Clock {
            let state = self.0.clone();
            #[allow(clippy::cast_precision_loss)]
            Arc::new(move || state.load(Ordering::Relaxed) as f64)
        }
    }

    fn ip(text: &str) -> IpAddr {
        IpAddr::from_str(text).expect("test address")
    }

    fn enabled_config(rate_limit: u32) -> RateLimitConfig {
        RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit,
            ..RateLimitConfig::default()
        }
    }

    #[test]
    fn default_config_is_off_with_reference_thresholds() {
        let config = RateLimitConfig::default();
        assert!(!config.enable_rate_limiting);
        assert_eq!(config.rate_limit, 10);
        assert_eq!(config.rate_limit_window, 60);
        assert!(!config.enable_rate_limit_auto_ban);
    }

    #[test]
    fn new_fails_closed_on_zero_limit_or_window() {
        let error = RateLimiter::new(RateLimitConfig {
            rate_limit: 0,
            ..RateLimitConfig::default()
        })
        .unwrap_err();
        assert_eq!(error.field, "rate_limit");
        assert_eq!(
            error.to_string(),
            "invalid rate_limit: must be at least 1 request per window"
        );

        let error = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 5,
            rate_limit_window: 0,
            enable_rate_limit_auto_ban: false,
        })
        .unwrap_err();
        assert_eq!(error.field, "rate_limit_window");
    }

    #[test]
    fn disabled_limiter_allows_and_records_nothing() {
        let limiter = RateLimiter::new(RateLimitConfig::default()).expect("default config");
        for _ in 0..50 {
            assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        }
        assert_eq!(limiter.tracked_windows(), 0, "no window was recorded");
    }

    #[test]
    fn blocks_at_the_crossing_and_reports_the_crossing_count() {
        let limiter = RateLimiter::new(enabled_config(3)).expect("valid config");
        for expected in 1..=3 {
            let decision = limiter.check(ip("192.0.2.1"), None);
            assert!(decision.allowed, "request {expected} must pass");
            assert_eq!(decision.count, expected);
        }
        let decision = limiter.check(ip("192.0.2.1"), None);
        assert!(
            !decision.allowed,
            "the 4th request inside the window blocks"
        );
        assert_eq!(decision.count, 4);
        assert_eq!(decision.retry_after(), 60, "Retry-After is the window");
    }

    #[test]
    fn window_slide_restores_the_budget() {
        let fake = FakeClock::default();
        let limiter = RateLimiter {
            config: enabled_config(2),
            windows: Mutex::new(LruCache::new(NonZeroUsize::new(16).expect("above zero"))),
            clock: fake.clock(),
        };
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(!limiter.check(ip("192.0.2.1"), None).allowed);

        // Half the window later the crossing request is still remembered.
        fake.advance(30);
        assert!(!limiter.check(ip("192.0.2.1"), None).allowed);
        // Past the window the expired timestamps are evicted and the budget
        // is whole again.
        fake.advance(31);
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
    }

    #[test]
    fn windows_are_per_ip() {
        let limiter = RateLimiter::new(enabled_config(1)).expect("valid config");
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(!limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(
            limiter.check(ip("192.0.2.2"), None).allowed,
            "another IP has its own budget"
        );
    }

    #[test]
    fn endpoint_scope_is_isolated_from_the_global_scope() {
        let limiter = RateLimiter::new(enabled_config(1)).expect("valid config");
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(
            limiter.check(ip("192.0.2.1"), Some("/login")).allowed,
            "the endpoint window is a separate budget"
        );
        assert!(!limiter.check(ip("192.0.2.1"), Some("/login")).allowed);
        assert!(
            limiter.check(ip("192.0.2.1"), Some("/signup")).allowed,
            "another endpoint has its own budget"
        );
        assert_eq!(limiter.tracked_windows(), 3);
    }

    #[test]
    fn ipv4_mapped_requests_share_the_ipv4_budget() {
        let limiter = RateLimiter::new(enabled_config(1)).expect("valid config");
        assert!(limiter.check(ip("::ffff:192.0.2.1"), None).allowed);
        assert!(
            !limiter.check(ip("192.0.2.1"), None).allowed,
            "the mapped form must count toward the same window"
        );
    }

    #[test]
    fn reset_drops_every_window() {
        let limiter = RateLimiter::new(enabled_config(1)).expect("valid config");
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        assert!(!limiter.check(ip("192.0.2.1"), None).allowed);
        limiter.reset();
        assert_eq!(limiter.tracked_windows(), 0);
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
    }

    #[test]
    fn large_windows_keep_their_exact_length() {
        // rate_limit_window beyond u32 must not fold the sliding window into
        // something shorter (the f64 conversion saturates, never truncates).
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: u64::from(u32::MAX) + 1,
            enable_rate_limit_auto_ban: false,
        })
        .expect("valid config");
        assert!(limiter.check(ip("192.0.2.1"), None).allowed);
        let decision = limiter.check(ip("192.0.2.1"), None);
        assert!(!decision.allowed);
        assert_eq!(decision.retry_after(), u64::from(u32::MAX) + 1);
    }
}
