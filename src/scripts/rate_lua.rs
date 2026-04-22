//! Redis Lua script used by the distributed rate-limiting backend.

/// Sliding-window rate-limit script consumed by
/// [`crate::handlers::ratelimit::RateLimitManager`].
///
/// Expects one key (`KEYS[1]`) and three arguments: `now`, `window`, `limit`.
/// Returns the current count within the window after recording `now`.
pub const RATE_LIMIT_SCRIPT: &str = r"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local window_start = now - window

redis.call('ZADD', key, now, now)

redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

local count = redis.call('ZCARD', key)

redis.call('EXPIRE', key, window * 2)

return count
";
