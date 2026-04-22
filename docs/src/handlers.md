# Handlers

Handlers under [`guard_core_rs::handlers`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/index.html) manage the mutable, usually network-backed, state that checks need. Each handler is `Arc`-friendly, async, and optionally Redis-backed.

## IPBanManager

[`IPBanManager`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/ipban/struct.IPBanManager.html) tracks active IP bans in a `moka` cache (up to 10 000 entries, 1 hour TTL) and mirrors them to Redis under the `banned_ips:` namespace.

```rust,ignore
use std::sync::Arc;
use guard_core_rs::handlers::ipban::IPBanManager;

let ipban = Arc::new(IPBanManager::new());
ipban.ban_ip("203.0.113.5", 3600, "sqli_attempt").await?;
assert!(ipban.is_ip_banned("203.0.113.5").await?);
```

## RateLimitManager

[`RateLimitManager`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/ratelimit/struct.RateLimitManager.html) supports two strategies:

- **In-memory sliding window**. Request timestamps live in a `dashmap::DashMap<String, VecDeque<f64>>` keyed by `client_ip` or `client_ip:endpoint`.
- **Redis Lua script**. `scripts/rate_lua.rs` uses `ZADD`/`ZRANGEBYSCORE` to implement a sliding window across instances. The manager auto-loads the script on first Redis initialisation.

`check_rate_limit(CheckRateLimitArgs)` returns `Ok(Some(response))` with status 429 on overflow or `Ok(None)` otherwise.

## CloudManager

With the `cloud-providers` feature, [`CloudManager`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/cloud/struct.CloudManager.html) downloads, parses, and caches the published IP ranges for AWS (`ip-ranges.json`), GCP (`cloud.json`), and Azure (XML feed). Refresh cadence is driven by `cloud_ip_refresh_interval`. The `CloudIpRefreshCheck` reads the last refresh timestamp from the middleware and triggers a refresh when stale.

## IPInfoManager

With the `geoip` feature, [`IPInfoManager`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/ipinfo/struct.IPInfoManager.html) provides country / ASN lookups using either a local MaxMind database (`ipinfo_db_path`) or the hosted IPInfo API (`ipinfo_token`). The manager is exposed to checks via `SecurityConfig::geo_ip_handler`.

## BehaviorTracker

[`BehaviorTracker`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/behavior/struct.BehaviorTracker.html) powers the `usage_monitor`, `return_monitor`, and `suspicious_frequency` decorators on `RouteConfig`. It records per-client-IP usage counts and return-pattern occurrences, enforces `BehaviorRule` thresholds, and optionally bans through `IPBanManager`.

## SecurityHeadersManager

[`SecurityHeadersManager`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/security_headers/struct.SecurityHeadersManager.html) renders `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`, and `Permissions-Policy` from a [`SecurityHeadersConfig`](https://docs.rs/guard-core-rs/latest/guard_core_rs/models/struct.SecurityHeadersConfig.html). It is not wired into a built-in check: the adapter typically applies the rendered headers at response time.

## RedisManager

With `redis-support`, [`RedisManager`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/redis/struct.RedisManager.html) implements `RedisHandlerProtocol` on top of `deadpool-redis`. It handles connection pooling, script loading, and tokio-rustls TLS when the URL scheme is `rediss://`.

## DynamicRuleManager

[`DynamicRuleManager`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/dynamic_rule/struct.DynamicRuleManager.html) polls the guard-agent endpoint for [`DynamicRules`](https://docs.rs/guard-core-rs/latest/guard_core_rs/models/struct.DynamicRules.html) at `dynamic_rule_interval` and merges them into the live config. Changes propagate without a restart.

## SusPatternsManager

Covered in [Detection Engine](./detection_engine.md). Import `suspatterns::SusPatternsManager` for the public API.

## Wiring

All handlers plug into checks through constructor arguments. Typical initialisation:

```rust,ignore
let redis = Arc::new(MyRedis::new());
rate_limit.initialize_redis(Arc::clone(&redis) as DynRedisHandler).await;
ipban.initialize_redis(Arc::clone(&redis) as DynRedisHandler).await;
patterns.initialize_redis(Arc::clone(&redis) as DynRedisHandler).await?;
```

Agent wiring is analogous via `initialize_agent(DynAgentHandler)`.

See `examples/quickstart.rs` for a complete scaffold.
