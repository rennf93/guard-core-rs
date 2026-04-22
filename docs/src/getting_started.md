# Getting Started

This chapter walks through depending on `guard-core-rs`, building a `SecurityCheckPipeline`, and wiring it into a request path.

## Add the dependency

```toml
[dependencies]
guard-core-rs = "0.0.1"
```

All built-in checks, the detection engine, Redis, cloud providers, and GeoIP support are enabled by the default feature set:

```toml
guard-core-rs = { version = "0.0.1", default-features = false, features = [
    "redis-support",
    "geoip",
    "agent",
    "cloud-providers",
] }
```

Trim features if your adapter does not need them. For example, dropping `redis-support` removes the `redis` and `deadpool-redis` transitive dependencies.

## Minimum supported Rust version

The MSRV is `1.85` (Rust 2024 edition). `cargo check --edition 2024` must succeed.

## Build a config

`SecurityConfig::builder()` exposes every tunable. See [Configuration](./configuration.md) for every field.

```rust,ignore
use std::sync::Arc;
use guard_core_rs::models::SecurityConfig;

let config = Arc::new(
    SecurityConfig::builder()
        .enable_ip_banning(true)
        .enable_rate_limiting(true)
        .rate_limit(100)
        .rate_limit_window(60)
        .enable_penetration_detection(true)
        .build()
        .expect("valid config"),
);
```

## Construct the pipeline

The pipeline is a chain of `Arc<dyn SecurityCheck>` values. Each check takes the middleware, a `RouteConfigResolver`, and any handler it needs (IP ban manager, rate limit manager, suspicious patterns).

```rust,ignore
use guard_core_rs::core::checks::{
    IpSecurityCheck, RateLimitCheck, SecurityCheckPipeline, SuspiciousActivityCheck, UserAgentCheck,
};
use guard_core_rs::core::routing::{RouteConfigResolver, RoutingContext};
use guard_core_rs::handlers::ipban::IPBanManager;
use guard_core_rs::handlers::ratelimit::RateLimitManager;
use guard_core_rs::handlers::suspatterns::SusPatternsManager;

let resolver = Arc::new(RouteConfigResolver::new(RoutingContext::new(Arc::clone(&config))));
let ipban = Arc::new(IPBanManager::new());
let rate = RateLimitManager::new(Arc::clone(&config));
let patterns = SusPatternsManager::arc(Some(&config));

let mut pipeline = SecurityCheckPipeline::new();
pipeline.add_check(Arc::new(IpSecurityCheck::new(
    Arc::clone(&middleware), Arc::clone(&resolver), Arc::clone(&ipban),
)));
pipeline.add_check(Arc::new(RateLimitCheck::new(
    Arc::clone(&middleware), Arc::clone(&resolver), Arc::clone(&rate),
)));
pipeline.add_check(Arc::new(UserAgentCheck::new(
    Arc::clone(&middleware), Arc::clone(&resolver),
)));
pipeline.add_check(Arc::new(SuspiciousActivityCheck::new(
    Arc::clone(&middleware), Arc::clone(&resolver), Arc::clone(&ipban), Arc::clone(&patterns),
)));
```

`middleware` here is your implementation of `GuardMiddlewareProtocol`; see [Handlers](./handlers.md) for what it needs to expose.

## Execute the pipeline

```rust,ignore
match pipeline.execute(&request).await? {
    Some(blocking) => return Ok(blocking),
    None => { /* forward to the inner service */ }
}
```

A blocking response is a regular `DynGuardResponse`. Your adapter is responsible for turning it back into the framework's native response type (`axum::Response`, `actix_web::HttpResponse`, and so on).

## Run the examples

The repository ships four runnable examples:

```bash
cargo run --example quickstart
cargo run --example with_decorator
cargo run --example custom_check
cargo run --example pattern_detection
```

Each one prints a short trace showing which checks fired. Use them as starting templates for your adapter.

## Next steps

- Read [Configuration](./configuration.md) to understand `SecurityConfig`.
- Read [Security Checks](./checks.md) for the canonical execution order and per-check semantics.
- Read [Architecture](./architecture.md) for the trait and context layout.
