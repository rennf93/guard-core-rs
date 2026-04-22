# Testing

`guard-core-rs` ships with an extensive integration test suite under `tests/` and a shared fixture crate under `tests/support/`. The design follows three rules:

1. **Every public API has an integration test.** Unit tests only exist when behaviour is awkward to exercise through a public path.
2. **Fixtures are inline, not macros.** `tests/support/mock_*.rs` and `tests/support/{request,response,middleware}.rs` are regular modules included via `#[path = "..."]`.
3. **Behaviour, not implementation.** Test names describe observable outcomes (`pipeline_returns_none_when_no_check_blocks`, `ip_security_banned_ip_blocks_with_403`).

## Running tests

```bash
cargo test --all-features
```

Specific test files use the path form:

```bash
cargo test --all-features --test test_checks_pipeline
cargo test --all-features --test test_detection_engine
```

For faster iteration, use [`cargo-nextest`](https://nexte.st/) which is pre-configured in the Makefile:

```bash
make nextest
```

## Coverage

Coverage runs through [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov):

```bash
make coverage
make coverage-html
```

The target is 100% branch and line coverage on every file touched by a change. The CI workflow rejects regressions.

## Support fixtures

| File | Provides |
|------|----------|
| `tests/support/request.rs` | `MockRequest`, `MockRequestBuilder` — configurable path, method, headers, query, body, client IP. |
| `tests/support/response.rs` | `MockResponse`, `MockResponseFactory` — satisfies `GuardResponse`/`GuardResponseFactory` with inspectable captures. |
| `tests/support/middleware.rs` | `MockMiddleware`, `InlineMockResponseFactory` — populated with config, optional agent/geo/redis handlers, and refresh-failure mode. |
| `tests/support/mock_agent.rs` | `MockAgent` — records every event/metric for assertions. |
| `tests/support/mock_redis.rs` | `MockRedis` — in-memory store with injectable failure modes. |
| `tests/support/geo_ip.rs` | `MockGeoIpHandler` — map-based country/ASN lookups. |

Example:

```rust,ignore
#[path = "support/request.rs"]
mod mock_request;
#[path = "support/middleware.rs"]
mod mock_middleware;

use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::core::checks::implementations::IpSecurityCheck;
use guard_core_rs::core::routing::{RouteConfigResolver, RoutingContext};
use guard_core_rs::handlers::ipban::IPBanManager;
use guard_core_rs::models::SecurityConfig;

#[tokio::test]
async fn banned_ip_is_blocked() {
    let config = std::sync::Arc::new(SecurityConfig::builder().build().expect("valid"));
    let middleware = mock_middleware::MockMiddleware::new(std::sync::Arc::clone(&config));
    let resolver = std::sync::Arc::new(
        RouteConfigResolver::new(RoutingContext::new(std::sync::Arc::clone(&config))),
    );
    let ipban = std::sync::Arc::new(IPBanManager::new());
    ipban.ban_ip("10.0.0.9", 60, "test").await.unwrap();
    let check = IpSecurityCheck::new(middleware, resolver, ipban);
    let request = mock_request::MockRequest::builder().path("/").build().arc();
    request.state().set_str(guard_core_rs::utils::CLIENT_IP_KEY, "10.0.0.9");
    let response = check.check(&request).await.unwrap().unwrap();
    assert_eq!(response.status_code(), 403);
}
```

## Benchmarks

Benchmarks live in `benches/` and use [`criterion`](https://docs.rs/criterion/latest/criterion/). Run:

```bash
cargo bench --all-features                       # all suites
cargo bench --all-features --bench detection_engine
cargo bench --all-features --bench checks
cargo bench --all-features --bench suspatterns
cargo bench --all-features --bench rate_limit
```

Use `cargo bench --no-run` to verify they compile without executing.

## Linting and security

`make quality` runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo machete`. `make security` runs `cargo audit` and `cargo deny`. Both must be clean before merging.

## Pre-commit workflow

```bash
make fmt
make lint
make test
make coverage
```

Every touched file must end up with 100% line and branch coverage. No `#[allow]` or feature-gated `#[cfg(not(test))]` workarounds; fix the underlying behaviour so the covered path is representative.
