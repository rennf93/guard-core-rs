# guard-core-rs

Framework-agnostic application-layer API security engine — Rust port of
[guard-core](https://github.com/rennf93/guard-core) (Python).

## Status

Active port in progress. The core engine compiles cleanly, all features
build, and the base test suite passes. See `./tests` for coverage.

## What's ported

| Subsystem | Status |
|---|---|
| Models (`SecurityConfig`, `DynamicRules`) | complete |
| Protocols (request/response/middleware/redis/geo-ip/agent traits) | complete |
| Detection engine (pattern compiler, performance monitor, preprocessor, semantic analyzer) | complete |
| Handlers (redis, ratelimit, ipban, cloud, ipinfo, behavior, dynamic-rule, security-headers, suspatterns) | complete |
| Core subsystems (responses, routing, validation, bypass, behavioral, events, initialization) | complete |
| Security check pipeline + 17 check implementations | complete |
| Decorators (builder API on `RouteConfig`) | complete |
| Prompt-injection subsystem (feature-gated) | in progress |
| Test suite | in progress (70+ tests passing) |
| Makefile + CI + deny.toml | complete |

## Features

- `redis-support` (default) — async Redis via `redis` + `deadpool-redis`
- `geoip` (default) — MaxMind database reader
- `cloud-providers` (default) — AWS / GCP / Azure IP range fetching
- `agent` (default) — SaaS telemetry plumbing
- `prompt-injection` — pattern/statistical prompt-injection detection
- `prompt-injection-ml` — transformer/embedding detectors (feature-gated)

## Quickstart

```toml
[dependencies]
guard-core-rs = { version = "0.0.1", features = ["redis-support", "geoip"] }
```

```rust,no_run
use guard_core_rs::SecurityConfig;

let config = SecurityConfig::builder()
    .rate_limit(100)
    .rate_limit_window(60)
    .enforce_https(true)
    .blacklist(vec!["10.0.0.0/8".into()])
    .build()
    .expect("config");
```

## Development

```bash
# build
make build             # cargo build --all-features
# tests
make test              # cargo test --all-features
# lint
make lint              # fmt + clippy + check
# coverage
make coverage          # cargo llvm-cov
# security audits
make security          # cargo audit + cargo deny
```

## Links

- Python reference: <https://github.com/rennf93/guard-core>
- FastAPI integration: <https://github.com/rennf93/fastapi-guard>
- TypeScript port: <https://github.com/rennf93/guard-core-ts>
- Cloud platform: <https://app.fastapi-guard.com>

## License

MIT
