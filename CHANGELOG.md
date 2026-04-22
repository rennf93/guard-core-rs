Changelog
=========

All notable changes to this project will be documented in this file. This project
follows [Semantic Versioning](https://semver.org/) and the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

___

Unreleased
----------

### Added

- Complete Rust port of `guard-core` (Python) — framework-agnostic application-layer API security engine
- Protocol traits (`GuardRequest`, `GuardResponse`, `GuardResponseFactory`, `GuardMiddlewareProtocol`, `RedisHandlerProtocol`, `GeoIpHandler`, `AgentHandlerProtocol`) under `guard_core_rs::protocols`
- `SecurityConfig` with builder API, 60+ configuration fields mirroring the Python reference, and 15 validators
- `DynamicRules` serde model for SaaS-driven rule updates
- Detection engine: `PatternCompiler` (LRU-cached regex compilation with ReDoS-safety validator), `PerformanceMonitor` (Gaussian anomaly detection with rolling-window statistics), `ContentPreprocessor` (Unicode NFKC normalization, homoglyph mapping, percent/HTML entity decoding, attack-region-preserving truncation), `SemanticAnalyzer` (keyword frequency + structural pattern scoring across XSS/SQL/command/path/template categories)
- Handlers: `RedisManager` (async multiplexed connection, Lua script loading, RESP3-aware value conversion), `RateLimitManager` (Lua sliding window + in-memory fallback), `IPBanManager` (moka TTL cache + Redis persistence), `CloudManager` (AWS/GCP/Azure IP range fetching with URL overrides via `fetch_*_from`), `IPInfoManager` (MaxMind database with configurable download URL via `new_with_url`), `BehaviorTracker` (endpoint usage + return pattern tracking), `DynamicRuleManager` (async rule-update task loop), `SecurityHeadersManager` (HSTS/CSP/CORS), `SusPatternsManager` (~70 built-in patterns with context classifiers, multi-layer detection pipeline)
- `SecurityCheckPipeline` with 17 check implementations: authentication, cloud IP refresh, cloud provider, custom request, custom validators, emergency mode, HTTPS enforcement, IP security, rate limit, referrer, request logging, request size/content, required headers, route config, suspicious activity, time window, user agent
- Core subsystems: `ResponseContext`/`ErrorResponseFactory`, `RoutingContext`/`RouteConfigResolver`, `ValidationContext`/`RequestValidator`, `BypassContext`/`BypassHandler`, `BehavioralContext`/`BehavioralProcessor`, `SecurityEventBus`, `MetricsCollector`, `HandlerInitializer`
- Decorator builder API: `RouteConfig::new().rate_limit(...).require_auth(...).block_countries(...)` with 25+ chainable methods; `SecurityDecorator` route registry
- Feature flags: `redis-support`, `geoip`, `agent`, `cloud-providers` (all on by default)
- Makefile with 25+ targets mirroring the Python reference, `.github/workflows/ci.yml` matrix (fmt / clippy / check / test / coverage / audit / deny / docs across Linux/macOS/Windows and stable/beta/MSRV), `deny.toml`, `rustfmt.toml`, `dependabot.yml`
- Integration test suite: 1300+ tests across 60+ files, mock implementations of every protocol under `tests/support/`, wiremock-backed HTTP mocks, moka-backed in-memory redis mock
- Edition 2024, MSRV 1.85

### Fixed

- `decode_html_entities` byte-boundary panic when input contained multi-byte UTF-8 characters (e.g. emoji or CJK glyphs) — now advances by `char::len_utf8()` and checks `str::is_char_boundary` before slicing

### Notes

- The Rust port is async-primary via tokio; no separate synchronous module is generated (unlike Python's `guard_core.sync`). Callers who need blocking semantics can use `tokio::runtime::Runtime::block_on`.
- The prompt-injection subsystem present on `feature/prompt-injection-detection` of the Python repo is not yet ported to this crate; follow-up work will land it on a matching feature branch.
