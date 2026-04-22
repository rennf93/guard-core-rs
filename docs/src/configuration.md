# Configuration

All behaviour is driven by [`SecurityConfig`](https://docs.rs/guard-core-rs/latest/guard_core_rs/models/struct.SecurityConfig.html). It is constructed through [`SecurityConfigBuilder`](https://docs.rs/guard-core-rs/latest/guard_core_rs/models/struct.SecurityConfigBuilder.html) and validated via `build()`.

## Sections

`SecurityConfig` groups its fields into several logical sections:

| Area | Fields (selected) | Notes |
|------|-------------------|-------|
| Proxy trust | `trusted_proxies`, `trusted_proxy_depth`, `trust_x_forwarded_proto` | Honour `X-Forwarded-For` only when the immediate peer is trusted. |
| IP access | `whitelist`, `blacklist`, `auto_ban_threshold`, `auto_ban_duration` | Global allow/deny lists and auto-ban policy. |
| Geo | `whitelist_countries`, `blocked_countries`, `ipinfo_token`, `ipinfo_db_path` | Requires `geoip` feature or a custom `GeoIpHandler`. |
| Rate limits | `enable_rate_limiting`, `rate_limit`, `rate_limit_window`, `endpoint_rate_limits` | Token-bucket-like counter with Redis or in-memory backing. |
| HTTPS | `enforce_https` | Redirects HTTP requests to HTTPS; respects `trust_x_forwarded_proto`. |
| Detection engine | `detection_compiler_timeout`, `detection_max_content_length`, `detection_semantic_threshold`, `detection_anomaly_threshold`, `detection_slow_pattern_threshold`, `detection_monitor_history_size`, `detection_max_tracked_patterns`, `detection_preserve_attack_patterns` | All are clamped to sensible ranges. |
| Cloud providers | `block_cloud_providers`, `cloud_ip_refresh_interval` | AWS / GCP / Azure IP range lookups. |
| Agent | `enable_agent`, `agent_api_key`, `agent_endpoint`, `agent_buffer_size`, `agent_flush_interval`, `agent_enable_events`, `agent_enable_metrics`, `agent_timeout`, `agent_retry_attempts` | Optional guard-agent telemetry. |
| Dynamic rules | `enable_dynamic_rules`, `dynamic_rule_interval`, `emergency_mode`, `emergency_whitelist` | Server-driven rule updates. |
| Misc | `passive_mode`, `custom_error_responses`, `exclude_paths`, `log_request_level`, `log_suspicious_level`, `log_format`, `custom_log_file` | |

## Builder

```rust,ignore
use guard_core_rs::models::SecurityConfig;

let config = SecurityConfig::builder()
    .trusted_proxies(vec!["10.0.0.0/8".into()])
    .trust_x_forwarded_proto(true)
    .whitelist(Some(vec!["192.168.1.10".into()]))
    .blacklist(vec!["203.0.113.5".into()])
    .enable_ip_banning(true)
    .auto_ban_threshold(5)
    .auto_ban_duration(3600)
    .rate_limit(60)
    .rate_limit_window(60)
    .enable_rate_limiting(true)
    .enforce_https(true)
    .enable_penetration_detection(true)
    .build()
    .expect("valid");
```

Any builder method returns `Self`, so chaining is idiomatic. `build()` returns `Result<SecurityConfig>`; always propagate errors rather than unwrapping in production code.

## Validation

`SecurityConfig::validate` runs during `build()`. It enforces:

- IP/CIDR syntax for `whitelist`, `blacklist`, and `trusted_proxies`.
- `trusted_proxy_depth >= 1`.
- GeoIP handler present if countries are configured.
- Agent API key present if the agent is enabled.
- Dynamic rules require the agent.
- Detection engine thresholds are inside documented ranges.
- `cloud_ip_refresh_interval` between 60 and 86400.

Use `validate()` directly if you built a `SecurityConfig` outside the builder (e.g. deserialised from config).

## Passive mode

Setting `passive_mode(true)` short-circuits every blocking response. Checks still run, events still ship to the agent, logs still go out, but `pipeline.execute(&request)` returns `Ok(None)` for everything that would otherwise deny. This mode is the safest way to roll out a policy change: enable passive, watch logs, then disable once false-positive rate is acceptable.

## Logging

`log_request_level`, `log_suspicious_level`, and `custom_log_file` are forwarded to `tracing`. `log_format` chooses between text and JSON formatters. See [Handlers](./handlers.md) and the [`utils`](https://docs.rs/guard-core-rs/latest/guard_core_rs/utils/index.html) module for log helpers.

## Per-route overrides

`SecurityConfig` is global. Per-route tuning uses [`RouteConfig`](https://docs.rs/guard-core-rs/latest/guard_core_rs/decorators/struct.RouteConfig.html) registered via [`SecurityDecorator`](https://docs.rs/guard-core-rs/latest/guard_core_rs/decorators/struct.SecurityDecorator.html). Those values win over `SecurityConfig` where they overlap. See [Decorators and Route Config](./decorators.md).
