# Decorators and Route Config

`guard-core-rs` does not come with procedural macros. Instead, per-route configuration is captured in [`RouteConfig`](https://docs.rs/guard-core-rs/latest/guard_core_rs/decorators/struct.RouteConfig.html) and looked up through [`SecurityDecorator`](https://docs.rs/guard-core-rs/latest/guard_core_rs/decorators/struct.SecurityDecorator.html). Adapter crates are encouraged to wrap the registration in their framework's idiomatic style (attribute macros, extractor traits, router layers, ...).

## RouteConfig

`RouteConfig` is the superset of every per-route knob. A selection of its builder methods:

| Builder | Effect |
|---------|--------|
| `require_ip(whitelist, blacklist)` | Restrict or deny IPs for this route. |
| `block_countries(vec)` / `allow_countries(vec)` | Geo lists applied before global config. |
| `block_clouds(Option<Vec>)` | Deny AWS/GCP/Azure; None means all three. |
| `rate_limit(requests, window)` | Per-route sliding window. |
| `geo_rate_limit(map)` | Per-country overrides, `*` fallback. |
| `require_https()` | Force HTTPS regardless of global config. |
| `require_auth(scheme)` | `Bearer`, `Basic`, etc. |
| `api_key_auth(header_name)` | Require a non-empty header. |
| `require_headers(map)` | Arbitrary header requirements. |
| `usage_monitor(max, window, action)` | BehaviorTracker usage rule. |
| `return_monitor(pattern, max, window, action)` | Response-body pattern rule. |
| `suspicious_frequency(freq, window, action)` | Derived rate rule. |
| `block_user_agents(vec)` | Route-specific UA deny list. |
| `content_type_filter(vec)` | Allowed request `Content-Type`s. |
| `max_request_size(bytes)` | Upper bound on body size. |
| `require_referrer(vec)` | Allowed referrer origins. |
| `time_window(start, end, tz)` | Only serve inside a window. |
| `custom_validation(closure)` | Async validator callback. |
| `suspicious_detection(bool)` | Toggle the detection engine per-route. |
| `bypass(vec)` | Skip named checks (`ip`, `ip_ban`, `rate_limit`, `penetration`, ...). |

`RouteConfig::new()` starts with `enable_suspicious_detection = true` and empty everything else.

## SecurityDecorator

```rust,ignore
use std::sync::Arc;
use guard_core_rs::decorators::{RouteConfig, SecurityDecorator};
use guard_core_rs::models::SecurityConfig;

let config = Arc::new(SecurityConfig::builder().build()?);
let decorator = SecurityDecorator::new(Arc::clone(&config));

decorator.register(
    "admin_api",
    RouteConfig::new()
        .require_https()
        .require_auth("Bearer")
        .rate_limit(10, 60)
        .require_ip(Some(vec!["10.0.0.0/24".into()]), None),
);
```

`register` accepts any `impl Into<String>` as the route id. Unregister with `unregister(&str)` or look up with `get_route_config(&str)`.

## Runtime resolution

Checks look up per-route configuration through [`get_route_decorator_config`](https://docs.rs/guard-core-rs/latest/guard_core_rs/decorators/fn.get_route_decorator_config.html), which reads the route id from request state at key `ROUTE_ID_STATE_KEY` and consults the decorator registry:

```rust,ignore
use guard_core_rs::decorators::base::{ROUTE_ID_STATE_KEY, get_route_decorator_config};

request.state().set_str(ROUTE_ID_STATE_KEY, "admin_api");
let rc = get_route_decorator_config(&request, &decorator);
```

Framework adapters typically set this key during routing so that the pipeline can resolve the per-route config without duplicating the router's matching logic.

## Behaviour tracker integration

`SecurityDecorator::behavior_tracker()` returns the shared [`BehaviorTracker`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/behavior/struct.BehaviorTracker.html) used by all decorators. Initialise it with `initialize_behavior_tracking(redis)` to persist counts across processes, and with `initialize_agent(agent, Some(ipban))` to emit behaviour events and auto-ban violators.

## Event emission

The decorator ships helper methods for publishing agent events tied to per-route policy:

- `send_access_denied_event`
- `send_authentication_failed_event`
- `send_rate_limit_event`
- `send_decorator_violation_event`

All four share the same metadata shape (timestamp, IP, user-agent, endpoint, method, response time, decorator type, plus a user-supplied metadata map).

## Adapter ergonomics

If your adapter uses attribute macros, the recommended pattern is to generate a `static` or `lazy_static` `RouteConfig`, register it at router build time, then ensure the route handler pushes the route id into `RequestState` before the pipeline executes. See `examples/with_decorator.rs` for a complete walkthrough.
