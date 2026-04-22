# Architecture

`guard-core-rs` mirrors the modular layout of the Python engine. Each sub-module owns a single responsibility, depends on contracts (traits) rather than concrete types, and participates in a deterministic lifecycle.

## Ecosystem

```text
guard-core-rs   <- engine: checks, detection, handlers
axum-guard-rs   <- adapter (example): wires guard-core-rs into an Axum router
actix-guard-rs  <- adapter (example): wires guard-core-rs into an Actix service
```

The engine has zero dependency on any web framework. Axum, Actix, Rocket, or a custom runtime each provide an adapter crate that implements the protocols under `guard_core_rs::protocols`.

## Module map

```text
src/
  core/
    checks/       SecurityCheck, SecurityCheckPipeline, 17 built-ins, helpers
    events/       SecurityEventBus, MetricsCollector
    initialization/ HandlerInitializer
    responses/    ErrorResponseFactory, ResponseContext
    routing/      RouteConfigResolver, RoutingContext
    validation/   RequestValidator, ValidationContext
    bypass/       BypassHandler, BypassContext
    behavioral/   BehavioralProcessor, BehavioralContext
  detection_engine/
    compiler.rs   LRU-cached regex builder with safety validation
    preprocessor.rs Unicode + encoding normalisation
    semantic.rs   Keyword, entropy, and obfuscation scoring
    monitor.rs    Per-pattern performance tracking
  handlers/
    behavior.rs   BehaviorTracker + BehaviorRule
    cloud.rs      CloudManager (feature = cloud-providers)
    dynamic_rule.rs DynamicRuleManager
    ipban.rs      IPBanManager
    ipinfo.rs     IPInfoManager (feature = geoip)
    ratelimit.rs  RateLimitManager
    redis.rs      RedisManager (feature = redis-support)
    security_headers.rs Header rendering
    suspatterns.rs SusPatternsManager
  decorators/
    base.rs       RouteConfig, SecurityDecorator, CustomValidator
  protocols/      GuardRequest, GuardResponse, GuardResponseFactory, GuardMiddlewareProtocol, RedisHandlerProtocol, GeoIpHandler, AgentHandlerProtocol
  error.rs        GuardCoreError, GuardRedisError, Result alias
  models.rs       SecurityConfig, CloudProvider, LogLevel, HstsConfig, etc.
  utils.rs        IP parsing, logging helpers, state keys
```

## Design principles

1. **Protocols over types.** Every boundary is an `async_trait` or plain trait. See [`DynGuardRequest`](https://docs.rs/guard-core-rs/latest/guard_core_rs/protocols/request/type.DynGuardRequest.html), [`DynGuardResponse`](https://docs.rs/guard-core-rs/latest/guard_core_rs/protocols/response/type.DynGuardResponse.html), [`DynGuardMiddleware`](https://docs.rs/guard-core-rs/latest/guard_core_rs/protocols/middleware/type.DynGuardMiddleware.html).
2. **Explicit ownership.** Handlers are passed as `Arc` so multiple checks can share them without contention.
3. **Context objects for DI.** `RoutingContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`, `ResponseContext` group their dependencies into small `Clone + Debug` structs. Tests and benchmarks construct them directly.
4. **No globals.** There are no `lazy_static`/`OnceCell` singletons. Pipelines are plain values.
5. **Short-circuit semantics.** `SecurityCheckPipeline::execute` returns the first `Some(response)`. Later checks never observe that request.
6. **Feature gates map to transitive deps.** Disabling `redis-support` or `cloud-providers` removes their crates from the build and the corresponding checks from compilation.

## Request lifecycle

```text
adapter                          pipeline                        check
--------------------------------------------------------------------------------
native request
    |  wrap in DynGuardRequest
    |  populate client_ip, route_id in RequestState
    v
SecurityCheckPipeline::execute ---+--> check.check(request)
                                  |      |
                                  |      +-- Ok(None)        -> continue
                                  |      +-- Ok(Some(resp))  -> short-circuit
                                  |      +-- Err(_)          -> bubble up
                                  |
                                  v
                   return DynGuardResponse (or forward to service)
```

The adapter converts the `DynGuardResponse` back into a framework-native response.

## Error handling

[`GuardCoreError`](https://docs.rs/guard-core-rs/latest/guard_core_rs/error/enum.GuardCoreError.html) is a thiserror enum covering configuration, Redis, cloud providers, validation, IP parsing, and adapter-supplied errors. The top-level `Result` alias is `Result<T, GuardCoreError>`. Prefer returning `Ok(Some(error_response))` over `Err(_)` for policy denials; reserve `Err` for unexpected failures (Redis down, config invalid).

## Performance guarantees

- `SecurityCheckPipeline::execute` does no heap allocation beyond what individual checks do.
- `RateLimitManager` in-memory path is an `O(log n)` `VecDeque` scan per IP.
- `IPBanManager` uses a `moka` cache; look-ups are wait-free.
- `SusPatternsManager` caches compiled regexes in an LRU and runs each regex in a `spawn_blocking` task with a timeout when operating on large inputs.

Benchmarks covering each subsystem live in `benches/`. Run `cargo bench` to reproduce.
