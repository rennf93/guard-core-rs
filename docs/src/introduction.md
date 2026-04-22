# Introduction

`guard-core-rs` is the Rust port of the Python `guard-core` library. It provides a framework-agnostic, application-layer security engine with IP controls, rate limiting, penetration-attempt detection, behavioural rules, and cloud-provider filtering. Every integration point lives behind a trait (`GuardRequest`, `GuardResponse`, `GuardResponseFactory`, `GuardMiddlewareProtocol`, `RedisHandlerProtocol`, `GeoIpHandler`, `AgentHandlerProtocol`), so the crate can plug into Axum, Actix, Rocket, tower-based stacks, or a custom runtime.

The design goal is the same as the Python implementation: let an application pick a small set of composable checks, configure them through `SecurityConfig` or per-route `RouteConfig`, and run them inside a `SecurityCheckPipeline` that short-circuits on the first blocking response.

## Why a Rust port?

- **Predictable latency**. Regex detection and pipeline dispatch run in a compiled, cache-friendly runtime with no GC pauses.
- **Embeddability**. The crate is `#![forbid(unsafe_code)]`, has no required global state, and exposes `Arc`-backed handlers that are safe to share between tasks.
- **Feature parity with guard-core**. The same 17 built-in checks, detection engine, preprocessor, semantic analyzer, behaviour tracker, cloud handler, and rate limiter are available.
- **First-class Redis support**. The `redis-support` feature enables distributed rate limits, IP bans, dynamic rule sync, and cloud IP caching across instances.

## What it is not

- It is not a web framework or middleware shim on its own. An adapter crate implements the request/response traits for a specific framework and delegates to `SecurityCheckPipeline`.
- It is not an IDS/IPS. The detection engine is tuned for application-layer inputs (URL paths, query parameters, headers, request bodies) and deliberately stays fast and simple.
- It is not a static analyzer. Every rule is evaluated at request time against the live content.

## Project layout

The crate is organised as:

```text
src/
  core/            pipeline, checks, routing, validation, bypass, behavioural, events, init, responses
  detection_engine/ pattern compiler, preprocessor, semantic analyzer, performance monitor
  handlers/        ip ban, rate limit, cloud ranges, geo-ip, suspicious patterns, redis, behaviour
  decorators/      RouteConfig and SecurityDecorator
  protocols/       framework-agnostic traits the adapter fills in
  models.rs        SecurityConfig, CloudProvider, LogLevel and other domain models
```

## API reference

Full rustdoc output lives at <https://docs.rs/guard-core-rs/>. This book focuses on configuration, pipeline behaviour, and embedding patterns. Whenever an API detail is load-bearing, the relevant trait or function is linked into the generated rustdoc rather than duplicated here.

## Status

The crate mirrors the public surface of Python `guard-core` v6+. All 17 checks and the detection engine have parity tests. See [Testing](./testing.md) for coverage expectations and [Development](./development.md) for contribution workflow.
