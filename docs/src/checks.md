# Security Checks

`SecurityCheck` is a trait that takes a request and returns `Result<Option<DynGuardResponse>>`. A concrete check returns `Ok(None)` to let the request continue, `Ok(Some(response))` to block with a specific response, or `Err(_)` to fail the pipeline.

The canonical pipeline is a [`SecurityCheckPipeline`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/struct.SecurityCheckPipeline.html) holding an ordered `Vec<Arc<dyn SecurityCheck>>`. Execution is strictly sequential and short-circuits on the first `Some(response)`.

## Built-in checks

The Python port defines 17 built-in checks. The Rust port has the same set:

| Order | Type | Purpose |
|-------|------|---------|
| 1 | [`RouteConfigCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.RouteConfigCheck.html) | Resolve `RouteConfig` from the request state. |
| 2 | [`EmergencyModeCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.EmergencyModeCheck.html) | Short-circuit every request except whitelisted IPs during emergency mode. |
| 3 | [`HttpsEnforcementCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.HttpsEnforcementCheck.html) | Redirect HTTP to HTTPS when enforced. |
| 4 | [`RequestLoggingCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.RequestLoggingCheck.html) | Emit structured logs and metrics. |
| 5 | [`RequestSizeContentCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.RequestSizeContentCheck.html) | Enforce `max_request_size` and content-type allow list. |
| 6 | [`RequiredHeadersCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.RequiredHeadersCheck.html) | Require specific headers to be present. |
| 7 | [`AuthenticationCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.AuthenticationCheck.html) | Validate `Bearer`, `Basic`, or custom auth schemes. |
| 8 | [`ReferrerCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.ReferrerCheck.html) | Restrict requests to allowed referrer domains. |
| 9 | [`CustomValidatorsCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.CustomValidatorsCheck.html) | Run user-supplied validators. |
| 10 | [`TimeWindowCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.TimeWindowCheck.html) | Only serve requests inside a time window. |
| 11 | [`CloudIpRefreshCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.CloudIpRefreshCheck.html) | Periodic refresh of cached cloud IP ranges. |
| 12 | [`IpSecurityCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.IpSecurityCheck.html) | IP ban, global allow/deny, per-route IP ranges. |
| 13 | [`CloudProviderCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.CloudProviderCheck.html) | Block requests from AWS/GCP/Azure when configured. |
| 14 | [`UserAgentCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.UserAgentCheck.html) | Deny requests matching a blocked User-Agent pattern. |
| 15 | [`RateLimitCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.RateLimitCheck.html) | Global, endpoint, route, and geo rate limits. |
| 16 | [`SuspiciousActivityCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.SuspiciousActivityCheck.html) | Run the detection engine across path/query/headers/body. |
| 17 | [`CustomRequestCheck`](https://docs.rs/guard-core-rs/latest/guard_core_rs/core/checks/implementations/struct.CustomRequestCheck.html) | Execute a user-provided async closure. |

You do not need to register every check. The pipeline runs whatever you add, in the order you add.

## Trait contract

```rust,ignore
use async_trait::async_trait;
use guard_core_rs::core::checks::SecurityCheck;
use guard_core_rs::error::Result;
use guard_core_rs::protocols::middleware::DynGuardMiddleware;
use guard_core_rs::protocols::request::DynGuardRequest;
use guard_core_rs::protocols::response::DynGuardResponse;

struct RequireApiKey { middleware: DynGuardMiddleware }

#[async_trait]
impl SecurityCheck for RequireApiKey {
    fn check_name(&self) -> &'static str { "require_api_key" }
    fn middleware(&self) -> &DynGuardMiddleware { &self.middleware }
    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        if request.header("X-Api-Key").is_none() {
            return Ok(Some(self.middleware.create_error_response(401, "api key required").await?));
        }
        Ok(None)
    }
}
```

`check_name` is used for debug formatting and selective removal via `SecurityCheckPipeline::remove_check`. `is_passive_mode` has a default implementation that reads `middleware.config().passive_mode`.

## Passive mode interaction

Every built-in check honours passive mode: if a check decides to block, it still logs and emits the agent event, but it returns `Ok(None)` when `passive_mode` is on. Custom checks should follow the same discipline.

## Registering custom checks

See the `examples/custom_check.rs` binary, reproduced in outline:

```bash
cargo run --example custom_check
```

The example shows implementing two independent checks and combining them into a pipeline that short-circuits on the first failure.

## Order matters

IP-based checks (`IpSecurityCheck`, `RateLimitCheck`) use `CLIENT_IP_KEY` from the request state. A framework adapter typically populates that state before pushing the request through the pipeline. If your custom check also needs the resolved IP, place it after `IpSecurityCheck`.

Likewise, `SuspiciousActivityCheck` is expensive: keep it late in the pipeline so cheaper bans and rate limits short-circuit first.
