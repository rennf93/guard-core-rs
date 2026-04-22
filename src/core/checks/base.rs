//! Base trait implemented by every concrete security check.
//!
//! [`crate::core::checks::base::SecurityCheck`] is the chain-of-responsibility
//! contract: each check either returns [`None`] (continue the pipeline) or
//! [`Some`](crate::protocols::response::DynGuardResponse) to short-circuit the
//! request.

use async_trait::async_trait;

use crate::error::Result;
use crate::protocols::middleware::DynGuardMiddleware;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;

/// Behavioural contract for every security check run by the pipeline.
///
/// Implementations hold a
/// [`crate::protocols::middleware::DynGuardMiddleware`] reference so they can
/// access configuration, handlers, and the response factory.
///
/// # Examples
///
/// ```no_run
/// use async_trait::async_trait;
/// use guard_core_rs::core::checks::base::SecurityCheck;
/// use guard_core_rs::error::Result;
/// use guard_core_rs::protocols::middleware::DynGuardMiddleware;
/// use guard_core_rs::protocols::request::DynGuardRequest;
/// use guard_core_rs::protocols::response::DynGuardResponse;
///
/// struct ExampleCheck {
///     middleware: DynGuardMiddleware,
/// }
///
/// #[async_trait]
/// impl SecurityCheck for ExampleCheck {
///     fn check_name(&self) -> &'static str { "example" }
///     fn middleware(&self) -> &DynGuardMiddleware { &self.middleware }
///     async fn check(&self, _request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
///         Ok(None)
///     }
/// }
/// ```
#[async_trait]
pub trait SecurityCheck: Send + Sync {
    /// Returns the stable, kebab-case identifier used by bypass rules and
    /// telemetry.
    fn check_name(&self) -> &'static str;

    /// Evaluates the check against `request`.
    ///
    /// Returning `Ok(None)` hands control to the next check in the pipeline;
    /// returning `Ok(Some(response))` short-circuits the request with the
    /// given response.
    ///
    /// # Errors
    ///
    /// Returns any error raised by the check's dependencies
    /// (e.g. [`crate::error::GuardCoreError::Redis`]).
    async fn check(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>>;

    /// Returns the shared
    /// [`crate::protocols::middleware::DynGuardMiddleware`] reference.
    fn middleware(&self) -> &DynGuardMiddleware;

    /// Convenience accessor returning
    /// [`crate::models::SecurityConfig::passive_mode`].
    fn is_passive_mode(&self) -> bool {
        self.middleware().config().passive_mode
    }
}
