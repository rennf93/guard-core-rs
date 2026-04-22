//! Chain-of-responsibility runner that executes registered security checks.
//!
//! [`crate::core::checks::pipeline::SecurityCheckPipeline`] holds an ordered
//! list of [`crate::core::checks::base::SecurityCheck`] implementations and
//! evaluates them against every incoming request until one short-circuits
//! with a response.

use std::sync::Arc;

use crate::core::checks::base::SecurityCheck;
use crate::error::Result;
use crate::protocols::request::DynGuardRequest;
use crate::protocols::response::DynGuardResponse;

/// Ordered collection of security checks evaluated sequentially per request.
///
/// The pipeline stops on the first check returning
/// [`Some`](crate::protocols::response::DynGuardResponse). Checks are stored
/// as [`Arc`]-ed trait objects so adapters can swap individual steps out at
/// runtime.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::core::checks::pipeline::SecurityCheckPipeline;
///
/// let pipeline = SecurityCheckPipeline::with_checks(Vec::new());
/// assert!(pipeline.get_check_names().is_empty());
/// # let _ = Arc::new(pipeline);
/// ```
pub struct SecurityCheckPipeline {
    checks: Vec<Arc<dyn SecurityCheck>>,
}

impl std::fmt::Debug for SecurityCheckPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityCheckPipeline")
            .field(
                "checks",
                &self.checks.iter().map(|c| c.check_name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Default for SecurityCheckPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityCheckPipeline {
    /// Creates an empty pipeline with no checks registered.
    pub const fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Creates a pipeline pre-populated with the supplied ordered checks.
    pub fn with_checks(checks: Vec<Arc<dyn SecurityCheck>>) -> Self {
        Self { checks }
    }

    /// Appends `check` to the end of the pipeline.
    pub fn add_check(&mut self, check: Arc<dyn SecurityCheck>) {
        self.checks.push(check);
    }

    /// Removes every check whose name equals `check_name`, returning `true`
    /// when at least one was removed.
    pub fn remove_check(&mut self, check_name: &str) -> bool {
        let before = self.checks.len();
        self.checks.retain(|c| c.check_name() != check_name);
        self.checks.len() != before
    }

    /// Returns the names of every registered check, in execution order.
    pub fn get_check_names(&self) -> Vec<&'static str> {
        self.checks.iter().map(|c| c.check_name()).collect()
    }

    /// Runs every check against `request`, returning the first short-circuit
    /// response.
    ///
    /// # Errors
    ///
    /// Propagates the first [`crate::error::GuardCoreError`] raised by any
    /// check.
    pub async fn execute(&self, request: &DynGuardRequest) -> Result<Option<DynGuardResponse>> {
        for check in &self.checks {
            if let Some(response) = check.check(request).await? {
                return Ok(Some(response));
            }
        }
        Ok(None)
    }
}
