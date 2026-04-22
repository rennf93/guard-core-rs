//! Lightweight processor that derives endpoint identifiers for behavioural
//! rule evaluation.

use crate::core::behavioral::context::BehavioralContext;
use crate::protocols::request::DynGuardRequest;

/// Processor that derives per-endpoint identifiers from a request.
#[derive(Clone, Debug)]
pub struct BehavioralProcessor {
    context: BehavioralContext,
}

impl BehavioralProcessor {
    /// Wraps `context` in a new processor.
    pub const fn new(context: BehavioralContext) -> Self {
        Self { context }
    }

    /// Returns the shared
    /// [`crate::core::behavioral::context::BehavioralContext`] reference.
    pub const fn context(&self) -> &BehavioralContext {
        &self.context
    }

    /// Returns the canonical endpoint identifier (`"METHOD:/path"`) for
    /// `request`.
    pub fn get_endpoint_id(&self, request: &DynGuardRequest) -> String {
        format!("{}:{}", request.method(), request.url_path())
    }
}
