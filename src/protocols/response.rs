//! Response-side protocol abstracting over framework-specific response types.
//!
//! [`crate::protocols::response::GuardResponse`] exposes mutable headers and
//! a status code, and [`crate::protocols::response::GuardResponseFactory`]
//! lets Guard Core produce error and redirect responses without knowing the
//! concrete framework type.

use std::collections::HashMap;
use std::sync::Arc;

/// Type alias for a shared, dynamically-dispatched
/// [`crate::protocols::response::GuardResponse`].
pub type DynGuardResponse = Arc<dyn GuardResponse>;

/// Type alias for a shared
/// [`crate::protocols::response::GuardResponseFactory`] implementation.
pub type DynGuardResponseFactory = Arc<dyn GuardResponseFactory>;

/// Framework-agnostic trait describing an outbound response.
///
/// Adapters implement this trait by wrapping their framework's native response
/// type. Guard Core only reads the status code and body and mutates headers;
/// it never replaces the entire response object.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::protocols::response::GuardResponse;
///
/// fn stamp(response: Arc<dyn GuardResponse>) {
///     response.set_header("X-Processed-By", "guard-core-rs");
/// }
/// ```
pub trait GuardResponse: Send + Sync + std::fmt::Debug {
    /// Returns the HTTP status code of the response.
    fn status_code(&self) -> u16;
    /// Returns every response header.
    fn headers(&self) -> HashMap<String, String>;
    /// Returns a single header by name, case-insensitively.
    fn header(&self, name: &str) -> Option<String> {
        let name_lower = name.to_ascii_lowercase();
        self.headers()
            .into_iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v)
    }
    /// Sets or replaces a header value.
    fn set_header(&self, name: &str, value: &str);
    /// Removes a header if present.
    fn remove_header(&self, name: &str);
    /// Returns the response body, if available without consuming the stream.
    fn body(&self) -> Option<bytes::Bytes>;
}

/// Factory that constructs concrete
/// [`crate::protocols::response::GuardResponse`] implementations for error and
/// redirect responses.
pub trait GuardResponseFactory: Send + Sync + std::fmt::Debug {
    /// Creates a standard text response with the given body and status code.
    fn create_response(&self, content: &str, status_code: u16) -> DynGuardResponse;
    /// Creates an HTTP redirect response pointing at `url`.
    fn create_redirect_response(&self, url: &str, status_code: u16) -> DynGuardResponse;
}
