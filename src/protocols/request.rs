//! Request-side protocol abstracting over framework-specific request objects.
//!
//! [`crate::protocols::request::GuardRequest`] exposes the fields Guard Core
//! needs from an incoming request — URL, method, headers, client IP, body, and
//! a mutable state bag. Adapters implement this trait by wrapping their
//! framework's request type. The state bag is modelled by
//! [`crate::protocols::request::RequestState`] and holds
//! [`crate::protocols::request::StateValue`] entries.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;

use crate::error::Result;

/// Type alias for a shared, dynamically-dispatched
/// [`crate::protocols::request::GuardRequest`] used throughout the crate.
///
/// Stored as [`Arc`] so checks can clone cheaply and outlive the request.
pub type DynGuardRequest = Arc<dyn GuardRequest>;

/// Framework-agnostic trait describing an inbound request.
///
/// Adapters implement this trait by wrapping their framework's native request
/// type. Guard Core only reads from a request and mutates it via the
/// associated [`crate::protocols::request::RequestState`].
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use guard_core_rs::protocols::request::GuardRequest;
///
/// fn describe(request: Arc<dyn GuardRequest>) -> String {
///     format!("{} {}", request.method(), request.url_path())
/// }
/// ```
#[async_trait]
pub trait GuardRequest: Send + Sync {
    /// Returns the URL path portion (no scheme, host, or query string).
    fn url_path(&self) -> String;
    /// Returns the URL scheme (`"http"` or `"https"`).
    fn url_scheme(&self) -> String;
    /// Returns the full absolute URL.
    fn url_full(&self) -> String;
    /// Returns the full URL with the scheme replaced by `scheme`.
    fn url_replace_scheme(&self, scheme: &str) -> String;
    /// Returns the HTTP method name in upper-case (`"GET"`, `"POST"`, ...).
    fn method(&self) -> String;
    /// Returns the connecting client's host, if the framework provides it.
    fn client_host(&self) -> Option<String>;
    /// Returns all request headers as a [`HashMap`].
    fn headers(&self) -> HashMap<String, String>;
    /// Returns the value of a header, looked up case-insensitively.
    fn header(&self, name: &str) -> Option<String> {
        let name_lower = name.to_ascii_lowercase();
        self.headers()
            .into_iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v)
    }
    /// Returns all parsed query parameters.
    fn query_params(&self) -> HashMap<String, String>;
    /// Returns a single query parameter by name.
    fn query_param(&self, name: &str) -> Option<String> {
        self.query_params().get(name).cloned()
    }
    /// Reads (or re-reads) the request body.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Io`] or
    /// [`crate::error::GuardCoreError::Other`] if the body cannot be read.
    async fn body(&self) -> Result<Bytes>;
    /// Returns the per-request mutable state bag.
    fn state(&self) -> Arc<RequestState>;
    /// Returns the framework-native ASGI/WSGI scope as a JSON map.
    fn scope(&self) -> HashMap<String, serde_json::Value>;
}

/// Typed value stored in [`crate::protocols::request::RequestState`].
///
/// Covers the primitive payload types that security checks exchange between
/// each other; use [`crate::protocols::request::StateValue::Json`] for
/// arbitrary structured data.
#[derive(Debug, Clone)]
pub enum StateValue {
    /// Boolean value.
    Bool(bool),
    /// Signed integer value.
    Int(i64),
    /// 64-bit floating-point value.
    Float(f64),
    /// UTF-8 string value.
    String(String),
    /// Opaque byte sequence.
    Bytes(Bytes),
    /// Arbitrary [`serde_json::Value`].
    Json(serde_json::Value),
}

impl StateValue {
    /// Returns the inner string slice when the variant is
    /// [`crate::protocols::request::StateValue::String`].
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    /// Returns the value as [`f64`] when the variant is
    /// [`crate::protocols::request::StateValue::Float`] or
    /// [`crate::protocols::request::StateValue::Int`].
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            Self::Int(i) => Some(*i as f64),
            _ => None,
        }
    }
    /// Returns the inner [`bool`] when the variant is
    /// [`crate::protocols::request::StateValue::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
    /// Returns the value as [`i64`] when the variant is
    /// [`crate::protocols::request::StateValue::Int`] or
    /// [`crate::protocols::request::StateValue::Float`] (truncating).
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Float(f) => Some(*f as i64),
            _ => None,
        }
    }
}

/// Concurrent key-value bag associated with a single request.
///
/// Shared across the pipeline so checks can pass contextual data (client IP,
/// correlation id, timing information, etc.) to later steps.
#[derive(Debug, Default)]
pub struct RequestState {
    data: DashMap<String, StateValue>,
}

impl RequestState {
    /// Creates an empty [`crate::protocols::request::RequestState`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a clone of the value stored under `key`, if any.
    pub fn get(&self, key: &str) -> Option<StateValue> {
        self.data.get(key).map(|v| v.value().clone())
    }

    /// Reads the value stored under `key` as a [`String`] when possible.
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.get(key).and_then(|v| match v {
            StateValue::String(s) => Some(s),
            _ => None,
        })
    }

    /// Reads the value stored under `key` as [`f64`] when possible.
    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| v.as_f64())
    }

    /// Reads the value stored under `key` as [`i64`] when possible.
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_int())
    }

    /// Reads the value stored under `key` as [`bool`] when possible.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    /// Inserts or replaces the entry under `key`.
    pub fn set(&self, key: impl Into<String>, value: StateValue) {
        self.data.insert(key.into(), value);
    }

    /// Inserts a [`crate::protocols::request::StateValue::String`] value.
    pub fn set_str(&self, key: impl Into<String>, value: impl Into<String>) {
        self.set(key, StateValue::String(value.into()));
    }

    /// Inserts a [`crate::protocols::request::StateValue::Float`] value.
    pub fn set_f64(&self, key: impl Into<String>, value: f64) {
        self.set(key, StateValue::Float(value));
    }

    /// Inserts a [`crate::protocols::request::StateValue::Int`] value.
    pub fn set_i64(&self, key: impl Into<String>, value: i64) {
        self.set(key, StateValue::Int(value));
    }

    /// Inserts a [`crate::protocols::request::StateValue::Bool`] value.
    pub fn set_bool(&self, key: impl Into<String>, value: bool) {
        self.set(key, StateValue::Bool(value));
    }

    /// Removes and returns the value stored under `key`.
    pub fn remove(&self, key: &str) -> Option<StateValue> {
        self.data.remove(key).map(|(_, v)| v)
    }

    /// Returns `true` when `key` is present in the state bag.
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }
}
