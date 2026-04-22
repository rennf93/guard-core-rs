#[path = "support/request.rs"]
mod mock_request;

use std::sync::Arc;

use bytes::Bytes;

use guard_core_rs::protocols::request::{GuardRequest, RequestState, StateValue};
use mock_request::MockRequest;

#[test]
fn state_value_as_str_returns_some_for_string() {
    let value = StateValue::String("hello".into());
    assert_eq!(value.as_str(), Some("hello"));
}

#[test]
fn state_value_as_str_returns_none_for_non_string() {
    assert_eq!(StateValue::Bool(true).as_str(), None);
    assert_eq!(StateValue::Int(1).as_str(), None);
    assert_eq!(StateValue::Float(1.0).as_str(), None);
    assert_eq!(StateValue::Bytes(Bytes::from_static(b"a")).as_str(), None);
    assert_eq!(
        StateValue::Json(serde_json::json!({"k": 1})).as_str(),
        None
    );
}

#[test]
fn state_value_as_f64_handles_numeric_variants() {
    assert_eq!(StateValue::Float(3.5).as_f64(), Some(3.5));
    assert_eq!(StateValue::Int(7).as_f64(), Some(7.0));
    assert_eq!(StateValue::Bool(true).as_f64(), None);
    assert_eq!(StateValue::String("x".into()).as_f64(), None);
}

#[test]
fn state_value_as_bool_returns_some_only_for_bool() {
    assert_eq!(StateValue::Bool(false).as_bool(), Some(false));
    assert_eq!(StateValue::Int(0).as_bool(), None);
    assert_eq!(StateValue::Float(0.0).as_bool(), None);
    assert_eq!(StateValue::String("true".into()).as_bool(), None);
}

#[test]
fn state_value_as_int_handles_numeric_variants() {
    assert_eq!(StateValue::Int(9).as_int(), Some(9));
    assert_eq!(StateValue::Float(9.9).as_int(), Some(9));
    assert_eq!(StateValue::Bool(true).as_int(), None);
    assert_eq!(StateValue::String("5".into()).as_int(), None);
    assert_eq!(StateValue::Bytes(Bytes::from_static(b"x")).as_int(), None);
    assert_eq!(
        StateValue::Json(serde_json::json!(1)).as_int(),
        None
    );
}

#[test]
fn request_state_new_is_empty() {
    let state = RequestState::new();
    assert!(state.get("missing").is_none());
    assert!(!state.contains("missing"));
}

#[test]
fn request_state_default_equals_new() {
    let default: RequestState = RequestState::default();
    assert!(!default.contains("any"));
}

#[test]
fn request_state_set_and_get_string() {
    let state = RequestState::new();
    state.set_str("name", "alice");
    assert_eq!(state.get_str("name").as_deref(), Some("alice"));
    assert!(state.contains("name"));
}

#[test]
fn request_state_get_str_none_for_non_string() {
    let state = RequestState::new();
    state.set_i64("count", 5);
    assert!(state.get_str("count").is_none());
}

#[test]
fn request_state_set_and_get_f64() {
    let state = RequestState::new();
    state.set_f64("ratio", 0.42);
    assert_eq!(state.get_f64("ratio"), Some(0.42));
    assert!(state.get_f64("missing").is_none());
}

#[test]
fn request_state_get_f64_from_int() {
    let state = RequestState::new();
    state.set_i64("n", 12);
    assert_eq!(state.get_f64("n"), Some(12.0));
}

#[test]
fn request_state_set_and_get_i64() {
    let state = RequestState::new();
    state.set_i64("total", 99);
    assert_eq!(state.get_i64("total"), Some(99));
}

#[test]
fn request_state_get_i64_from_float() {
    let state = RequestState::new();
    state.set_f64("ratio", 2.7);
    assert_eq!(state.get_i64("ratio"), Some(2));
}

#[test]
fn request_state_set_and_get_bool() {
    let state = RequestState::new();
    state.set_bool("flag", true);
    assert_eq!(state.get_bool("flag"), Some(true));
}

#[test]
fn request_state_get_bool_for_non_bool_returns_none() {
    let state = RequestState::new();
    state.set_str("key", "value");
    assert!(state.get_bool("key").is_none());
}

#[test]
fn request_state_set_with_generic_value() {
    let state = RequestState::new();
    state.set("blob", StateValue::Bytes(Bytes::from_static(b"abc")));
    match state.get("blob") {
        Some(StateValue::Bytes(b)) => assert_eq!(b.as_ref(), b"abc"),
        _ => panic!("expected bytes"),
    }
}

#[test]
fn request_state_remove_returns_existing_value() {
    let state = RequestState::new();
    state.set_str("key", "value");
    let removed = state.remove("key");
    assert!(matches!(removed, Some(StateValue::String(ref s)) if s == "value"));
    assert!(!state.contains("key"));
}

#[test]
fn request_state_remove_missing_returns_none() {
    let state = RequestState::new();
    assert!(state.remove("nope").is_none());
}

#[test]
fn request_state_json_variant_roundtrip() {
    let state = RequestState::new();
    state.set("payload", StateValue::Json(serde_json::json!({"x": 1})));
    match state.get("payload") {
        Some(StateValue::Json(v)) => assert_eq!(v["x"], 1),
        _ => panic!("expected json variant"),
    }
}

#[test]
fn state_value_debug_and_clone() {
    let value = StateValue::String("abc".into());
    let cloned = value.clone();
    assert_eq!(cloned.as_str(), Some("abc"));
    let debugged = format!("{:?}", StateValue::Int(1));
    assert!(debugged.contains("Int"));
}

#[test]
fn request_state_debug_output_contains_struct_name() {
    let state = RequestState::new();
    state.set_str("key", "value");
    let debugged = format!("{state:?}");
    assert!(debugged.contains("RequestState"));
}

#[tokio::test]
async fn mock_request_header_lookup_is_case_insensitive() {
    let request = MockRequest::builder()
        .header("Content-Type", "application/json")
        .build();
    let request: Arc<dyn GuardRequest> = Arc::new(request);
    assert_eq!(
        request.header("content-type").as_deref(),
        Some("application/json")
    );
    assert!(request.header("missing").is_none());
}

#[tokio::test]
async fn mock_request_query_param_lookup() {
    let request = MockRequest::builder()
        .query("token", "abc")
        .build();
    assert_eq!(request.query_param("token").as_deref(), Some("abc"));
    assert!(request.query_param("missing").is_none());
}
