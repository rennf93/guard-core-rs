use std::io;
use std::time::Duration;

use guard_core_rs::error::{GuardCoreError, GuardRedisError, Result};

#[test]
fn guard_redis_error_new_and_display() {
    let err = GuardRedisError::new(500, "redis down");
    assert_eq!(err.status_code, 500);
    assert_eq!(err.detail, "redis down");
    assert_eq!(format!("{err}"), "redis down");
    let debug = format!("{err:?}");
    assert!(debug.contains("GuardRedisError"));
    assert!(debug.contains("500"));
}

#[test]
fn guard_redis_error_accepts_various_string_types() {
    let err_string = GuardRedisError::new(502, String::from("bad gateway"));
    assert_eq!(err_string.status_code, 502);
    let err_str = GuardRedisError::new(503, "service unavailable");
    assert_eq!(err_str.status_code, 503);
    assert_eq!(err_str.detail, "service unavailable");
}

#[test]
fn config_variant_display() {
    let err = GuardCoreError::Config("missing key".into());
    assert_eq!(err.to_string(), "configuration error: missing key");
}

#[test]
fn validation_variant_display() {
    let err = GuardCoreError::Validation("bad value".into());
    assert_eq!(err.to_string(), "validation error: bad value");
}

#[test]
fn pattern_variant_from_regex_error() {
    let bad = String::from("[");
    let regex_err = regex::Regex::new(&bad).expect_err("invalid regex");
    let err: GuardCoreError = regex_err.into();
    assert!(matches!(err, GuardCoreError::Pattern(_)));
    assert!(err.to_string().contains("pattern compilation error"));
}

#[test]
fn unsafe_pattern_variant_display() {
    let err = GuardCoreError::UnsafePattern("catastrophic".into());
    assert_eq!(err.to_string(), "pattern is unsafe: catastrophic");
}

#[test]
fn pattern_timeout_variant_display() {
    let err = GuardCoreError::PatternTimeout(Duration::from_millis(500));
    let msg = err.to_string();
    assert!(msg.contains("pattern execution timed out"));
    assert!(msg.contains("500"));
}

#[test]
fn io_variant_from_io_error() {
    let io_err = io::Error::new(io::ErrorKind::NotFound, "missing file");
    let err: GuardCoreError = io_err.into();
    assert!(matches!(err, GuardCoreError::Io(_)));
    assert!(err.to_string().contains("io error"));
}

#[tokio::test]
async fn http_variant_from_reqwest_error() {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1))
        .build()
        .expect("client");
    let err = client.get("http://127.0.0.1:1/xyz").send().await.unwrap_err();
    let converted: GuardCoreError = err.into();
    assert!(matches!(converted, GuardCoreError::Http(_)));
    assert!(converted.to_string().contains("http error"));
}

#[test]
fn json_variant_from_serde_error() {
    let json_err = serde_json::from_str::<serde_json::Value>("not valid json").unwrap_err();
    let err: GuardCoreError = json_err.into();
    assert!(matches!(err, GuardCoreError::Json(_)));
    assert!(err.to_string().contains("json error"));
}

#[test]
fn invalid_ip_variant_display() {
    let err = GuardCoreError::InvalidIp("junk".into());
    assert_eq!(err.to_string(), "invalid ip or cidr: junk");
}

#[test]
fn geo_ip_variant_display() {
    let err = GuardCoreError::GeoIp("no db".into());
    assert_eq!(err.to_string(), "geo ip lookup error: no db");
}

#[test]
fn cloud_provider_variant_display() {
    let err = GuardCoreError::CloudProvider("network".into());
    assert_eq!(err.to_string(), "cloud provider fetch error: network");
}

#[test]
fn rate_limit_variant_display() {
    let err = GuardCoreError::RateLimit("overflow".into());
    assert_eq!(err.to_string(), "rate limit error: overflow");
}

#[test]
fn behavior_variant_display() {
    let err = GuardCoreError::Behavior("rule".into());
    assert_eq!(err.to_string(), "behavior rule error: rule");
}

#[test]
fn agent_variant_display() {
    let err = GuardCoreError::Agent("buffer".into());
    assert_eq!(err.to_string(), "agent handler error: buffer");
}

#[test]
fn prompt_injection_variant_display() {
    let err = GuardCoreError::PromptInjection("found".into());
    assert_eq!(err.to_string(), "prompt injection detected: found");
}

#[test]
fn not_initialized_variant_display() {
    let err = GuardCoreError::NotInitialized("handler".into());
    assert_eq!(err.to_string(), "not initialized: handler");
}

#[test]
fn other_variant_display() {
    let err = GuardCoreError::Other("generic".into());
    assert_eq!(err.to_string(), "generic");
}

#[test]
fn redis_variant_from_guard_redis_error() {
    let redis_err = GuardRedisError::new(500, "pool empty");
    let core: GuardCoreError = redis_err.into();
    assert!(matches!(core, GuardCoreError::Redis(_)));
    assert_eq!(core.to_string(), "pool empty");
}

#[test]
fn debug_output_exists_for_every_variant() {
    let variants = [
        GuardCoreError::Redis(GuardRedisError::new(500, "r")),
        GuardCoreError::Config("c".into()),
        GuardCoreError::Validation("v".into()),
        GuardCoreError::UnsafePattern("p".into()),
        GuardCoreError::PatternTimeout(Duration::from_secs(1)),
        GuardCoreError::InvalidIp("ip".into()),
        GuardCoreError::GeoIp("g".into()),
        GuardCoreError::CloudProvider("cp".into()),
        GuardCoreError::RateLimit("rl".into()),
        GuardCoreError::Behavior("b".into()),
        GuardCoreError::Agent("a".into()),
        GuardCoreError::PromptInjection("pi".into()),
        GuardCoreError::NotInitialized("ni".into()),
        GuardCoreError::Other("o".into()),
    ];
    for v in &variants {
        let formatted = format!("{v:?}");
        assert!(!formatted.is_empty());
    }
}

#[test]
fn result_alias_works() {
    fn return_ok() -> Result<i32> {
        Ok(42)
    }
    let value = return_ok().expect("should be Ok");
    assert_eq!(value, 42);
    let err: Result<i32> = Err(GuardCoreError::Other("nope".into()));
    assert!(err.is_err());
}

#[cfg(feature = "redis-support")]
#[test]
fn redis_feature_from_redis_error() {
    let redis_err = redis::RedisError::from(std::io::Error::other("fail"));
    let core: GuardCoreError = redis_err.into();
    match core {
        GuardCoreError::Redis(g) => {
            assert_eq!(g.status_code, 500);
            assert!(!g.detail.is_empty());
        }
        other => panic!("expected Redis variant, got {other:?}"),
    }
}
