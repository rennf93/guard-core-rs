use guard_core_rs::scripts::rate_lua::RATE_LIMIT_SCRIPT;

#[test]
fn rate_limit_script_is_non_empty() {
    assert!(!RATE_LIMIT_SCRIPT.is_empty());
    assert!(RATE_LIMIT_SCRIPT.len() > 50);
}

#[test]
fn rate_limit_script_contains_expected_redis_commands() {
    assert!(RATE_LIMIT_SCRIPT.contains("ZADD"));
    assert!(RATE_LIMIT_SCRIPT.contains("ZREMRANGEBYSCORE"));
    assert!(RATE_LIMIT_SCRIPT.contains("ZCARD"));
    assert!(RATE_LIMIT_SCRIPT.contains("EXPIRE"));
}

#[test]
fn rate_limit_script_uses_lua_arguments() {
    assert!(RATE_LIMIT_SCRIPT.contains("KEYS[1]"));
    assert!(RATE_LIMIT_SCRIPT.contains("ARGV[1]"));
    assert!(RATE_LIMIT_SCRIPT.contains("ARGV[2]"));
    assert!(RATE_LIMIT_SCRIPT.contains("ARGV[3]"));
}

#[test]
fn rate_limit_script_returns_count() {
    assert!(RATE_LIMIT_SCRIPT.contains("return count"));
}
