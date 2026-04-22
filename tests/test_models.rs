use std::collections::HashSet;

use guard_core_rs::models::{
    AgentConfig, CloudProvider, CustomRequestCheck, CustomResponseModifier, DynamicRules,
    HstsConfig, LogFormat, LogLevel, SecurityConfig, SecurityHeadersConfig, validate_ip_or_cidr,
};

#[test]
fn default_config_is_valid() {
    let cfg = SecurityConfig::builder().build().expect("default config should be valid");
    assert!(cfg.enable_redis);
    assert_eq!(cfg.rate_limit, 10);
    assert_eq!(cfg.rate_limit_window, 60);
    assert_eq!(cfg.redis_prefix, "guard_core:");
    assert_eq!(cfg.trusted_proxy_depth, 1);
    assert_eq!(cfg.log_suspicious_level, Some(LogLevel::Warning));
    assert_eq!(cfg.log_format, LogFormat::Text);
    assert!(!cfg.enable_agent);
    assert!(cfg.enable_ip_banning);
    assert!(cfg.enable_rate_limiting);
    assert!(cfg.enable_penetration_detection);
}

#[test]
fn valid_cidr_passes() {
    let cfg = SecurityConfig::builder()
        .whitelist(Some(vec!["10.0.0.0/8".into(), "192.168.1.1".into()]))
        .build()
        .expect("config should be valid");
    let whitelist = cfg.whitelist.as_ref().expect("whitelist is set");
    assert_eq!(whitelist.len(), 2);
}

#[test]
fn invalid_ip_rejected() {
    let err = SecurityConfig::builder()
        .blacklist(vec!["not-an-ip".into()])
        .build()
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("Invalid") || msg.contains("invalid"));
}

#[test]
fn trusted_proxy_depth_minimum() {
    let config = SecurityConfig {
        trusted_proxy_depth: 0,
        ..SecurityConfig::builder().build().expect("base")
    };
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("trusted_proxy_depth"));
}

#[test]
fn agent_api_key_required() {
    let err = SecurityConfig::builder()
        .enable_agent(true)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("agent_api_key"));
}

#[test]
fn dynamic_rules_require_agent() {
    let err = SecurityConfig::builder()
        .enable_dynamic_rules(true)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("enable_agent"));
}

#[test]
fn detection_timeout_bounds() {
    let config = SecurityConfig {
        detection_compiler_timeout: 0.05,
        ..SecurityConfig::builder().build().expect("base")
    };
    assert!(config.validate().is_err());
}

#[test]
fn detection_threshold_bounds() {
    let config = SecurityConfig {
        detection_semantic_threshold: 1.5,
        ..SecurityConfig::builder().build().expect("base")
    };
    assert!(config.validate().is_err());
}

#[test]
fn security_headers_defaults() {
    let headers = SecurityHeadersConfig::default();
    assert!(headers.enabled);
    assert_eq!(headers.frame_options, "SAMEORIGIN");
    assert_eq!(headers.content_type_options, "nosniff");
    assert!(headers.hsts.include_subdomains);
    assert_eq!(headers.hsts.max_age, 31_536_000);
}

#[test]
fn cloud_provider_parsing() {
    assert_eq!(CloudProvider::from_str_loose("AWS"), Some(CloudProvider::Aws));
    assert_eq!(CloudProvider::from_str_loose("gcp"), Some(CloudProvider::Gcp));
    assert_eq!(CloudProvider::from_str_loose("AZURE"), Some(CloudProvider::Azure));
    assert_eq!(CloudProvider::from_str_loose("unknown"), None);
}

#[test]
fn dynamic_rules_default_values() {
    let rules = DynamicRules::default();
    assert_eq!(rules.ttl, 0);
    assert_eq!(rules.ip_ban_duration, 0);
    assert!(!rules.emergency_mode);
}

#[test]
fn dynamic_rules_serde_defaults_fire_when_fields_missing() {
    let json = r#"{"rule_id":"r","version":1,"timestamp":"2024-01-01T00:00:00Z"}"#;
    let rules: DynamicRules = serde_json::from_str(json).expect("parse");
    assert_eq!(rules.ttl, 300);
    assert_eq!(rules.ip_ban_duration, 3600);
}

#[test]
fn log_level_default_is_warning() {
    assert_eq!(LogLevel::default(), LogLevel::Warning);
}

#[test]
fn log_format_default_is_text() {
    assert_eq!(LogFormat::default(), LogFormat::Text);
}

#[test]
fn cloud_provider_as_str_round_trip() {
    assert_eq!(CloudProvider::Aws.as_str(), "AWS");
    assert_eq!(CloudProvider::Gcp.as_str(), "GCP");
    assert_eq!(CloudProvider::Azure.as_str(), "Azure");
}

#[test]
fn cloud_provider_from_str_loose_all_variants() {
    assert_eq!(CloudProvider::from_str_loose("Aws"), Some(CloudProvider::Aws));
    assert_eq!(CloudProvider::from_str_loose("aws"), Some(CloudProvider::Aws));
    assert_eq!(CloudProvider::from_str_loose("GCP"), Some(CloudProvider::Gcp));
    assert_eq!(CloudProvider::from_str_loose("Gcp"), Some(CloudProvider::Gcp));
    assert_eq!(CloudProvider::from_str_loose("Azure"), Some(CloudProvider::Azure));
    assert_eq!(CloudProvider::from_str_loose("azure"), Some(CloudProvider::Azure));
    assert_eq!(CloudProvider::from_str_loose("  AWS  "), Some(CloudProvider::Aws));
    assert_eq!(CloudProvider::from_str_loose("xyz"), None);
}

#[test]
fn hsts_config_default_values() {
    let hsts = HstsConfig::default();
    assert_eq!(hsts.max_age, 31_536_000);
    assert!(hsts.include_subdomains);
    assert!(!hsts.preload);
    let debug = format!("{hsts:?}");
    assert!(debug.contains("HstsConfig"));
}

#[test]
fn security_headers_config_debug() {
    let c = SecurityHeadersConfig::default();
    assert!(c.enabled);
    assert!(format!("{c:?}").contains("SecurityHeadersConfig"));
}

#[test]
fn validate_ip_or_cidr_accepts_cidr() {
    let out = validate_ip_or_cidr("10.0.0.0/8").expect("valid");
    assert!(out.contains('/'));
}

#[test]
fn validate_ip_or_cidr_accepts_plain_ip() {
    let out = validate_ip_or_cidr("192.168.1.1").expect("valid");
    assert!(!out.contains('/'));
}

#[test]
fn validate_ip_or_cidr_rejects_invalid_cidr() {
    let err = validate_ip_or_cidr("not/a/cidr").unwrap_err();
    assert!(err.to_string().contains("invalid"));
}

#[test]
fn validate_ip_or_cidr_rejects_invalid_ip() {
    let err = validate_ip_or_cidr("not-an-ip").unwrap_err();
    assert!(err.to_string().contains("invalid"));
}

#[test]
fn validate_rejects_invalid_trusted_proxy() {
    let err = SecurityConfig::builder()
        .trusted_proxies(vec!["junk".into()])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("proxy IP or CIDR") || err.to_string().contains("invalid"));
}

#[test]
fn validate_rejects_invalid_whitelist_entry() {
    let err = SecurityConfig::builder()
        .whitelist(Some(vec!["nope".into()]))
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("invalid") || err.to_string().contains("Invalid"));
}

#[test]
fn validate_requires_geo_handler_for_blocked_countries() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.blocked_countries = vec!["CN".into()];
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("geo_ip_handler"));
}

#[test]
fn validate_requires_geo_handler_for_whitelist_countries() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.whitelist_countries = vec!["US".into()];
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("geo_ip_handler"));
}

#[test]
fn validate_accepts_ipinfo_token_as_geo_fallback() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.blocked_countries = vec!["CN".into()];
    config.ipinfo_token = Some("fake-token".into());
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_content_length_out_of_range_low() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.detection_max_content_length = 500;
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_content_length_out_of_range_high() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.detection_max_content_length = 500_000;
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_detection_anomaly_threshold_out_of_range() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.detection_anomaly_threshold = 0.5;
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_detection_slow_pattern_threshold_too_low() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.detection_slow_pattern_threshold = 0.005;
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_detection_slow_pattern_threshold_too_high() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.detection_slow_pattern_threshold = 2.0;
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_detection_monitor_history_out_of_range() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.detection_monitor_history_size = 20;
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_detection_max_tracked_patterns_out_of_range() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.detection_max_tracked_patterns = 50_000;
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_cloud_ip_refresh_out_of_range() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.cloud_ip_refresh_interval = 5;
    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_invalid_blacklist() {
    let err = SecurityConfig::builder()
        .blacklist(vec!["bad/ip".into()])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("invalid") || err.to_string().contains("Invalid"));
}

#[test]
fn validate_raw_config_catches_invalid_trusted_proxies_direct() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.trusted_proxies = vec!["not-an-ip".into()];
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("Invalid proxy"));
}

#[test]
fn validate_raw_config_catches_invalid_whitelist_direct() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.whitelist = Some(vec!["not-an-ip".into()]);
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("Invalid IP or CIDR"));
}

#[test]
fn validate_raw_config_catches_invalid_blacklist_direct() {
    let mut config = SecurityConfig::builder().build().expect("base");
    config.blacklist = vec!["not-an-ip".into()];
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("Invalid IP or CIDR"));
}

#[test]
fn security_config_debug_output() {
    let cfg = SecurityConfig::builder().build().expect("valid");
    assert!(format!("{cfg:?}").contains("SecurityConfig"));
}

#[test]
fn to_agent_config_returns_none_when_disabled() {
    let cfg = SecurityConfig::builder().build().expect("valid");
    assert!(cfg.to_agent_config().is_none());
}

#[test]
fn to_agent_config_returns_none_when_api_key_missing() {
    let mut cfg = SecurityConfig::builder().build().expect("valid");
    cfg.enable_agent = true;
    cfg.agent_api_key = None;
    assert!(cfg.to_agent_config().is_none());
}

#[test]
fn to_agent_config_returns_some_when_enabled_with_api_key() {
    let cfg = SecurityConfig::builder()
        .enable_agent(true)
        .agent_api_key(Some("key-123".into()))
        .build()
        .expect("valid");
    let agent = cfg.to_agent_config().expect("some");
    assert_eq!(agent.api_key, "key-123");
    assert_eq!(agent.endpoint, "https://api.fastapi-guard.com");
    assert!(format!("{agent:?}").contains("AgentConfig"));
}

#[test]
fn security_config_builder_exposes_setters_for_all_fields() {
    let cfg = SecurityConfig::builder()
        .trusted_proxies(vec!["10.0.0.0/8".into()])
        .trusted_proxy_depth(2)
        .trust_x_forwarded_proto(true)
        .passive_mode(true)
        .enable_redis(false)
        .redis_url(Some("redis://other".into()))
        .redis_prefix("prefix:")
        .whitelist(Some(vec!["10.0.0.1".into()]))
        .blacklist(vec!["1.2.3.4".into()])
        .whitelist_countries(vec![])
        .blocked_countries(vec![])
        .blocked_user_agents(vec!["bot".into()])
        .auto_ban_threshold(5)
        .auto_ban_duration(1800)
        .rate_limit(100)
        .rate_limit_window(30)
        .enforce_https(true)
        .enable_ip_banning(false)
        .enable_rate_limiting(false)
        .enable_penetration_detection(false)
        .enable_agent(false)
        .agent_api_key(None)
        .enable_dynamic_rules(false)
        .block_cloud_providers(Some(HashSet::from([CloudProvider::Aws])))
        .build()
        .expect("valid");
    assert_eq!(cfg.trusted_proxy_depth, 2);
    assert!(cfg.trust_x_forwarded_proto);
    assert!(cfg.passive_mode);
    assert!(!cfg.enable_redis);
    assert_eq!(cfg.redis_url.as_deref(), Some("redis://other"));
    assert_eq!(cfg.redis_prefix, "prefix:");
    assert_eq!(cfg.auto_ban_threshold, 5);
    assert_eq!(cfg.auto_ban_duration, 1800);
    assert_eq!(cfg.rate_limit, 100);
    assert_eq!(cfg.rate_limit_window, 30);
    assert!(cfg.enforce_https);
    assert!(!cfg.enable_ip_banning);
    assert!(!cfg.enable_rate_limiting);
    assert!(!cfg.enable_penetration_detection);
    assert!(cfg.block_cloud_providers.as_ref().is_some());
}

#[test]
fn security_config_default_whitelist_is_none_when_not_set() {
    let cfg = SecurityConfig::builder().whitelist(None).build().expect("valid");
    assert!(cfg.whitelist.is_none());
}

#[test]
fn custom_request_check_debug_output() {
    let check = CustomRequestCheck(std::sync::Arc::new(|_req| Box::pin(async { None })));
    let debug = format!("{check:?}");
    assert!(debug.contains("CustomRequestCheck"));
    let cloned = check.clone();
    let _ = format!("{cloned:?}");
}

#[test]
fn custom_response_modifier_debug_output() {
    let modifier = CustomResponseModifier(std::sync::Arc::new(|resp| Box::pin(async { resp })));
    let debug = format!("{modifier:?}");
    assert!(debug.contains("CustomResponseModifier"));
    let cloned = modifier.clone();
    let _ = format!("{cloned:?}");
}

#[test]
fn log_level_serde_roundtrip() {
    for level in [
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Warning,
        LogLevel::Error,
        LogLevel::Critical,
    ] {
        let json = serde_json::to_string(&level).expect("serialize");
        let back: LogLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, level);
    }
}

#[test]
fn log_format_serde_roundtrip() {
    for fmt in [LogFormat::Text, LogFormat::Json] {
        let json = serde_json::to_string(&fmt).expect("serialize");
        let back: LogFormat = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, fmt);
    }
}

#[test]
fn cloud_provider_serde_roundtrip() {
    for cp in [CloudProvider::Aws, CloudProvider::Gcp, CloudProvider::Azure] {
        let json = serde_json::to_string(&cp).expect("serialize");
        let back: CloudProvider = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, cp);
    }
}

#[test]
fn cloud_provider_ordering() {
    let mut set = [CloudProvider::Gcp, CloudProvider::Aws, CloudProvider::Azure];
    set.sort();
    assert_eq!(set[0], CloudProvider::Aws);
}

#[test]
fn hsts_config_serde_defaults() {
    let json = r#"{}"#;
    let hsts: HstsConfig = serde_json::from_str(json).expect("defaults");
    assert_eq!(hsts.max_age, 31_536_000);
    assert!(hsts.include_subdomains);
    assert!(!hsts.preload);
}

#[test]
fn security_headers_config_serde_defaults() {
    let json = r#"{}"#;
    let h: SecurityHeadersConfig = serde_json::from_str(json).expect("defaults");
    assert!(h.enabled);
    assert_eq!(h.frame_options, "SAMEORIGIN");
    assert_eq!(h.content_type_options, "nosniff");
    assert_eq!(h.xss_protection, "1; mode=block");
    assert_eq!(h.referrer_policy, "strict-origin-when-cross-origin");
    assert_eq!(h.permissions_policy, "geolocation=(), microphone=(), camera=()");
    assert!(h.csp.is_none());
    assert!(h.custom.is_none());
}

#[test]
fn agent_config_serde_defaults() {
    let json = r#"{"api_key":"key","project_id":null}"#;
    let a: AgentConfig = serde_json::from_str(json).expect("defaults");
    assert_eq!(a.api_key, "key");
    assert_eq!(a.endpoint, "https://api.fastapi-guard.com");
    assert_eq!(a.buffer_size, 100);
    assert_eq!(a.flush_interval, 30);
    assert!(a.enable_events);
    assert!(a.enable_metrics);
    assert_eq!(a.timeout, 30);
    assert_eq!(a.retry_attempts, 3);
}

#[test]
fn dynamic_rules_debug_output() {
    let rules = DynamicRules::default();
    let debug = format!("{rules:?}");
    assert!(debug.contains("DynamicRules"));
    let cloned = rules.clone();
    assert_eq!(cloned.rule_id, rules.rule_id);
}

#[test]
fn dynamic_rules_roundtrip() {
    let rules = DynamicRules {
        rule_id: "test".into(),
        version: 1,
        timestamp: chrono::Utc::now(),
        expires_at: None,
        ttl: 600,
        ip_blacklist: vec!["10.0.0.1".into()],
        ip_whitelist: Vec::new(),
        ip_ban_duration: 3600,
        blocked_countries: vec!["CN".into()],
        whitelist_countries: Vec::new(),
        global_rate_limit: Some(100),
        global_rate_window: Some(60),
        endpoint_rate_limits: Default::default(),
        blocked_cloud_providers: Default::default(),
        blocked_user_agents: Vec::new(),
        suspicious_patterns: Vec::new(),
        enable_penetration_detection: Some(true),
        enable_ip_banning: Some(true),
        enable_rate_limiting: Some(true),
        emergency_mode: false,
        emergency_whitelist: Vec::new(),
    };
    let json = serde_json::to_string(&rules).expect("serialize");
    let back: DynamicRules = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.rule_id, rules.rule_id);
    assert_eq!(back.version, rules.version);
    assert_eq!(back.ip_blacklist, rules.ip_blacklist);
}
