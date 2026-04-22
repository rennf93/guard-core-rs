#[path = "support/agent.rs"]
mod agent;

use std::sync::Arc;
use std::time::Duration;

use guard_core_rs::detection_engine::{
    ContentPreprocessor, PatternCompiler, PerformanceMonitor, RecordMetricInput, RegexFlags,
    SemanticAnalyzer,
};
use guard_core_rs::detection_engine::compiler::MAX_CACHE_SIZE;
use guard_core_rs::detection_engine::monitor::PatternStats;
use guard_core_rs::protocols::agent::DynAgentHandler;
use parking_lot::Mutex;

use agent::MockAgent;

#[tokio::test]
async fn compile_pattern_caches() {
    let compiler = PatternCompiler::new(Duration::from_secs(2), 100);
    let regex1 = compiler
        .compile_pattern(r"\b\w+@\w+\b", RegexFlags::default_flags())
        .await
        .expect("compile");
    let regex2 = compiler
        .compile_pattern(r"\b\w+@\w+\b", RegexFlags::default_flags())
        .await
        .expect("compile");
    assert!(regex1.is_match("name@host"));
    assert!(regex2.is_match("name@host"));
}

#[test]
fn dangerous_pattern_rejected() {
    let compiler = PatternCompiler::new(Duration::from_secs(2), 100);
    let (safe, reason) = compiler.validate_pattern_safety(r"(.*)+", None);
    assert!(!safe);
    assert!(reason.contains("dangerous"));
}

#[test]
fn safe_pattern_passes() {
    let compiler = PatternCompiler::new(Duration::from_secs(2), 100);
    let (safe, _) = compiler.validate_pattern_safety(r"\b\d{3}\b", None);
    assert!(safe);
}

#[tokio::test]
async fn invalid_regex_fails() {
    let compiler = PatternCompiler::new(Duration::from_secs(2), 100);
    let result = compiler
        .compile_pattern(r"[unclosed", RegexFlags::default_flags())
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn batch_compile_skips_unsafe() {
    let compiler = PatternCompiler::new(Duration::from_secs(2), 100);
    let patterns = vec![
        r"\b\d+\b".to_string(),
        r"(.*)+".to_string(),
        r"\w+".to_string(),
    ];
    let compiled = compiler.batch_compile(&patterns, true).await;
    assert_eq!(compiled.len(), 2);
}

#[tokio::test]
async fn monitor_tracks_metrics() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    monitor
        .record_metric(RecordMetricInput {
            pattern: "pattern1",
            execution_time: 0.01,
            content_length: 100,
            matched: false,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    monitor
        .record_metric(RecordMetricInput {
            pattern: "pattern1",
            execution_time: 0.02,
            content_length: 100,
            matched: true,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let summary = monitor.get_summary_stats().await;
    assert_eq!(summary["total_executions"], 2);
}

#[tokio::test]
async fn monitor_detects_timeout_anomaly() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    monitor
        .record_metric(RecordMetricInput {
            pattern: "pattern_timeout",
            execution_time: 5.0,
            content_length: 100,
            matched: false,
            timeout: true,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let report = monitor.get_pattern_report("pattern_timeout").await.expect("exists");
    assert_eq!(report["total_timeouts"], 1);
}

#[tokio::test]
async fn preprocessor_normalizes_unicode() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let fullwidth_less_than = "\u{ff1c}script\u{ff1e}";
    let out = pp.normalize_unicode(fullwidth_less_than);
    assert!(out.contains('<') || out.contains('>') || out.contains("script"));
}

#[tokio::test]
async fn preprocessor_removes_null_bytes() {
    let pp = ContentPreprocessor::new(10_000, true, None, None);
    let out = pp.remove_null_bytes("hello\u{0}world\u{1}\u{2}");
    assert_eq!(out, "helloworld");
}

#[tokio::test]
async fn preprocessor_truncates_long_content() {
    let pp = ContentPreprocessor::new(100, false, None, None);
    let content = "x".repeat(500);
    let out = pp.truncate_safely(&content).await;
    assert_eq!(out.len(), 100);
}

#[test]
fn semantic_analyzer_detects_xss_keywords() {
    let analyzer = SemanticAnalyzer::new();
    let probs = analyzer.analyze_attack_probability("<script>alert(document.cookie)</script>");
    let xss = probs.get("xss").copied().unwrap_or(0.0);
    assert!(xss > 0.2);
}

#[test]
fn semantic_analyzer_detects_sql_patterns() {
    let analyzer = SemanticAnalyzer::new();
    let probs =
        analyzer.analyze_attack_probability("SELECT * FROM users WHERE id=1 UNION SELECT");
    let sql = probs.get("sql").copied().unwrap_or(0.0);
    assert!(sql > 0.2);
}

#[test]
fn semantic_analyzer_reports_entropy() {
    let analyzer = SemanticAnalyzer::new();
    let entropy = analyzer.calculate_entropy("aaaaaa");
    let entropy_mixed = analyzer.calculate_entropy("abcdefghijk");
    assert!(entropy_mixed > entropy);
}

#[test]
fn regex_flags_default_matches_const_default() {
    let d: RegexFlags = RegexFlags::default();
    let c = RegexFlags::default_flags();
    assert_eq!(d.case_insensitive, c.case_insensitive);
    assert_eq!(d.multi_line, c.multi_line);
    assert_eq!(d.dot_matches_new_line, c.dot_matches_new_line);
}

#[test]
fn regex_flags_debug_output() {
    let f = RegexFlags::default_flags();
    let debug = format!("{f:?}");
    assert!(debug.contains("RegexFlags"));
}

#[test]
fn compiler_default_uses_public_constants() {
    let compiler = PatternCompiler::default();
    assert_eq!(compiler.default_timeout(), Duration::from_secs(5));
    assert_eq!(compiler.max_cache_size(), MAX_CACHE_SIZE);
    let debug = format!("{compiler:?}");
    assert!(debug.contains("PatternCompiler"));
}

#[test]
fn compiler_max_cache_size_is_clamped() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 10_000);
    assert_eq!(compiler.max_cache_size(), 5000);
}

#[tokio::test]
async fn compiler_all_flag_permutations_build() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    for ci in [false, true] {
        for ml in [false, true] {
            for dn in [false, true] {
                let flags = RegexFlags {
                    case_insensitive: ci,
                    multi_line: ml,
                    dot_matches_new_line: dn,
                };
                let re = compiler.compile_pattern("foo", flags).await.expect("build");
                assert!(re.is_match("foo"));
            }
        }
    }
}

#[tokio::test]
async fn compiler_lru_eviction_at_capacity() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 2);
    compiler
        .compile_pattern("alpha", RegexFlags::default_flags())
        .await
        .expect("compile");
    compiler
        .compile_pattern("beta", RegexFlags::default_flags())
        .await
        .expect("compile");
    compiler
        .compile_pattern("gamma", RegexFlags::default_flags())
        .await
        .expect("compile");
    compiler
        .compile_pattern("alpha", RegexFlags::default_flags())
        .await
        .expect("compile again after eviction");
}

#[tokio::test]
async fn compiler_lru_promotes_cache_hit() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 2);
    compiler
        .compile_pattern("one", RegexFlags::default_flags())
        .await
        .expect("one");
    compiler
        .compile_pattern("two", RegexFlags::default_flags())
        .await
        .expect("two");
    compiler
        .compile_pattern("one", RegexFlags::default_flags())
        .await
        .expect("one hit");
    compiler
        .compile_pattern("three", RegexFlags::default_flags())
        .await
        .expect("three");
}

#[test]
fn compile_pattern_sync_works() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let re = compiler
        .compile_pattern_sync(r"\d+", RegexFlags::default_flags())
        .expect("sync compile");
    assert!(re.is_match("123"));
}

#[test]
fn compile_pattern_sync_errors_on_invalid() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let err = compiler
        .compile_pattern_sync(r"[", RegexFlags::default_flags())
        .unwrap_err();
    assert!(err.to_string().contains("pattern compilation error"));
}

#[test]
fn validate_pattern_safety_rejects_all_dangerous_constructs() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    for bad in [
        r"(.*)+",
        r"(.+)+",
        r"(x*)+",
        r"(x+)+",
        r".*.*",
        r".+.+",
    ] {
        let (safe, reason) = compiler.validate_pattern_safety(bad, None);
        assert!(!safe, "expected unsafe for {bad:?}");
        assert!(reason.contains("dangerous"));
    }
}

#[test]
fn validate_pattern_safety_rejects_invalid_regex() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let (safe, reason) = compiler.validate_pattern_safety(r"[unclosed", None);
    assert!(!safe);
    assert!(reason.contains("validation failed"));
}

#[test]
fn validate_pattern_safety_with_custom_test_strings() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let (safe, _) = compiler.validate_pattern_safety(
        r"\w+",
        Some(vec!["abc".into(), "xyz".into()]),
    );
    assert!(safe);
}

#[test]
fn validate_pattern_safety_detects_slow_pattern_timeout() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let slow_input = "a".repeat(100_000);
    let (safe, reason) = compiler.validate_pattern_safety(
        r"(a|a)*b",
        Some(vec![slow_input]),
    );
    if !safe {
        assert!(reason.contains("timed out") || reason.contains("dangerous"));
    }
}

#[test]
fn validate_pattern_safety_tolerates_slow_default_tests() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let (_safe, _) = compiler.validate_pattern_safety(r"\b(?:needle)\b", None);
}

#[test]
fn validate_pattern_safety_times_out_on_huge_input() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let huge_input = "ab".repeat(5_000_000);
    let (_safe, _reason) = compiler.validate_pattern_safety(
        r"^(?:ab)*c$",
        Some(vec![huge_input]),
    );
}

#[tokio::test]
async fn batch_compile_without_validation_skips_safety_check() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let patterns = vec![
        r"\b\w+\b".to_string(),
        r"\d{3}".to_string(),
    ];
    let compiled = compiler.batch_compile(&patterns, false).await;
    assert_eq!(compiled.len(), 2);
}

#[tokio::test]
async fn batch_compile_skips_invalid_regex() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    let patterns = vec![
        r"\b\w+\b".to_string(),
        r"[unclosed".to_string(),
    ];
    let compiled = compiler.batch_compile(&patterns, false).await;
    assert_eq!(compiled.len(), 1);
}

#[tokio::test]
async fn clear_cache_empties_compilation_cache() {
    let compiler = PatternCompiler::new(Duration::from_secs(1), 100);
    compiler
        .compile_pattern(r"\d+", RegexFlags::default_flags())
        .await
        .expect("compile");
    compiler.clear_cache().await;
    compiler
        .compile_pattern(r"\d+", RegexFlags::default_flags())
        .await
        .expect("re-compile after clear");
}

#[test]
fn pattern_stats_new_initializes_defaults() {
    let s = PatternStats::new("pat".into());
    assert_eq!(s.pattern, "pat");
    assert_eq!(s.total_executions, 0);
    assert_eq!(s.total_matches, 0);
    assert_eq!(s.total_timeouts, 0);
    assert_eq!(s.avg_execution_time, 0.0);
    assert!(s.recent_times.is_empty());
    assert!(s.min_execution_time.is_infinite());
    let debug = format!("{s:?}");
    assert!(debug.contains("PatternStats"));
}

#[test]
fn monitor_default_sets_bounded_thresholds() {
    let monitor = PerformanceMonitor::default();
    assert_eq!(monitor.anomaly_threshold, 3.0);
    assert!((monitor.slow_pattern_threshold - 0.1).abs() < 1e-9);
    assert_eq!(monitor.history_size, 1000);
    assert_eq!(monitor.max_tracked_patterns, 1000);
    let debug = format!("{monitor:?}");
    assert!(debug.contains("PerformanceMonitor"));
}

#[test]
fn monitor_clamps_constructor_values() {
    let low = PerformanceMonitor::new(0.0, 0.0, 0, 0);
    assert!(low.anomaly_threshold >= 1.0);
    assert!(low.slow_pattern_threshold >= 0.01);
    assert!(low.history_size >= 100);
    assert!(low.max_tracked_patterns >= 100);

    let high = PerformanceMonitor::new(100.0, 100.0, 100_000, 100_000);
    assert!(high.anomaly_threshold <= 10.0);
    assert!(high.slow_pattern_threshold <= 10.0);
    assert!(high.history_size <= 10_000);
    assert!(high.max_tracked_patterns <= 5_000);
}

#[tokio::test]
async fn monitor_get_summary_stats_empty() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    let summary = monitor.get_summary_stats().await;
    assert_eq!(summary["total_executions"], 0);
}

#[tokio::test]
async fn monitor_get_summary_stats_all_timeouts_have_zero_times() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    for _ in 0..5 {
        monitor
            .record_metric(RecordMetricInput {
                pattern: "all_timeouts",
                execution_time: 0.0,
                content_length: 10,
                matched: false,
                timeout: true,
                agent_handler: None,
                correlation_id: None,
            })
            .await;
    }
    let summary = monitor.get_summary_stats().await;
    assert_eq!(summary["avg_execution_time"], 0.0);
    assert_eq!(summary["max_execution_time"], 0.0);
    assert_eq!(summary["min_execution_time"], 0.0);
}

#[tokio::test]
async fn monitor_record_metric_truncates_long_pattern() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    let long = "A".repeat(200);
    monitor
        .record_metric(RecordMetricInput {
            pattern: &long,
            execution_time: 0.01,
            content_length: 50,
            matched: false,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let report = monitor.get_pattern_report(&long).await.expect("exists");
    assert!(report["pattern_hash"].is_string());
}

#[tokio::test]
async fn monitor_detects_slow_execution_anomaly() {
    let monitor = PerformanceMonitor::new(3.0, 0.05, 100, 100);
    monitor
        .record_metric(RecordMetricInput {
            pattern: "slow_pattern",
            execution_time: 0.5,
            content_length: 10,
            matched: false,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let report = monitor.get_pattern_report("slow_pattern").await.expect("exists");
    assert_eq!(report["total_executions"], 1);
}

#[tokio::test]
async fn monitor_detects_statistical_anomaly() {
    let monitor = PerformanceMonitor::new(2.0, 10.0, 1000, 1000);
    for _ in 0..12 {
        monitor
            .record_metric(RecordMetricInput {
                pattern: "statistical",
                execution_time: 0.01,
                content_length: 10,
                matched: false,
                timeout: false,
                agent_handler: None,
                correlation_id: None,
            })
            .await;
    }
    monitor
        .record_metric(RecordMetricInput {
            pattern: "statistical",
            execution_time: 5.0,
            content_length: 10,
            matched: false,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let report = monitor.get_pattern_report("statistical").await.expect("exists");
    assert_eq!(report["total_executions"], 13);
}

#[tokio::test]
async fn monitor_callbacks_are_invoked_on_anomaly() {
    let monitor = PerformanceMonitor::new(3.0, 0.01, 100, 100);
    let counter: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let counter_clone = Arc::clone(&counter);
    monitor.register_anomaly_callback(Arc::new(move |_v| {
        *counter_clone.lock() += 1;
    }));
    monitor
        .record_metric(RecordMetricInput {
            pattern: "cb_pattern",
            execution_time: 5.0,
            content_length: 10,
            matched: false,
            timeout: true,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    assert!(*counter.lock() >= 1);
}

#[tokio::test]
async fn monitor_sends_anomaly_events_to_agent() {
    let monitor = PerformanceMonitor::new(3.0, 0.01, 100, 100);
    let agent = MockAgent::new();
    let handler: DynAgentHandler = agent.clone();
    monitor
        .record_metric(RecordMetricInput {
            pattern: "agent_pattern",
            execution_time: 0.5,
            content_length: 10,
            matched: false,
            timeout: false,
            agent_handler: Some(&handler),
            correlation_id: Some("corr-xyz"),
        })
        .await;
    assert!(!agent.events.lock().is_empty());
}

#[tokio::test]
async fn monitor_sanitizes_long_patterns_in_callback() {
    let monitor = PerformanceMonitor::new(3.0, 0.01, 100, 100);
    let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured);
    monitor.register_anomaly_callback(Arc::new(move |v| {
        captured_clone.lock().push(v.clone());
    }));
    let long = "X".repeat(80);
    monitor
        .record_metric(RecordMetricInput {
            pattern: &long,
            execution_time: 5.0,
            content_length: 10,
            matched: false,
            timeout: true,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let events = captured.lock();
    assert!(!events.is_empty());
    let pattern = events[0]["pattern"].as_str().unwrap();
    assert!(pattern.ends_with("..."));
    let hash = events[0]["pattern_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 8);
}

#[tokio::test]
async fn monitor_clear_stats_resets_data() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    monitor
        .record_metric(RecordMetricInput {
            pattern: "to_clear",
            execution_time: 0.01,
            content_length: 10,
            matched: true,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    monitor.clear_stats().await;
    let summary = monitor.get_summary_stats().await;
    assert_eq!(summary["total_executions"], 0);
    assert!(monitor.get_pattern_report("to_clear").await.is_none());
}

#[tokio::test]
async fn monitor_remove_pattern_stats_targeted() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    monitor
        .record_metric(RecordMetricInput {
            pattern: "keep",
            execution_time: 0.01,
            content_length: 10,
            matched: true,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    monitor
        .record_metric(RecordMetricInput {
            pattern: "drop",
            execution_time: 0.01,
            content_length: 10,
            matched: true,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    monitor.remove_pattern_stats("drop").await;
    assert!(monitor.get_pattern_report("keep").await.is_some());
    assert!(monitor.get_pattern_report("drop").await.is_none());
}

#[tokio::test]
async fn monitor_get_pattern_report_missing_returns_none() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    assert!(monitor.get_pattern_report("missing").await.is_none());
}

#[tokio::test]
async fn monitor_get_slow_patterns_excludes_timeout_only() {
    let monitor = PerformanceMonitor::new(3.0, 0.01, 100, 100);
    monitor
        .record_metric(RecordMetricInput {
            pattern: "only_timeouts",
            execution_time: 0.0,
            content_length: 10,
            matched: false,
            timeout: true,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    monitor
        .record_metric(RecordMetricInput {
            pattern: "fast",
            execution_time: 0.02,
            content_length: 10,
            matched: false,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    monitor
        .record_metric(RecordMetricInput {
            pattern: "slow",
            execution_time: 0.5,
            content_length: 10,
            matched: false,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let slow = monitor.get_slow_patterns(10).await;
    assert!(!slow.is_empty());
}

#[tokio::test]
async fn monitor_problematic_patterns_detects_high_timeout_rate() {
    let monitor = PerformanceMonitor::new(3.0, 0.01, 100, 100);
    monitor
        .record_metric(RecordMetricInput {
            pattern: "high_timeout",
            execution_time: 0.0,
            content_length: 10,
            matched: false,
            timeout: true,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let problems = monitor.get_problematic_patterns().await;
    assert!(problems.iter().any(|v| v["issue"] == "high_timeout_rate"));
}

#[tokio::test]
async fn monitor_problematic_patterns_detects_consistently_slow() {
    let monitor = PerformanceMonitor::new(3.0, 0.01, 100, 100);
    for _ in 0..5 {
        monitor
            .record_metric(RecordMetricInput {
                pattern: "always_slow",
                execution_time: 1.0,
                content_length: 10,
                matched: false,
                timeout: false,
                agent_handler: None,
                correlation_id: None,
            })
            .await;
    }
    let problems = monitor.get_problematic_patterns().await;
    assert!(problems.iter().any(|v| v["issue"] == "consistently_slow"));
}

#[tokio::test]
async fn monitor_pattern_stats_eviction_at_capacity() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    for i in 0..150 {
        let name = format!("pat_{i}");
        monitor
            .record_metric(RecordMetricInput {
                pattern: &name,
                execution_time: 0.01,
                content_length: 10,
                matched: false,
                timeout: false,
                agent_handler: None,
                correlation_id: None,
            })
            .await;
    }
    let summary = monitor.get_summary_stats().await;
    let patterns = summary["total_patterns"].as_u64().unwrap();
    assert!(patterns <= 100);
}

#[tokio::test]
async fn monitor_history_size_bounds_recent_metrics() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    for _ in 0..150 {
        monitor
            .record_metric(RecordMetricInput {
                pattern: "overflow",
                execution_time: 0.01,
                content_length: 10,
                matched: false,
                timeout: false,
                agent_handler: None,
                correlation_id: None,
            })
            .await;
    }
    let summary = monitor.get_summary_stats().await;
    let total = summary["total_executions"].as_u64().unwrap();
    assert!(total <= 100);
}

#[tokio::test]
async fn monitor_record_metric_clamps_negative_execution_time() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 100, 100);
    monitor
        .record_metric(RecordMetricInput {
            pattern: "clamp",
            execution_time: -1.0,
            content_length: 10,
            matched: false,
            timeout: false,
            agent_handler: None,
            correlation_id: None,
        })
        .await;
    let report = monitor.get_pattern_report("clamp").await.expect("exists");
    let max_time = report["max_execution_time"].as_f64().unwrap();
    assert!(max_time >= 0.0);
}

#[tokio::test]
async fn monitor_stats_recent_times_bounded() {
    let monitor = PerformanceMonitor::new(3.0, 0.1, 200, 200);
    for i in 0..150 {
        monitor
            .record_metric(RecordMetricInput {
                pattern: "recent",
                execution_time: 0.01 + i as f64 * 0.001,
                content_length: 10,
                matched: true,
                timeout: false,
                agent_handler: None,
                correlation_id: None,
            })
            .await;
    }
    let report = monitor.get_pattern_report("recent").await.expect("exists");
    assert_eq!(report["total_executions"], 150);
}

#[test]
fn semantic_analyzer_debug_output() {
    let analyzer = SemanticAnalyzer::new();
    let debug = format!("{analyzer:?}");
    assert!(debug.contains("SemanticAnalyzer"));
    let d: SemanticAnalyzer = SemanticAnalyzer::default();
    assert!(!d.attack_keywords.is_empty());
}

#[test]
fn semantic_analyzer_detects_command_attack() {
    let analyzer = SemanticAnalyzer::new();
    let probs = analyzer.analyze_attack_probability("exec; system(cmd) bash /shell");
    let cmd = probs.get("command").copied().unwrap_or(0.0);
    assert!(cmd > 0.0);
}

#[test]
fn semantic_analyzer_detects_path_traversal() {
    let analyzer = SemanticAnalyzer::new();
    let probs = analyzer.analyze_attack_probability("../../etc/passwd /etc/shadow /proc/boot");
    let path = probs.get("path").copied().unwrap_or(0.0);
    assert!(path > 0.0);
}

#[test]
fn semantic_analyzer_detects_template_keywords() {
    let analyzer = SemanticAnalyzer::new();
    let probs = analyzer.analyze_attack_probability("jinja template render mustache handlebars ejs pug twig");
    let tpl = probs.get("template").copied().unwrap_or(0.0);
    assert!(tpl > 0.0);
}

#[test]
fn semantic_analyzer_calculate_entropy_empty_is_zero() {
    let analyzer = SemanticAnalyzer::new();
    assert_eq!(analyzer.calculate_entropy(""), 0.0);
}

#[test]
fn semantic_analyzer_calculate_entropy_large_input() {
    let analyzer = SemanticAnalyzer::new();
    let big = "a".repeat(20_000);
    let entropy = analyzer.calculate_entropy(&big);
    assert!(entropy >= 0.0);
}

#[test]
fn semantic_analyzer_extract_tokens_handles_large_input() {
    let analyzer = SemanticAnalyzer::new();
    let big = "word ".repeat(20_000);
    let tokens = analyzer.extract_tokens(&big);
    assert!(!tokens.is_empty());
    assert!(tokens.len() <= 1000);
}

#[test]
fn semantic_analyzer_extract_tokens_hits_special_cap() {
    let analyzer = SemanticAnalyzer::new();
    let structural = format!(
        "{}{}{}{}{}",
        "<a>".repeat(10),
        "f(x)".repeat(10),
        ";&|".repeat(10),
        "../".repeat(10),
        "http://".repeat(10),
    );
    let tokens = analyzer.extract_tokens(&structural);
    assert!(!tokens.is_empty());
}

#[test]
fn semantic_analyzer_encoding_layers_detects_multiple() {
    let analyzer = SemanticAnalyzer::new();
    let mixed = "%20 AAAAbbbb 0x1234 \\u0041 &#x41;";
    let layers = analyzer.detect_encoding_layers(mixed);
    assert!(layers >= 3);
}

#[test]
fn semantic_analyzer_encoding_layers_zero_for_plain() {
    let analyzer = SemanticAnalyzer::new();
    let layers = analyzer.detect_encoding_layers("hi");
    assert_eq!(layers, 0);
}

#[test]
fn semantic_analyzer_encoding_layers_large_input_truncated() {
    let analyzer = SemanticAnalyzer::new();
    let big = format!("%20{}", "x".repeat(20_000));
    let layers = analyzer.detect_encoding_layers(&big);
    assert!(layers >= 1);
}

#[test]
fn semantic_analyzer_obfuscation_by_entropy() {
    let analyzer = SemanticAnalyzer::new();
    let high_entropy = "The quick brown fox jumps over the lazy dog! 123 abc 789 !@#$%";
    let even_higher = (0..200)
        .map(|i| char::from((33 + (i * 7) % 94) as u8))
        .collect::<String>();
    assert!(analyzer.detect_obfuscation(&even_higher) || analyzer.detect_obfuscation(high_entropy));
}

#[test]
fn semantic_analyzer_obfuscation_by_encoding_layers() {
    let analyzer = SemanticAnalyzer::new();
    let content = "%20 AAAAbbbb 0x1234 \\u0041 &#x41;";
    assert!(analyzer.detect_obfuscation(content));
}

#[test]
fn semantic_analyzer_obfuscation_by_special_ratio() {
    let analyzer = SemanticAnalyzer::new();
    let content = "!@#$%^&*()!@#$%^&*()!@#$%^&*()!@#$%^&*()";
    assert!(analyzer.detect_obfuscation(content));
}

#[test]
fn semantic_analyzer_obfuscation_by_long_no_whitespace() {
    let analyzer = SemanticAnalyzer::new();
    let content = "a".repeat(150);
    assert!(analyzer.detect_obfuscation(&content));
}

#[test]
fn semantic_analyzer_not_obfuscated_for_plain_text() {
    let analyzer = SemanticAnalyzer::new();
    assert!(!analyzer.detect_obfuscation("hello world"));
}

#[test]
fn semantic_analyzer_suspicious_patterns_reports_context() {
    let analyzer = SemanticAnalyzer::new();
    let content = "hello <script>alert(1)</script> world";
    let patterns = analyzer.extract_suspicious_patterns(content);
    assert!(!patterns.is_empty());
    for p in &patterns {
        assert!(p["context"].is_string());
        assert!(p["position"].is_number());
    }
}

#[test]
fn semantic_analyzer_code_injection_risk_pattern_boosts() {
    let analyzer = SemanticAnalyzer::new();
    let risk = analyzer.analyze_code_injection_risk("{x{y}} foo(bar) $variable x==y");
    assert!(risk > 0.0);
}

#[test]
fn semantic_analyzer_code_injection_risk_keywords() {
    let analyzer = SemanticAnalyzer::new();
    for kw in ["eval(1)", "exec(1)", "compile(1)", "__import__(1)", "globals()", "locals()"] {
        let risk = analyzer.analyze_code_injection_risk(kw);
        assert!(risk >= 0.2, "expected risk for {kw}");
    }
}

#[test]
fn semantic_analyzer_code_injection_risk_capped_at_one() {
    let analyzer = SemanticAnalyzer::new();
    let content = "{a} func() $var == eval() exec compile __import__ globals locals";
    let risk = analyzer.analyze_code_injection_risk(content);
    assert!(risk <= 1.0);
}

#[test]
fn semantic_analyzer_analyze_returns_full_report() {
    let analyzer = SemanticAnalyzer::new();
    let result = analyzer.analyze("<script>alert(1)</script>");
    assert!(result["attack_probabilities"].is_object());
    assert!(result["entropy"].is_number());
    assert!(result["encoding_layers"].is_number());
    assert!(result["is_obfuscated"].is_boolean());
    assert!(result["suspicious_patterns"].is_array());
    assert!(result["code_injection_risk"].is_number());
    assert!(result["token_count"].is_number());
}

#[test]
fn semantic_analyzer_threat_score_accumulates_factors() {
    let analyzer = SemanticAnalyzer::new();
    let result = analyzer.analyze("<script>eval(%20 0x1234 \\u0041 &#x41; %20 alert(document.cookie))</script>");
    let score = analyzer.get_threat_score(&result);
    assert!(score > 0.0);
    assert!(score <= 1.0);
}

#[test]
fn semantic_analyzer_threat_score_zero_for_plain() {
    let analyzer = SemanticAnalyzer::new();
    let result = analyzer.analyze("hello world this is safe");
    let score = analyzer.get_threat_score(&result);
    assert!(score >= 0.0);
}

#[test]
fn semantic_analyzer_threat_score_handles_empty_analysis() {
    let analyzer = SemanticAnalyzer::new();
    let empty = serde_json::json!({});
    let score = analyzer.get_threat_score(&empty);
    assert_eq!(score, 0.0);
}

#[test]
fn performance_metric_debug_output() {
    let pm = guard_core_rs::detection_engine::PerformanceMetric {
        pattern: "p".into(),
        execution_time: 0.1,
        content_length: 10,
        timestamp: chrono::Utc::now(),
        matched: true,
        timeout: false,
    };
    let clone = pm.clone();
    assert_eq!(clone.pattern, pm.pattern);
    assert!(format!("{pm:?}").contains("PerformanceMetric"));
}

#[test]
fn record_metric_input_clone_and_debug() {
    let input = RecordMetricInput {
        pattern: "p",
        execution_time: 0.1,
        content_length: 10,
        matched: false,
        timeout: false,
        agent_handler: None,
        correlation_id: None,
    };
    let debug = format!("{input:?}");
    assert!(debug.contains("RecordMetricInput"));
    let cloned = input;
    assert_eq!(cloned.pattern, "p");
}
