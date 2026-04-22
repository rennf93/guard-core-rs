# Detection Engine

The detection engine lives under [`guard_core_rs::detection_engine`](https://docs.rs/guard-core-rs/latest/guard_core_rs/detection_engine/index.html) and underpins `SuspiciousActivityCheck`. It has four cooperating pieces: a regex pattern compiler, a content preprocessor, a semantic analyzer, and a performance monitor.

## PatternCompiler

[`PatternCompiler`](https://docs.rs/guard-core-rs/latest/guard_core_rs/detection_engine/struct.PatternCompiler.html) compiles regex strings into [`regex::Regex`](https://docs.rs/regex/latest/regex/struct.Regex.html) values and caches them in an LRU with a configurable cap (default 1000, hard ceiling 5000). `compile_pattern(&self, pattern, flags)` is async because the cache uses a `tokio::sync::Mutex`; there is also a synchronous `compile_pattern_sync` for cold paths.

```rust,ignore
use std::time::Duration;
use guard_core_rs::detection_engine::{PatternCompiler, RegexFlags};

let compiler = PatternCompiler::new(Duration::from_secs(5), 500);
let re = compiler
    .compile_pattern(r"(?i)password\s*=\s*\w+", RegexFlags::default_flags())
    .await?;
assert!(re.is_match("Password=hunter2"));
```

`validate_pattern_safety` rejects constructs that trigger catastrophic backtracking (`(.*)+`, repeated `.*` quantifiers) and runs each candidate against a handful of fuzz-friendly inputs with a 50 ms wall-clock budget.

## ContentPreprocessor

[`ContentPreprocessor`](https://docs.rs/guard-core-rs/latest/guard_core_rs/detection_engine/struct.ContentPreprocessor.html) prepares input for the regex and semantic stages:

1. Unicode NFKC normalisation plus a lookalike replacement table (full-width slashes, zero-width joiners, etc.).
2. URL decoding and HTML entity decoding, up to three iterations.
3. Null-byte and control-character stripping.
4. Excess-whitespace collapsing.
5. Safe truncation that preserves regions around attack indicators when `preserve_attack_patterns` is on.

```rust,ignore
use guard_core_rs::detection_engine::ContentPreprocessor;

let pp = ContentPreprocessor::new(10_000, true, None, None);
let processed = pp.preprocess("%3Cscript%3Ealert(1)%3C/script%3E").await;
assert!(processed.contains("<script>"));
```

`preserve_attack_patterns = true` keeps windows of text surrounding any of 21 built-in indicators (`<script`, `javascript:`, `onerror=`, `SELECT .. FROM`, `../`, `${`, `%hh`, etc.) even when the payload is longer than `max_content_length`.

## SemanticAnalyzer

[`SemanticAnalyzer`](https://docs.rs/guard-core-rs/latest/guard_core_rs/detection_engine/struct.SemanticAnalyzer.html) returns a [`serde_json::Value`](https://docs.rs/serde_json/latest/serde_json/enum.Value.html) summarising:

- `attack_probabilities` across `xss`, `sql`, `command`, `path`, and `template` keyword buckets.
- `entropy` (Shannon, capped at 10 000 characters).
- `encoding_layers` (URL, base64, hex, unicode escapes, HTML entities).
- `is_obfuscated` (true if entropy > 4.5, more than 2 encoding layers, or high special-character density).
- `suspicious_patterns` matching structural regexes (tag-like, function call, command chain, path traversal, URL-style prefix).
- `code_injection_risk` (`eval`, `exec`, `__import__`, etc., plus code-shape heuristics).
- `token_count`.

`get_threat_score(&analysis)` blends those fields into a single 0.0-1.0 score that `SuspiciousActivityCheck` compares against `detection_semantic_threshold`.

## PerformanceMonitor

[`PerformanceMonitor`](https://docs.rs/guard-core-rs/latest/guard_core_rs/detection_engine/struct.PerformanceMonitor.html) records `PerformanceMetric { pattern, execution_time, content_length, matched, timeout, timestamp }` entries via `record_metric(RecordMetricInput)`. It rolls up per-pattern `PatternStats` (executions, matches, timeouts, min/max/average execution time, recent 100 samples) and can flush anomalies to the agent when a pattern breaches `detection_slow_pattern_threshold` or `detection_anomaly_threshold`.

## SusPatternsManager

[`SusPatternsManager`](https://docs.rs/guard-core-rs/latest/guard_core_rs/handlers/suspatterns/struct.SusPatternsManager.html) is the orchestrator. It owns the four detection engine pieces plus a library of 70+ built-in regex patterns across XSS, SQLi, path traversal, command injection, LDAP, XXE, SSRF, NoSQL, file upload, template injection, CRLF, sensitive-file probes, and reconnaissance.

```rust,ignore
use guard_core_rs::handlers::suspatterns::{CTX_REQUEST_BODY, SusPatternsManager};
use guard_core_rs::models::SecurityConfig;

let config = SecurityConfig::builder().build()?;
let patterns = SusPatternsManager::arc(Some(&config));
let result = patterns
    .detect("<script>alert(1)</script>", "10.0.0.1", CTX_REQUEST_BODY, None)
    .await;
assert!(result.is_threat);
```

Add or remove custom patterns with `add_pattern` / `remove_pattern`; persist across restarts by initialising a Redis handler. The manager publishes threat events through the agent handler when one is configured.

Benchmarks for each component are in `benches/detection_engine.rs` and `benches/suspatterns.rs`. Run them with `cargo bench`.
