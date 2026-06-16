#![no_main]

use libfuzzer_sys::fuzz_target;

use guard_core_engine::semantic::AttackKeywords;
use guard_core_engine::semantic::AttackStructures;

fuzz_target!(|data: &str| {
    let kw = AttackKeywords::default();
    let st = AttackStructures::default();

    let _ = guard_core_engine::semantic::extract_tokens(data, &st);
    let _ = guard_core_engine::semantic::calculate_entropy(data);
    let _ = guard_core_engine::semantic::detect_encoding_layers(data);
    let _ = guard_core_engine::semantic::detect_obfuscation(data);
    let _ = guard_core_engine::semantic::analyze_attack_probability(data, &kw, &st);
    let _ = guard_core_engine::semantic::extract_suspicious_patterns(data, &st);
    let _ = guard_core_engine::semantic::analyze_code_injection_risk(data);

    let result = guard_core_engine::semantic::analyze(data, &kw, &st);
    let score = guard_core_engine::semantic::get_threat_score(&result);
    assert!((0.0..=1.0).contains(&score));
});
