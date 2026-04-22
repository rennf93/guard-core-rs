use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use guard_core_rs::handlers::suspatterns::{CTX_REQUEST_BODY, SusPatternsManager};
use guard_core_rs::models::SecurityConfig;

fn config() -> SecurityConfig {
    SecurityConfig::builder().build().expect("config")
}

fn short_benign() -> String {
    "Hello, this is a normal JSON body.".into()
}

fn short_xss() -> String {
    "<script>alert('boom')</script>".into()
}

fn short_sqli() -> String {
    "1 UNION SELECT username, password FROM users --".into()
}

fn short_traversal() -> String {
    "../../etc/passwd".into()
}

fn short_cmd() -> String {
    "id=1; cat /etc/shadow".into()
}

fn medium_mixed() -> String {
    let mut s = "ordinary payload ".repeat(50);
    s.push_str("<iframe src=javascript:alert(1)></iframe>");
    s.push_str(&" padding ".repeat(50));
    s.push_str("SELECT * FROM accounts WHERE 1=1 OR 'a'='a'");
    s
}

fn long_benign() -> String {
    "the quick brown fox jumps over the lazy dog. ".repeat(300)
}

fn long_obfuscated() -> String {
    let mut s = String::new();
    s.push_str(&"safe ".repeat(200));
    s.push_str("%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E");
    s.push_str(&" more safe text ".repeat(200));
    s.push_str("onerror=alert(1)");
    s.push_str(&" and more ".repeat(200));
    s
}

fn bench_detect(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let manager: Arc<SusPatternsManager> = SusPatternsManager::arc(Some(&config()));

    let benign = short_benign();
    let xss = short_xss();
    let sqli = short_sqli();
    let traversal = short_traversal();
    let cmd = short_cmd();
    let medium = medium_mixed();
    let long_ok = long_benign();
    let long_obfusc = long_obfuscated();

    let samples: Vec<(&str, &str)> = vec![
        ("short_benign", benign.as_str()),
        ("short_xss", xss.as_str()),
        ("short_sqli", sqli.as_str()),
        ("short_traversal", traversal.as_str()),
        ("short_cmd_injection", cmd.as_str()),
        ("medium_mixed", medium.as_str()),
        ("long_benign", long_ok.as_str()),
        ("long_obfuscated", long_obfusc.as_str()),
    ];

    let mut group = c.benchmark_group("sus_patterns_detect");
    for (label, content) in &samples {
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), content, |b, input| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = manager
                        .detect(black_box(input), "10.0.0.1", CTX_REQUEST_BODY, None)
                        .await;
                });
            });
        });
    }
    group.finish();

    let mut pattern_match_group = c.benchmark_group("sus_patterns_detect_pattern_match");
    for (label, content) in &samples {
        pattern_match_group.throughput(Throughput::Bytes(content.len() as u64));
        pattern_match_group.bench_with_input(
            BenchmarkId::from_parameter(label),
            content,
            |b, input| {
                b.iter(|| {
                    rt.block_on(async {
                        let _ = manager
                            .detect_pattern_match(
                                black_box(input),
                                "10.0.0.1",
                                CTX_REQUEST_BODY,
                                None,
                            )
                            .await;
                    });
                });
            },
        );
    }
    pattern_match_group.finish();
}

criterion_group!(suspatterns_benches, bench_detect);
criterion_main!(suspatterns_benches);
