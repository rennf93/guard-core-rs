use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use guard_core_rs::detection_engine::{
    ContentPreprocessor, PatternCompiler, RegexFlags, SemanticAnalyzer,
};

fn short_benign() -> &'static str {
    "Hello, this is a perfectly safe request payload."
}

fn short_xss() -> &'static str {
    "<script>alert('xss')</script>"
}

fn short_sql() -> &'static str {
    "1' UNION SELECT password FROM users --"
}

fn medium_benign() -> String {
    "lorem ipsum dolor sit amet ".repeat(40)
}

fn medium_xss() -> String {
    let mut s = "safe prefix ".repeat(30);
    s.push_str("<img src=x onerror=alert(document.cookie)>");
    s.push_str(&" harmless suffix ".repeat(30));
    s
}

fn medium_sql() -> String {
    let mut s = "data=".to_string();
    s.push_str(&"value&".repeat(30));
    s.push_str("id=1 OR 1=1; DROP TABLE users;");
    s.push_str(&"&other=field".repeat(10));
    s
}

fn long_benign() -> String {
    "the quick brown fox jumps over the lazy dog. ".repeat(200)
}

fn long_mixed() -> String {
    let mut s = "benign text ".repeat(200);
    s.push_str("<iframe src=javascript:alert(1)>");
    s.push_str(&" more text ".repeat(100));
    s.push_str("%3Cscript%3Ealert('encoded')%3C/script%3E");
    s.push_str(&" trailing ".repeat(200));
    s
}

fn bench_pattern_compiler(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let compiler = PatternCompiler::new(Duration::from_secs(5), 1000);

    let simple = r"^hello$";
    let moderate = r"(?:<script[^>]*>|javascript:|on\w+=)";
    let complex = r#"(?i)(?:<[^>]+\s+(?:href|src|data|action)\s*=[\s"']*(?:javascript|vbscript|data):)"#;

    let mut group = c.benchmark_group("pattern_compiler");
    group.bench_function("compile_simple_cold", |b| {
        b.iter(|| {
            let c = PatternCompiler::default();
            rt.block_on(async {
                let _ = c
                    .compile_pattern(black_box(simple), RegexFlags::default_flags())
                    .await;
            });
        });
    });
    group.bench_function("compile_moderate_cold", |b| {
        b.iter(|| {
            let c = PatternCompiler::default();
            rt.block_on(async {
                let _ = c
                    .compile_pattern(black_box(moderate), RegexFlags::default_flags())
                    .await;
            });
        });
    });
    group.bench_function("compile_complex_cold", |b| {
        b.iter(|| {
            let c = PatternCompiler::default();
            rt.block_on(async {
                let _ = c
                    .compile_pattern(black_box(complex), RegexFlags::default_flags())
                    .await;
            });
        });
    });
    group.bench_function("compile_cached_hot", |b| {
        rt.block_on(async {
            let _ = compiler
                .compile_pattern(complex, RegexFlags::default_flags())
                .await;
        });
        b.iter(|| {
            rt.block_on(async {
                let _ = compiler
                    .compile_pattern(black_box(complex), RegexFlags::default_flags())
                    .await;
            });
        });
    });
    group.finish();
}

fn bench_semantic_analyzer(c: &mut Criterion) {
    let analyzer = SemanticAnalyzer::new();
    let medium_xss_s = medium_xss();
    let medium_sql_s = medium_sql();
    let medium_benign_s = medium_benign();
    let long_mixed_s = long_mixed();
    let long_benign_s = long_benign();

    let samples: Vec<(&str, &str)> = vec![
        ("short_benign", short_benign()),
        ("short_xss", short_xss()),
        ("short_sql", short_sql()),
        ("medium_benign", medium_benign_s.as_str()),
        ("medium_xss", medium_xss_s.as_str()),
        ("medium_sql", medium_sql_s.as_str()),
        ("long_benign", long_benign_s.as_str()),
        ("long_mixed", long_mixed_s.as_str()),
    ];

    let mut group = c.benchmark_group("semantic_analyzer_analyze");
    for (label, content) in &samples {
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), content, |b, input| {
            b.iter(|| {
                let _ = analyzer.analyze(black_box(input));
            });
        });
    }
    group.finish();

    let mut tokens_group = c.benchmark_group("semantic_analyzer_extract_tokens");
    for (label, content) in &samples {
        tokens_group.throughput(Throughput::Bytes(content.len() as u64));
        tokens_group.bench_with_input(
            BenchmarkId::from_parameter(label),
            content,
            |b, input| {
                b.iter(|| {
                    let _ = analyzer.extract_tokens(black_box(input));
                });
            },
        );
    }
    tokens_group.finish();
}

fn bench_content_preprocessor(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let pp = ContentPreprocessor::new(10_000, true, None, None);

    let medium_xss_s = medium_xss();
    let medium_sql_s = medium_sql();
    let medium_benign_s = medium_benign();
    let long_mixed_s = long_mixed();
    let long_benign_s = long_benign();

    let samples: Vec<(&str, &str)> = vec![
        ("short_benign", short_benign()),
        ("short_xss", short_xss()),
        ("short_sql", short_sql()),
        ("medium_benign", medium_benign_s.as_str()),
        ("medium_xss", medium_xss_s.as_str()),
        ("medium_sql", medium_sql_s.as_str()),
        ("long_benign", long_benign_s.as_str()),
        ("long_mixed", long_mixed_s.as_str()),
    ];

    let mut group = c.benchmark_group("preprocessor_preprocess");
    for (label, content) in &samples {
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), content, |b, input| {
            b.iter(|| {
                rt.block_on(async {
                    let _ = pp.preprocess(black_box(input)).await;
                });
            });
        });
    }
    group.finish();

    let mut normalize_group = c.benchmark_group("preprocessor_normalize_unicode");
    for (label, content) in &samples {
        normalize_group.throughput(Throughput::Bytes(content.len() as u64));
        normalize_group.bench_with_input(
            BenchmarkId::from_parameter(label),
            content,
            |b, input| {
                b.iter(|| {
                    let _ = pp.normalize_unicode(black_box(input));
                });
            },
        );
    }
    normalize_group.finish();
}

criterion_group!(
    detection_engine,
    bench_pattern_compiler,
    bench_semantic_analyzer,
    bench_content_preprocessor
);
criterion_main!(detection_engine);
