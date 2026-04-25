use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use guard_core_engine::compiler::PatternCache;
use guard_core_engine::compiler::batch_compile;
use guard_core_engine::compiler::compile;
use guard_core_engine::compiler::validate_pattern_safety;

fn bench_compile_single(c: &mut Criterion) {
    let patterns = [
        (r"<script[^>]*>", "xss_tag"),
        (r"(?i)SELECT\s+.{0,50}?\s+FROM", "sqli_select"),
        (r"\.\./", "path_traversal"),
        (r"(?i)eval\s*\(", "eval_call"),
        (r"%[0-9a-fA-F]{2}", "url_encoded"),
    ];

    let mut group = c.benchmark_group("compile_single");

    for (pat, name) in &patterns {
        group.bench_with_input(BenchmarkId::new("compile", name), pat, |b, pat| {
            b.iter(|| compile(pat));
        });
    }

    group.finish();
}

fn bench_cache_hit(c: &mut Criterion) {
    let mut cache = PatternCache::new(100);
    // warm up
    let _ = cache.get_or_compile(r"<script[^>]*>");

    c.bench_function("cache_hit", |b| {
        b.iter(|| {
            let _ = cache.get_or_compile(r"<script[^>]*>");
        });
    });
}

fn bench_cache_miss_then_hit(c: &mut Criterion) {
    c.bench_function("cache_miss_then_hit", |b| {
        b.iter_batched(
            || PatternCache::new(100),
            |mut cache| {
                let _ = cache.get_or_compile(r"<script[^>]*>");
                let _ = cache.get_or_compile(r"<script[^>]*>");
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_validate_safety(c: &mut Criterion) {
    let patterns = [
        (r"(.*)+", "dangerous_backtrack"),
        (r"<script[^>]*>", "safe_xss"),
        (r"\d{3}-\d{3}-\d{4}", "safe_phone"),
    ];

    let mut group = c.benchmark_group("validate_safety");

    for (pat, name) in &patterns {
        group.bench_with_input(BenchmarkId::new("validate", name), pat, |b, pat| {
            b.iter(|| validate_pattern_safety(pat));
        });
    }

    group.finish();
}

fn bench_batch_compile(c: &mut Criterion) {
    let patterns: Vec<&str> = vec![
        r"<script[^>]*>",
        r"(?i)SELECT\s+.{0,50}?\s+FROM",
        r"(?i)UNION\s+SELECT",
        r"\.\./",
        r"(?i)eval\s*\(",
        r"(?i)exec\s*\(",
        r"(?i)system\s*\(",
        r"<\?php",
        r"(?i)<iframe",
        r"\$\{",
    ];

    c.bench_function("batch_compile_10_patterns", |b| {
        b.iter(|| batch_compile(&patterns, true));
    });
}

criterion_group!(
    benches,
    bench_compile_single,
    bench_cache_hit,
    bench_cache_miss_then_hit,
    bench_validate_safety,
    bench_batch_compile,
);
criterion_main!(benches);
