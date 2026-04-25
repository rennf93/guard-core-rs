use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use guard_core_engine::preprocessor::collapse_whitespace;
use guard_core_engine::preprocessor::decode_common_encodings;
use guard_core_engine::preprocessor::extract_attack_regions;
use guard_core_engine::preprocessor::normalize_unicode;
use guard_core_engine::preprocessor::preprocess;
use guard_core_engine::preprocessor::remove_null_bytes;
use guard_core_engine::preprocessor::truncate_safely;

const CLEAN_SHORT: &str = "GET /api/v1/users?page=1&limit=20 HTTP/1.1";
const CLEAN_MEDIUM: &str = "This is a normal API request body with some JSON data \
    {\"username\": \"john_doe\", \"email\": \"john@example.com\", \"age\": 30}";

fn xss_payload() -> String {
    format!(
        "<scr{}ipt>al{}ert(document.cookie)</sc{}ript>",
        '\u{200B}', '\u{200C}', '\u{200D}'
    )
}

fn sqli_payload() -> String {
    "1' %55NION %53ELECT username, password FROM users WHERE '1'='1".to_owned()
}

fn path_traversal_payload() -> String {
    "../../../../../../etc/passwd%00.jpg".to_owned()
}

fn double_encoded() -> String {
    "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E".to_owned()
}

fn large_padding_attack() -> String {
    format!(
        "{}<script>alert(1)</script>{}",
        "a".repeat(5000),
        "b".repeat(5000)
    )
}

fn bench_normalize_unicode(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalize_unicode");

    group.bench_function("clean", |b| b.iter(|| normalize_unicode(CLEAN_SHORT)));
    group.bench_function("xss_bypass", |b| {
        let payload = xss_payload();
        b.iter(|| normalize_unicode(&payload));
    });
    group.bench_function("fullwidth_chars", |b| {
        let input = "\u{FF1C}script\u{FF1E}alert(1)\u{FF1C}/script\u{FF1E}";
        b.iter(|| normalize_unicode(input));
    });

    group.finish();
}

fn bench_collapse_whitespace(c: &mut Criterion) {
    let mut group = c.benchmark_group("collapse_whitespace");

    group.bench_function("normal", |b| b.iter(|| collapse_whitespace(CLEAN_MEDIUM)));
    group.bench_function("excessive", |b| {
        let input = "test  \t\t  multiple   \n\n  spaces   everywhere  ";
        b.iter(|| collapse_whitespace(input));
    });

    group.finish();
}

fn bench_remove_null_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove_null_bytes");

    group.bench_function("clean", |b| b.iter(|| remove_null_bytes(CLEAN_SHORT)));
    group.bench_function("with_nulls", |b| {
        let input = "test\x00null\x01\x02control\x03chars\x00here";
        b.iter(|| remove_null_bytes(input));
    });

    group.finish();
}

fn bench_decode_encodings(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_encodings");

    group.bench_function("url_encoded", |b| {
        b.iter(|| decode_common_encodings("%3Cscript%3Ealert(1)%3C%2Fscript%3E"));
    });
    group.bench_function("html_entities", |b| {
        b.iter(|| decode_common_encodings("&lt;script&gt;alert(1)&lt;/script&gt;"));
    });
    group.bench_function("double_encoded", |b| {
        let payload = double_encoded();
        b.iter(|| decode_common_encodings(&payload));
    });
    group.bench_function("sqli_encoded", |b| {
        let payload = sqli_payload();
        b.iter(|| decode_common_encodings(&payload));
    });

    group.finish();
}

fn bench_extract_attack_regions(c: &mut Criterion) {
    let mut group = c.benchmark_group("extract_attack_regions");

    group.bench_function("clean_content", |b| {
        b.iter(|| extract_attack_regions(CLEAN_MEDIUM, 10_000));
    });
    group.bench_function("xss_content", |b| {
        let payload = "<script>alert(1)</script> normal text SELECT * FROM users";
        b.iter(|| extract_attack_regions(payload, 10_000));
    });
    group.bench_function("large_padding", |b| {
        let payload = large_padding_attack();
        b.iter(|| extract_attack_regions(&payload, 200));
    });

    group.finish();
}

fn bench_truncate_safely(c: &mut Criterion) {
    let mut group = c.benchmark_group("truncate_safely");

    group.bench_function("short_noop", |b| {
        b.iter(|| truncate_safely(CLEAN_SHORT, 1000, true));
    });
    group.bench_function("large_with_attacks", |b| {
        let payload = large_padding_attack();
        b.iter(|| truncate_safely(&payload, 200, true));
    });
    group.bench_function("large_no_preserve", |b| {
        let payload = "a".repeat(10_000);
        b.iter(|| truncate_safely(&payload, 100, false));
    });

    group.finish();
}

fn bench_full_preprocess(c: &mut Criterion) {
    let payloads: Vec<(&str, String)> = vec![
        ("clean_short", CLEAN_SHORT.to_owned()),
        ("clean_medium", CLEAN_MEDIUM.to_owned()),
        ("xss_bypass", xss_payload()),
        ("sqli_encoded", sqli_payload()),
        ("path_traversal", path_traversal_payload()),
        ("double_encoded", double_encoded()),
        ("large_padding", large_padding_attack()),
    ];

    let mut group = c.benchmark_group("full_preprocess");

    for (name, payload) in &payloads {
        group.bench_with_input(BenchmarkId::new("preprocess", name), payload, |b, p| {
            b.iter(|| preprocess(p, 10_000, true));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_normalize_unicode,
    bench_collapse_whitespace,
    bench_remove_null_bytes,
    bench_decode_encodings,
    bench_extract_attack_regions,
    bench_truncate_safely,
    bench_full_preprocess,
);
criterion_main!(benches);
