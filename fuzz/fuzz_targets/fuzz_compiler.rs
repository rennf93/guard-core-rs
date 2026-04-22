#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = guard_core_engine::compiler::compile(data);
    let _ = guard_core_engine::compiler::validate_pattern_safety(data);
    let _ = guard_core_engine::compiler::compile_and_test(data, &["test", "hello world", "<script>"]);

    let mut cache = guard_core_engine::compiler::PatternCache::new(10);
    let _ = cache.get_or_compile(data);
});
