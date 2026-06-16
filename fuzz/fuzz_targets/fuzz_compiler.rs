#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = guard_core_engine::compiler::compile(data);
    let _ = guard_core_engine::compiler::validate_pattern_safety(data);

    if let Ok(re) = guard_core_engine::compiler::compile(data) {
        for sample in ["test", "hello world", "<script>"] {
            let _ = re.is_match(sample);
        }
    }

    let mut cache = guard_core_engine::compiler::PatternCache::new(10);
    let _ = cache.get_or_compile(data);
});
