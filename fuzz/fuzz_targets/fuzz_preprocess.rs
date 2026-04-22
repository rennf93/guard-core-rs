#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = guard_core_engine::preprocessor::preprocess(data, 10_000, true);

    let _ = guard_core_engine::preprocessor::normalize_unicode(data);
    let _ = guard_core_engine::preprocessor::decode_common_encodings(data);
    let _ = guard_core_engine::preprocessor::remove_null_bytes(data);
    let _ = guard_core_engine::preprocessor::collapse_whitespace(data);
    let _ = guard_core_engine::preprocessor::extract_attack_regions(data, 10_000);

    let _ = guard_core_engine::preprocessor::truncate_safely(data, 50, true);
    let _ = guard_core_engine::preprocessor::truncate_safely(data, 50, false);
    let _ = guard_core_engine::preprocessor::truncate_safely(data, 0, true);
});
