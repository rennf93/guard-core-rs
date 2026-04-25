# Changelog

All notable changes to this project.

## [Unreleased]

### Initial scaffold (pre-review)

- Cargo workspace with `crates/*` layout
- Rust detection engine: compiler, preprocessor, semantic analyzer
- Maturin/PyO3 bindings for Python interop with `batch_threat_scores`
- Criterion benchmarks (~125x faster than Python on full pipeline)
- Fuzz targets via cargo-fuzz
- Benchmark scripts for Python vs Rust comparison

### PR #1 review fixes (post-review)

- Rename umbrella crate `guard-core` -> `guard-core-rs` matching ecosystem convention
- Dual-license MIT OR Apache-2.0
- Swap `htmlescape` (unmaintained, last 2016) for `html-escape`
- `extract_attack_regions` and `extract_suspicious_patterns` round byte offsets to UTF-8 char boundaries before slicing (no panic on multi-byte content near region edges)
- `batch_threat_scores` releases the GIL during batch via `py.detach()`
- `analyze()` returns `position` as Python `int` (was string)
- `extract_tokens` caps at 10 per-pattern matching Python `[:10]` semantics
- `analyze()` deduplicates shared work (tokens, entropy, encoding layers computed once, passed to dependent functions)
- `validate_pattern_safety` returns the specific dangerous construct that matched, not a generic message
- `SuspiciousPattern.pattern_type` is now `&'static str` (was `String`), skipping per-match allocation
- `PatternCache::get_or_compile` uses single-lookup `try_get_or_insert_mut`
- Create `floor_boundary` / `ceil_boundary` in `crate::util`
- Drop `#[doc(hidden)]` on `calculate_entropy`, `detect_encoding_layers`, `detect_obfuscation` since PyO3 re-exposes them publicly
- CI: fuzz build + 60s smoke run per target on PR
- pre-commit: justify crate-level `#![allow(clippy::doc_markdown)]` in `guard-core-python` (numpy-style PyO3 docstrings)

### Known differences from Python

- **Entropy is computed over bytes, not code points.** Python uses `Counter(content)` which counts code points. Rust uses a fixed-size 256-byte array for speed. Multi-byte UTF-8 content reaches the `entropy > 4.5` obfuscation threshold more readily in Rust. Acceptable trade-off given how the entropy signal is used (one of four obfuscation heuristics, not a hard threshold).
- **`ast.parse` injection signal dropped.** Python's `_check_ast_parsing_risk` adds 0.2-0.3 to code injection scores when content parses as a Python expression. Pulling a Python parser into Rust is not worth the dependency for a weak signal (most innocent content also parses).
- **Async event plumbing not ported.** Python's `agent_handler`, `correlation_id`, and `preprocess_batch` exist for the handler layer which is out of scope for this crate.
- **`<?php` regex fix.** Python's `r"<?php"` makes `<` optional and matches bare "php" as an attack indicator. Rust uses `r"<\?php"` which is the intended behavior. Filed upstream as guard-core#6.
- **`truncate_safely` output ordering.** Python emits `[gapN, ..., gap1, region1, region2, ...]` via `insert(0, ...)`. Rust emits `[gap1, region1, gap2, region2, ...]` which is the more intuitive interleaving. Detection is regex-based on substrings so the difference is invisible in practice. Filed upstream as guard-core#7.
- **Base64 detector is broad.** `[A-Za-z0-9+/]{4,}={0,2}` matches any 4+ alphanumeric run. Faithful port of Python; means obfuscation detection is trigger-happy on normal alphanumeric content.
