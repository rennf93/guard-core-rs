# Changelog

All notable changes to this project.

## [4.0.4] - 2026-09-24

### Added

- First crates.io release of `guard-core-engine` 4.0.4 and `guard-core-rs` 4.0.4; automated publish on GitHub release via `CARGO_REGISTRY_TOKEN`
- `Makefile` (`install`, `test`, `lint`, `bump-version`, `clean`) and `.github/scripts/bump_version.py` (stdlib-only version train across all workspace crates, `Cargo.lock`, and a CHANGELOG scaffold)

### Changed

- Parity with guard-core 4.0.4: binary-noise gates for binary request bodies, including the SQLi comment-terminator binary gate, and corpus harmonization with the go/php spec 4.0.3 set
- Version train bumped to 4.0.4 across all workspace member crates; `guard-core-engine` is now publishable (`publish = false` dropped)

## [Unreleased]

### Added

- Cargo workspace with `crates/*` layout (`guard-core-engine`, `guard-core-python`, `guard-core-rs`, `guard-core-benchmark`)
- Detection engine: `compiler` (LRU regex cache, ReDoS validation), `preprocessor` (unicode normalize, URL/HTML decode, hex/unicode/base64/SQL-comment decode, attack-preserving truncation), `semantic` (entropy, encoding-layer detection, obfuscation heuristics, attack probability scoring, threat score)
- PyO3/maturin bindings with stable ABI (`abi3-py310`): `preprocess`, `analyze`, `get_threat_score`, `calculate_entropy`, `detect_encoding_layers`, `detect_obfuscation`, `validate_pattern_safety`, `batch_threat_scores`
- `batch_threat_scores` releases the GIL during batch processing via `py.detach()`
- Fuzz targets via `cargo-fuzz` for preprocessor, semantic, and compiler
- Criterion benchmarks; Python vs Rust comparison script in `scripts/benches/`
- CI workflow: fmt + clippy + test on ubuntu-latest with SHA-pinned actions, `permissions: {}`, concurrency cancel
- Fuzz CI: build + 60s smoke run per target on push/PR
- Pre-commit: zizmor, prettier, taplo, shfmt, cargo fmt/clippy/test, `forbidden-allow-attr` hook
- `.editorconfig`, `.prettierrc`, `.taplo.toml`, `scripts/pin-actions.sh` ported from internal tooling
- `DANGEROUS_PATTERNS` list for flagging catastrophic-backtracking constructs safe in Rust's NFA engine but dangerous in PCRE/Python `re`

### Changed

- Crate renamed `guard-core` -> `guard-core-rs` to match ecosystem convention
- License: single MIT -> dual MIT OR Apache-2.0
- `htmlescape` (unmaintained, 2016) replaced with `html-escape`
- `filter_map(...ok())` on all static pattern slices replaced with `.map(...expect())` — silent skip on bad static regex is always a bug
- All `LazyLock<Regex>` statics: `.unwrap()` -> `.expect("static regex")`
- `PatternCache::new`: `unreachable!` macro dropped; `NonZeroUsize::new(...).expect()` after explicit `clamp(1, 5000)` guard
- `batch_compile`: double `filter` + `filter_map` chain collapsed into single `filter_map` pass
- `util::floor_boundary` / `util::ceil_boundary` deleted; all callers updated to `str::floor_char_boundary` / `str::ceil_char_boundary` (stabilized Rust 1.79)
- `extract_attack_regions` and `extract_suspicious_patterns`: byte offsets rounded to UTF-8 char boundaries before slicing
- `detect_encoding_layers`: `MAX_SCAN_LENGTH` rounded to char boundary before slice
- `obfuscation_with_inputs`: special-char ratio denominator uses `chars().count()` not `len()`, matching Python `len(content)` semantics
- `decode_common_encodings` iteration cap raised 3 -> 7; added 5 decoder stages matching Python pipeline: `\xNN` hex-escape, `\uNNNN` unicode-escape, base64 candidate (printable-ASCII guard, no new dep), SQL block-comment stripping (`SEL/**/ECT`), SQL line-comment stripping (`--`, `#`)
- `extract_tokens` caps per-pattern matches at 10, matching Python `[:10]` semantics
- `analyze()` deduplicates shared work — tokens, entropy, encoding layers computed once
- `validate_pattern_safety` returns the specific dangerous construct matched, not a generic message
- `SuspiciousPattern.pattern_type` is `&'static str` (was `String`), no per-match allocation
- `SuspiciousPattern.position` is now a Unicode code-point index into the analyzed content, matching the Python reference (`semantic.py` emits `match.start()` on the processed `str`). The `regex` crate still matches on bytes internally; byte offsets are converted at the result boundary with an incremental per-regex cursor. Binding-visible: the PyO3 `analyze` function forwards the field, so `suspicious_patterns[*].position` is a code-point index for Python callers too
- `PatternCache::get_or_compile` uses single-lookup `try_get_or_insert_mut` (lru 0.17+)
- All GitHub Actions workflows: `permissions: {}` top-level, `persist-credentials: false` on checkout, all `actions/*` refs SHA-pinned; `dtolnay/rust-toolchain` replaced with `actions-rust-lang/setup-rust-toolchain` (pinnable)
- `greetings.yml`: `pull_request_target` -> `pull_request` (removes write-token exposure on untrusted forks)
- `bench.py`: `sys.path.insert` hack removed; relies on `guard-core` in `requirements.txt`

### Removed

- `compile_and_test`: dead helper, no callers outside its own tests
- `crates/guard-core-engine/src/util.rs`: replaced by stdlib (see above)
- `scripts/benches/bench_results.json` from version control (added to `.gitignore`)

### Known differences from Python

- **Entropy over bytes, not code points.** Python `Counter(content)` counts code points; Rust uses a 256-byte array. Multi-byte UTF-8 reaches the `entropy > 4.5` threshold more readily in Rust. Acceptable — entropy is one of four obfuscation heuristics, not a hard gate.
- **Suspicious-pattern context windows slice bytes, not code points.** The Python reference expands the context window ±20 code points around a match; Rust expands ±20 bytes rounded to char boundaries. Identical for ASCII content; positions themselves are code-point indices in both.
- **`ast.parse` injection signal not ported.** Python's `_check_ast_parsing_risk` adds 0.2-0.3 to code injection scores. Not worth a Python parser dependency for a weak signal.
- **Async event plumbing not ported.** `agent_handler`, `correlation_id`, `preprocess_batch` are handler-layer concerns, out of scope.
- **`<?php` pattern corrected.** Python's `r"<?php"` makes `<` optional. Rust uses `r"<\?php"` (correct intent). Filed upstream as guard-core#6.
- **`truncate_safely` output order differs.** Python `insert(0, ...)` yields `[gapN…gap1, region…]`. Rust yields `[gap1, region1, gap2, region2…]`. Invisible in practice — detection is substring-based. Filed upstream as guard-core#7.
- **Base64 detector is broad.** `[A-Za-z0-9+/]{4,}={0,2}` fires on any 4+ alphanumeric run. Faithful port of Python.
