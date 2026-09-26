# Changelog

All notable changes to this project.

## [Unreleased]

### Added

- Global IP gate (`guard_core_engine::ip_gate`), the minimal Rust port of the reference engine's global IP stage and the exempt_ips contract (spec rennf93/guard-core#117): `IpGateConfig::new(whitelist, blacklist, exempt_ips)` parses and validates the three lists once at startup and fails closed on an invalid entry (`IpGateError` names the list and the entry), and `IpGateConfig::evaluate` mirrors the reference ordering - with a non-empty `whitelist` an unlisted, non-exempt IP is denied (`IP not in whitelist`), otherwise a `blacklist` hit is denied (`IP is blacklisted`). `exempt_ips` sets the same skip state a whitelist match sets (`IpGateDecision::is_exempt`, alongside `is_whitelisted`) but never adds a deny path, never opens the whitelist gate, and is only set after the deny checks pass; matching semantics are identical for all three lists (exact, CIDR with host bits cleared, IPv4-mapped parity, no cross-family matches). The adapters' deny paths and skip-state plumbing build on this module
- Request body value extraction in the engine (`body_scan`, `multipart_scan`, `json_walk`, `binary_islands`), porting the reference body-scanning split (guard-core 4.0.4, upstream commit 5f399234, via the Go engine's second-reference port): urlencoded form bodies split into field values scanned under `request_body:form_field`, multipart/form-data bodies split into parts scanned under `request_body:multipart_field` (label name scan, `filename="..."` entry with quote stripping and RFC 2231 extended-filename handling, every raw part header entry, then the payload), JSON bodies walked to their leaves with mongo operator keys (`$where`, `$ne`, ...) reported as direct `nosql` hits, embedded JSON in form/multipart field values walked with the `:embedded_json` leaf-context suffix per level, and the whole-body blob fallback for everything else. Adapters feed every extracted value through the normal detect path instead of the lossy whole-body blob, so `\default` in a form field now flows through the raw-view recon scan
- Binary islands reduction for binary-dense multipart file-part payloads: a file-part payload whose binary artifact characters fill at least a fifth of it is reduced to printable runs of at least the new `DetectConfig::binary_min_run_length` (`detection_binary_min_run_length`, reference bounds 4..=1024, default 16) before pattern scanning, so compressed upload bytes stop producing attack-shaped matches whose rate grows with file size while text genuinely embedded in an upload still scans in full. Text uploads, short or mostly-text payloads, text parts without a filename, and whole-body fallback scans keep their full scan, so raw-body signature coverage stays intact
- Hand-rolled line-based multipart scanner mirroring the email feedparser tolerances the reference relies on: raw header names and case in wire order, folded header values with the raw break kept, colonless lines opening the payload (`MissingHeaderBodySeparatorDefect`), the line terminator before a boundary belonging to the delimiter, transport padding ignored on boundary lines, nested multipart containers expanded in place, and a missing closing boundary keeping the part parsed so far
- `detect_verdict` (PyO3) accepts the new `binary_min_run_length` knob with the reference default of 16

### Fixed

- Recon-category rows now also scan the signal-preserving raw view: the configured preprocessor folds LDAP hex escapes (`\de` -> `Þ`) before the pattern tables run, so separator-prefixed probes such as `\default` or `\report.asp` in query or body values never reached a recon row and went undetected. The raw view carries the original value, the #116 leading-separator gate applies to raw-view matches unchanged (bare words stay innocent outside `url_path`/`unknown`, embedded JSON leaves included), and a (pattern, match) deduplication on the raw-view merge keeps a row that matches in both views a single threat
- Structural matchers fold ASCII case like the reference engine: every builtin row compiles under a global `re.IGNORECASE` (`suspatterns_handler.py`), so the sensitive-path, cms-probing, recon, file-upload and proto-pollution matchers now catch uppercase probes (`/SAP`, `/.ENV`, `Thumbs.DB`, `/DOCKERFILE`, `filename="shell.PHP.jpg"`, `object.prototype.x = 1`) exactly as guard-core does; the four `(?-i:...)` deserialization base64 magic rows stay case-sensitive, which was already correct
- Recon whole-value rows with an optional leading path separator no longer read bare query or body values such as `?system=SAP` or `README.md` as probe paths: on `query_param`/`request_body` (embedded JSON leaves included) those hits are rejected unless the value starts with `/` or `\`, while `url_path` and `unknown` are unchanged and separator-leading probes still fire. Gated rows are derived from the table (recon category plus the `\A[/\]?` anchor), matching guard-core #115 (upstream commit 08f79d67)

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
