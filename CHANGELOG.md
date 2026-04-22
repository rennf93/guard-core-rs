# Changelog

All notable changes to this project.

## [Unreleased]

### Added

- Rust detection engine: compiler, preprocessor, semantic analyzer
- Maturin/PyO3 bindings for Python interop
- Criterion benchmarks (~125x faster than Python on full pipeline)
- Fuzz targets via cargo-fuzz
- Benchmark scripts for Python vs Rust comparison

### Changed

- Restructured as Cargo workspace with `crates/*` layout
