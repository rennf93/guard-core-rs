//! Framework-agnostic application-layer API security engine.
//!
//! Rust port of [guard-core](https://github.com/rennf93/guard-core)'s
//! detection engine. **Work in progress:** currently covers only the
//! CPU-bound detection pipeline. Handlers, protocols, decorators, and
//! I/O layers are not yet ported.
//!
//! Re-exports the detection engine modules:
//!
//! - [`compiler`] - regex pattern compilation with LRU caching and ReDoS
//!   safety validation
//! - [`preprocessor`] - unicode NFKC normalization, URL/HTML decoding,
//!   null byte removal, whitespace collapsing, and attack-preserving
//!   truncation
//! - [`semantic`] - token extraction, Shannon entropy, encoding layer
//!   detection, attack probability scoring, obfuscation detection, code
//!   injection risk analysis, and aggregate threat scoring
//!
//! # Usage
//!
//! ```
//! use guard_core::preprocessor;
//! use guard_core::semantic::{self, AttackKeywords, AttackStructures};
//!
//! let raw = "<scr\u{200B}ipt>alert(1)</script>";
//! let clean = preprocessor::preprocess(raw, 10_000, true);
//!
//! let kw = AttackKeywords::default();
//! let st = AttackStructures::default();
//! let result = semantic::analyze(&clean, &kw, &st);
//! let score = semantic::get_threat_score(&result);
//!
//! assert!(score > 0.0);
//! ```

pub use guard_core_engine::compiler;
pub use guard_core_engine::preprocessor;
pub use guard_core_engine::semantic;
