//! Pattern-based attack detection engine.
//!
//! Covers regex compilation in [`crate::detection_engine::compiler`], runtime
//! performance monitoring in [`crate::detection_engine::monitor`], content
//! preprocessing in [`crate::detection_engine::preprocessor`], and semantic
//! analysis in [`crate::detection_engine::semantic`].

pub mod compiler;
pub mod monitor;
pub mod preprocessor;
pub mod semantic;

pub use compiler::{PatternCompiler, RegexFlags};
pub use monitor::{AnomalyCallback, PatternStats, PerformanceMetric, PerformanceMonitor, RecordMetricInput};
pub use preprocessor::ContentPreprocessor;
pub use semantic::SemanticAnalyzer;
