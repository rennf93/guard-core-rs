#![allow(clippy::doc_markdown)]

use std::collections::HashMap;

use guard_core_engine::preprocessor as preprocessor;
use guard_core_engine::semantic as semantic;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Preprocess content: unicode normalization, URL/HTML decode, null byte
/// removal, whitespace collapsing, attack-preserving truncation.
///
/// Parameters
/// ----------
/// content : str
///     Raw input to preprocess.
/// max_length : int, optional
///     Maximum output length (default 10000).
/// preserve_attacks : bool, optional
///     Whether to prioritize attack regions when truncating (default True).
///
/// Returns
/// -------
/// str
///     Preprocessed content.
#[pyfunction]
#[pyo3(signature = (content, max_length=10_000, preserve_attacks=true))]
fn preprocess(content: &str, max_length: usize, preserve_attacks: bool) -> String {
    preprocessor::preprocess(content, max_length, preserve_attacks)
}

/// Normalize unicode content (NFKC + lookalike replacement).
///
/// Parameters
/// ----------
/// content : str
///     Raw input.
///
/// Returns
/// -------
/// str
///     Normalized content.
#[pyfunction]
fn normalize_unicode(content: &str) -> String {
    preprocessor::normalize_unicode(content)
}

/// Decode URL-encoded and HTML-escaped content (up to 3 iterations).
///
/// Parameters
/// ----------
/// content : str
///     Encoded input.
///
/// Returns
/// -------
/// str
///     Decoded content.
#[pyfunction]
fn decode_common_encodings(content: &str) -> String {
    preprocessor::decode_common_encodings(content)
}

/// Run full semantic analysis on content.
///
/// Parameters
/// ----------
/// content : str
///     Content to analyze (should be preprocessed first).
///
/// Returns
/// -------
/// dict
///     Analysis results with keys: attack_probabilities, entropy,
///     encoding_layers, is_obfuscated, suspicious_patterns,
///     code_injection_risk, token_count.
#[pyfunction]
fn analyze(py: Python<'_>, content: &str) -> PyResult<Py<PyDict>> {
    let keywords = semantic::AttackKeywords::default();
    let structures = semantic::AttackStructures::default();
    let result = semantic::analyze(content, &keywords, &structures);

    let dict = PyDict::new(py);

    let probs = PyDict::new(py);
    for (k, v) in &result.attack_probabilities {
        probs.set_item(k, v)?;
    }

    dict.set_item("attack_probabilities", probs)?;
    dict.set_item("entropy", result.entropy)?;
    dict.set_item("encoding_layers", result.encoding_layers)?;
    dict.set_item("is_obfuscated", result.is_obfuscated)?;
    dict.set_item("code_injection_risk", result.code_injection_risk)?;
    dict.set_item("token_count", result.token_count)?;

    let patterns: Vec<HashMap<&str, String>> = result
        .suspicious_patterns
        .iter()
        .map(|p| {
            HashMap::from([
                ("type", p.pattern_type.clone()),
                ("pattern", p.matched.clone()),
                ("position", p.position.to_string()),
                ("context", p.context.clone()),
            ])
        })
        .collect();

    dict.set_item("suspicious_patterns", patterns)?;

    Ok(dict.into())
}

/// Calculate threat score from analysis results.
///
/// Parameters
/// ----------
/// content : str
///     Content to score (runs full analysis internally).
///
/// Returns
/// -------
/// float
///     Threat score between 0.0 and 1.0.
#[pyfunction]
fn get_threat_score(content: &str) -> f64 {
    let keywords = semantic::AttackKeywords::default();
    let structures = semantic::AttackStructures::default();
    let result = semantic::analyze(content, &keywords, &structures);
    semantic::get_threat_score(&result)
}

/// Calculate Shannon entropy of content.
///
/// Parameters
/// ----------
/// content : str
///     Input text.
///
/// Returns
/// -------
/// float
///     Entropy value in bits.
#[pyfunction]
fn calculate_entropy(content: &str) -> f64 {
    semantic::calculate_entropy(content)
}

/// Detect number of encoding layers in content.
///
/// Parameters
/// ----------
/// content : str
///     Input text.
///
/// Returns
/// -------
/// int
///     Number of detected encoding layers (URL, base64, hex, unicode, HTML).
#[pyfunction]
fn detect_encoding_layers(content: &str) -> u32 {
    semantic::detect_encoding_layers(content)
}

/// Detect if content appears obfuscated.
///
/// Parameters
/// ----------
/// content : str
///     Input text.
///
/// Returns
/// -------
/// bool
///     True if content shows signs of obfuscation.
#[pyfunction]
fn detect_obfuscation(content: &str) -> bool {
    semantic::detect_obfuscation(content)
}

/// Validate if a regex pattern is safe from catastrophic backtracking.
///
/// Parameters
/// ----------
/// pattern : str
///     Regex pattern to validate.
///
/// Returns
/// -------
/// tuple[bool, str]
///     (is_safe, reason) pair.
#[pyfunction]
fn validate_pattern_safety(pattern: &str) -> (bool, &'static str) {
    guard_core_engine::compiler::validate_pattern_safety(pattern)
}

/// Process a batch of contents and return threat scores.
///
/// Single FFI crossing for the entire batch, amortizing PyO3 overhead.
///
/// Parameters
/// ----------
/// contents : list[str]
///     List of raw inputs to process.
/// max_length : int, optional
///     Maximum preprocessed length per item (default 10000).
///
/// Returns
/// -------
/// list[float]
///     Threat scores between 0.0 and 1.0 for each input.
#[pyfunction]
#[pyo3(signature = (contents, max_length=10_000))]
fn batch_threat_scores(contents: Vec<String>, max_length: usize) -> Vec<f64> {
    let keywords = semantic::AttackKeywords::default();
    let structures = semantic::AttackStructures::default();

    contents
        .iter()
        .map(|content| {
            let preprocessed = preprocessor::preprocess(content.as_str(), max_length, true);
            let result = semantic::analyze(&preprocessed, &keywords, &structures);
            semantic::get_threat_score(&result)
        })
        .collect()
}

#[pymodule]
fn guard_core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(preprocess, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_unicode, m)?)?;
    m.add_function(wrap_pyfunction!(decode_common_encodings, m)?)?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add_function(wrap_pyfunction!(get_threat_score, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(detect_encoding_layers, m)?)?;
    m.add_function(wrap_pyfunction!(detect_obfuscation, m)?)?;
    m.add_function(wrap_pyfunction!(validate_pattern_safety, m)?)?;
    m.add_function(wrap_pyfunction!(batch_threat_scores, m)?)?;
    Ok(())
}
