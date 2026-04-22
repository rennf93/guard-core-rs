//! Semantic-analysis layer that complements regex-based detection.
//!
//! [`crate::detection_engine::semantic::SemanticAnalyzer`] scores incoming
//! content against a catalogue of attack keywords and structural patterns,
//! returning per-attack probabilities and an aggregate threat score.

use std::collections::{HashMap, HashSet};

use regex::{Regex, RegexBuilder};
use serde_json::{Value, json};

const MAX_CONTENT_LENGTH_TOKENS: usize = 50_000;
const MAX_TOKENS: usize = 1000;
const MAX_ENTROPY_LENGTH: usize = 10_000;

/// Heuristic analyser that scores content for common attack categories.
///
/// Internally holds a precompiled set of structural regexes and a keyword
/// index per attack type (XSS, SQL, command, path, template).
///
/// # Examples
///
/// ```no_run
/// use guard_core_rs::detection_engine::semantic::SemanticAnalyzer;
///
/// let analyzer = SemanticAnalyzer::new();
/// let analysis = analyzer.analyze("SELECT * FROM users WHERE id=1");
/// let score = analyzer.get_threat_score(&analysis);
/// assert!(score >= 0.0);
/// ```
pub struct SemanticAnalyzer {
    /// Map of attack category → keyword set used for base scoring.
    pub attack_keywords: HashMap<&'static str, HashSet<&'static str>>,
    /// Map of structural pattern name → pattern source string.
    pub attack_structures: HashMap<&'static str, &'static str>,
    compiled_structures: HashMap<&'static str, Regex>,
}

impl std::fmt::Debug for SemanticAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticAnalyzer").finish()
    }
}

impl Default for SemanticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticAnalyzer {
    /// Builds a fully-initialised analyser with the default keyword and
    /// structure tables.
    pub fn new() -> Self {
        let attack_keywords = build_attack_keywords();
        let attack_structures = build_attack_structures();
        let compiled_structures = attack_structures
            .iter()
            .filter_map(|(name, pat)| {
                RegexBuilder::new(pat)
                    .case_insensitive(true)
                    .build()
                    .ok()
                    .map(|re| (*name, re))
            })
            .collect();
        Self { attack_keywords, attack_structures, compiled_structures }
    }

    /// Tokenises `content` into lower-case words plus short structural
    /// snippets. The output is capped at 1000 tokens.
    pub fn extract_tokens(&self, content: &str) -> Vec<String> {
        let mut content_owned = content.to_string();
        if content_owned.len() > MAX_CONTENT_LENGTH_TOKENS {
            content_owned.truncate(MAX_CONTENT_LENGTH_TOKENS);
        }
        let ws = Regex::new(r"\s+").expect("static");
        content_owned = ws.replace_all(&content_owned, " ").to_string();
        let lowered = content_owned.to_ascii_lowercase();
        let word_re = Regex::new(r"\b\w+\b").expect("static");
        let mut tokens: Vec<String> = word_re
            .find_iter(&lowered)
            .take(MAX_TOKENS)
            .map(|m| m.as_str().to_string())
            .collect();

        let mut special = Vec::new();
        for re in self.compiled_structures.values() {
            for m in re.find_iter(&content_owned).take(10) {
                special.push(m.as_str().to_string());
            }
            if special.len() >= 50 {
                break;
            }
        }
        tokens.extend(special);
        tokens.truncate(MAX_TOKENS);
        tokens
    }

    /// Computes Shannon entropy over the first 10k characters of `content`.
    pub fn calculate_entropy(&self, content: &str) -> f64 {
        if content.is_empty() {
            return 0.0;
        }
        let truncated = if content.len() > MAX_ENTROPY_LENGTH {
            &content[..MAX_ENTROPY_LENGTH]
        } else {
            content
        };
        let mut counts: HashMap<char, usize> = HashMap::new();
        for ch in truncated.chars() {
            *counts.entry(ch).or_insert(0) += 1;
        }
        let length = truncated.chars().count() as f64;
        let mut entropy = 0.0;
        for count in counts.values() {
            let probability = *count as f64 / length;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        entropy
    }

    /// Counts the number of distinct encoding layers (percent, base64-like,
    /// hex, unicode-escapes, HTML entities) present in `content`.
    pub fn detect_encoding_layers(&self, content: &str) -> u32 {
        let scan = if content.len() > MAX_ENTROPY_LENGTH {
            &content[..MAX_ENTROPY_LENGTH]
        } else {
            content
        };
        let mut layers = 0;
        let checks = [
            r"%[0-9a-fA-F]{2}",
            r"[A-Za-z0-9+/]{4,}={0,2}",
            r"(?:0x)?[0-9a-fA-F]{4,}",
            r"\\u[0-9a-fA-F]{4}",
            r"&[#\w]+;",
        ];
        for pat in checks {
            if Regex::new(pat).ok().is_some_and(|r| r.is_match(scan)) {
                layers += 1;
            }
        }
        layers
    }

    fn calculate_base_score(&self, token_set: &HashSet<&str>, keywords: &HashSet<&'static str>) -> f64 {
        if keywords.is_empty() {
            return 0.0;
        }
        let matches = keywords.iter().filter(|k| token_set.contains(*k)).count();
        matches as f64 / keywords.len() as f64
    }

    fn get_structural_pattern_boost(&self, attack_type: &str, content: &str) -> f64 {
        let (pattern, case_insensitive): (&str, bool) = match attack_type {
            "xss" => (r"<[^>]+>", false),
            "sql" => (r"\b(?:union|select|from|where)\b", true),
            "command" => (r"[;&|]", false),
            "path" => (r"\.{2,}[/\\]", false),
            _ => return 0.0,
        };
        if RegexBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .build()
            .ok()
            .is_some_and(|r| r.is_match(content)) { 0.3 } else { 0.0 }
    }

    /// Returns the per-attack probability map for `content` keyed by attack
    /// type (`"xss"`, `"sql"`, ...).
    pub fn analyze_attack_probability(&self, content: &str) -> HashMap<String, f64> {
        let tokens = self.extract_tokens(content);
        let token_set: HashSet<&str> = tokens.iter().map(String::as_str).collect();
        let mut probs = HashMap::new();
        for (attack_type, keywords) in &self.attack_keywords {
            let base = self.calculate_base_score(&token_set, keywords);
            let boost = self.get_structural_pattern_boost(attack_type, content);
            probs.insert((*attack_type).to_string(), (base + boost).min(1.0));
        }
        probs
    }

    /// Returns `true` when the content looks obfuscated (high entropy, nested
    /// encodings, or dense special-character usage).
    pub fn detect_obfuscation(&self, content: &str) -> bool {
        if self.calculate_entropy(content) > 4.5 {
            return true;
        }
        if self.detect_encoding_layers(content) > 2 {
            return true;
        }
        let total = content.chars().count().max(1) as f64;
        let special = Regex::new(r"[^a-zA-Z0-9\s]").expect("static");
        let special_count = special.find_iter(content).count() as f64;
        if special_count / total > 0.4 {
            return true;
        }
        Regex::new(r"\S{100,}").expect("static").is_match(content)
    }

    /// Returns every structural pattern hit, each annotated with its position
    /// and surrounding context.
    pub fn extract_suspicious_patterns(&self, content: &str) -> Vec<Value> {
        let mut out = Vec::new();
        for (name, re) in &self.compiled_structures {
            for m in re.find_iter(content) {
                let context_start = m.start().saturating_sub(20);
                let context_end = (m.end() + 20).min(content.len());
                out.push(json!({
                    "type": name,
                    "pattern": m.as_str(),
                    "position": m.start(),
                    "context": &content[context_start..context_end],
                }));
            }
        }
        out
    }

    fn check_code_pattern_risks(&self, content: &str) -> f64 {
        let mut risk = 0.0;
        let checks: &[(&str, f64)] = &[
            (r"[\{\}].*[\{\}]", 0.2),
            (r"\w+\s*\([^)]*\)", 0.2),
            (r"[$@]\w+", 0.1),
            (r"[=+\-*/]{2,}", 0.1),
        ];
        for (pat, score) in checks {
            if Regex::new(pat).ok().is_some_and(|r| r.is_match(content)) {
                risk += score;
            }
        }
        risk
    }

    fn check_injection_keywords(&self, content: &str) -> f64 {
        let keywords = ["eval", "exec", "compile", "__import__", "globals", "locals"];
        for kw in keywords {
            let pat = format!(r"\b{kw}\b");
            if RegexBuilder::new(&pat).case_insensitive(true).build().ok().is_some_and(|r| r.is_match(content)) {
                return 0.2;
            }
        }
        0.0
    }

    /// Returns a 0.0-1.0 code-injection risk score by combining
    /// structural-pattern risk and keyword presence.
    pub fn analyze_code_injection_risk(&self, content: &str) -> f64 {
        let mut risk = 0.0;
        risk += self.check_code_pattern_risks(content);
        risk += self.check_injection_keywords(content);
        risk.min(1.0)
    }

    /// Runs every analysis sub-routine and returns a combined JSON report.
    pub fn analyze(&self, content: &str) -> Value {
        json!({
            "attack_probabilities": self.analyze_attack_probability(content),
            "entropy": self.calculate_entropy(content),
            "encoding_layers": self.detect_encoding_layers(content),
            "is_obfuscated": self.detect_obfuscation(content),
            "suspicious_patterns": self.extract_suspicious_patterns(content),
            "code_injection_risk": self.analyze_code_injection_risk(content),
            "token_count": self.extract_tokens(content).len(),
        })
    }

    /// Collapses an analysis report into a 0.0-1.0 threat score.
    pub fn get_threat_score(&self, analysis_results: &Value) -> f64 {
        let mut score = 0.0;
        if let Some(probs) = analysis_results.get("attack_probabilities").and_then(Value::as_object) {
            let max_prob = probs
                .values()
                .filter_map(Value::as_f64)
                .fold(0.0_f64, f64::max);
            score += max_prob * 0.3;
        }
        if analysis_results
            .get("is_obfuscated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            score += 0.2;
        }
        if let Some(layers) = analysis_results.get("encoding_layers").and_then(Value::as_u64)
            && layers > 0
        {
            score += (layers as f64 * 0.1).min(0.2);
        }
        if let Some(risk) = analysis_results.get("code_injection_risk").and_then(Value::as_f64) {
            score += risk * 0.2;
        }
        if let Some(patterns) = analysis_results.get("suspicious_patterns").and_then(Value::as_array) {
            score += (patterns.len() as f64 * 0.05).min(0.1);
        }
        score.min(1.0)
    }
}

fn build_attack_keywords() -> HashMap<&'static str, HashSet<&'static str>> {
    let mut m = HashMap::new();
    m.insert(
        "xss",
        HashSet::from([
            "script", "javascript", "onerror", "onload", "onclick", "onmouseover", "alert", "eval",
            "document", "cookie", "window", "location",
        ]),
    );
    m.insert(
        "sql",
        HashSet::from([
            "select", "union", "insert", "update", "delete", "drop", "from", "where", "order",
            "group", "having", "concat", "substring", "database", "table", "column",
        ]),
    );
    m.insert(
        "command",
        HashSet::from([
            "exec", "system", "shell", "cmd", "bash", "powershell", "wget", "curl", "nc",
            "netcat", "chmod", "chown", "sudo", "passwd",
        ]),
    );
    m.insert(
        "path",
        HashSet::from(["etc", "passwd", "shadow", "hosts", "proc", "boot", "win", "ini"]),
    );
    m.insert(
        "template",
        HashSet::from([
            "render", "template", "jinja", "mustache", "handlebars", "ejs", "pug", "twig",
        ]),
    );
    m
}

fn build_attack_structures() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("tag_like", r"<[^>]+>");
    m.insert("function_call", r"\w+\s*\([^)]*\)");
    m.insert("command_chain", r"[;&|]{1,2}");
    m.insert("path_traversal", r"\.{2,}[/\\]");
    m.insert("url_pattern", r"[a-z]+://");
    m
}
