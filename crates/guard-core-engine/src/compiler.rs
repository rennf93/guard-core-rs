use std::num::NonZeroUsize;

use lru::LruCache;
use regex::Regex;

const DANGEROUS_PATTERNS: &[&str] = &[
    r"\(\.\*\)\+",
    r"\(\.\+\)\+",
    r"\([^)]*\*\)\+",
    r"\([^)]*\+\)\+",
    r"(?:\.\*){2,}",
    r"(?:\.\+){2,}",
];

/// LRU cache for compiled regex patterns.
///
/// Capacity is clamped to 1..=5000. Patterns are compiled with
/// case-insensitive and multiline flags (`(?im)`).
pub struct PatternCache {
    cache: LruCache<String, Regex>,
}

impl PatternCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.clamp(1, 5000);
        Self {
            cache: LruCache::new(NonZeroUsize::new(cap).expect("clamped above zero")),
        }
    }

    /// Retrieve from cache or compile and insert. LRU eviction on overflow.
    pub fn get_or_compile(&mut self, pattern: &str) -> Result<&Regex, regex::Error> {
        if !self.cache.contains(pattern) {
            let compiled = Regex::new(&format!("(?im){pattern}"))?;
            self.cache.put(pattern.to_owned(), compiled);
        }

        Ok(self.cache.get(pattern).expect("clamped above zero"))
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// Compile a one-shot pattern with case-insensitive + multiline flags.
pub fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(&format!("(?im){pattern}"))
}

/// Check if a pattern contains constructs that cause catastrophic
/// backtracking in PCRE/Python `re`.
///
/// Rust's `regex` crate uses finite automata and is inherently ReDoS-safe,
/// but this flags patterns that would be dangerous in other engines.
/// Returns `(is_safe, reason)`.
#[must_use]
pub fn validate_pattern_safety(pattern: &str) -> (bool, &'static str) {
    for dangerous in DANGEROUS_PATTERNS {
        if let Ok(checker) = Regex::new(dangerous)
            && checker.is_match(pattern)
        {
            return (false, "pattern contains dangerous backtracking construct");
        }
    }

    (true, "pattern appears safe")
}

/// Compile and exercise a pattern against test strings.
/// Returns `false` if compilation fails.
#[doc(hidden)]
#[must_use]
pub fn compile_and_test(pattern: &str, test_strings: &[&str]) -> bool {
    let Ok(re) = compile(pattern) else {
        return false;
    };

    for s in test_strings {
        let _ = re.is_match(s);
    }

    true
}

/// Compile multiple patterns, skipping invalid ones. When `validate` is
/// true, patterns flagged by [`validate_pattern_safety`] are also skipped.
#[must_use]
pub fn batch_compile(patterns: &[&str], validate: bool) -> Vec<(String, Regex)> {
    patterns
        .iter()
        .filter(|pat| !validate || validate_pattern_safety(pat).0)
        .filter_map(|&pat| compile(pat).ok().map(|re| (pat.to_owned(), re)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_basic_operations() {
        let mut cache = PatternCache::new(10);
        assert!(cache.is_empty());

        let re = cache.get_or_compile(r"\d+").unwrap();
        assert!(re.is_match("123"));
        assert_eq!(cache.len(), 1);

        let _ = cache.get_or_compile(r"\d+").unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_eviction() {
        let mut cache = PatternCache::new(2);

        cache.get_or_compile("aaa").unwrap();
        cache.get_or_compile("bbb").unwrap();
        cache.get_or_compile("ccc").unwrap();

        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_capacity_clamping() {
        let cache = PatternCache::new(0);
        assert_eq!(cache.cache.cap().get(), 1);

        let cache = PatternCache::new(99999);
        assert_eq!(cache.cache.cap().get(), 5000);
    }

    #[test]
    fn dangerous_patterns_detected() {
        let dangerous = [
            r"(.*)+",
            r"(.+)+",
            r"([a-z]*)+",
            r"([a-z]+)+",
            r".*.*",
            r".+.+",
        ];

        for pat in dangerous {
            let (safe, _) = validate_pattern_safety(pat);
            assert!(!safe, "should flag: {pat}");
        }
    }

    #[test]
    fn safe_patterns_pass() {
        let safe = [
            r"<script[^>]*>",
            r"\d{3}-\d{3}-\d{4}",
            r"[a-zA-Z0-9]+",
            r"https?://\S+",
        ];

        for pat in safe {
            let (safe, _) = validate_pattern_safety(pat);
            assert!(safe, "should pass: {pat}");
        }
    }

    #[test]
    fn compile_invalid_pattern() {
        assert!(compile(r"invalid(pattern").is_err());
    }

    #[test]
    fn batch_compile_filters_invalid() {
        let patterns = vec![r"\d+", r"invalid(", r"[a-z]+"];
        let results = batch_compile(&patterns, false);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn batch_compile_with_validation() {
        let patterns = vec![r"\d+", r"(.*)+", r"[a-z]+"];
        let results = batch_compile(&patterns, true);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(p, _)| p != "(.*)+"));
    }

    #[test]
    fn case_insensitive_by_default() {
        let re = compile(r"select").unwrap();
        assert!(re.is_match("SELECT"));
        assert!(re.is_match("SeLeCt"));
    }

    #[test]
    fn multiline_by_default() {
        let re = compile(r"^hello").unwrap();
        assert!(re.is_match("first line\nhello world"));
    }

    #[test]
    fn compile_and_test_works() {
        assert!(compile_and_test(r"\d+", &["123", "abc"]));
        assert!(!compile_and_test(r"invalid(", &["test"]));
    }

    #[test]
    fn compile_sync_basic_match() {
        let re = compile(r"test\d+").unwrap();
        assert!(re.is_match("test123"));
        assert!(!re.is_match("test"));
    }

    #[test]
    fn cache_lru_order() {
        let mut cache = PatternCache::new(3);
        for i in 0..3 {
            cache.get_or_compile(&format!("pattern_{i}")).unwrap();
        }
        assert_eq!(cache.len(), 3);

        let _ = cache.get_or_compile("pattern_0").unwrap();
        cache.get_or_compile("pattern_new").unwrap();
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn validate_with_custom_test_strings() {
        let (safe, msg) = validate_pattern_safety(r"test\d+");
        assert!(safe);
        assert_eq!(msg, "pattern appears safe");
    }

    #[test]
    fn batch_compile_all_invalid() {
        let patterns = vec![r"invalid(", r"[unclosed"];
        let results = batch_compile(&patterns, false);
        assert!(results.is_empty());
    }

    #[test]
    fn cache_clear() {
        let mut cache = PatternCache::new(10);
        cache.get_or_compile("a").unwrap();
        cache.get_or_compile("b").unwrap();
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn compile_same_pattern_returns_same_result() {
        let mut cache = PatternCache::new(10);
        let r1 = cache.get_or_compile(r"\d+").unwrap().as_str().to_owned();
        let r2 = cache.get_or_compile(r"\d+").unwrap().as_str().to_owned();
        assert_eq!(r1, r2);
        assert_eq!(cache.len(), 1);
    }
}
