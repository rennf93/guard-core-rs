//! Regex compilation, caching, and ReDoS safety validation.
//!
//! [`crate::detection_engine::compiler::PatternCompiler`] caches compiled
//! patterns by `(pattern, flags)` and validates user-supplied regexes against
//! a library of known-dangerous constructs before they are executed.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};
use tokio::sync::Mutex;

use crate::error::{GuardCoreError, Result};

/// Soft cap on the number of compiled patterns retained by the compiler.
pub const MAX_CACHE_SIZE: usize = 1000;
const MAX_CACHE_SIZE_HARD: usize = 5000;

/// Compile-time flags applied when building a [`regex::Regex`].
///
/// Matches [`regex::RegexBuilder`] knobs that Guard Core cares about.
#[derive(Debug, Clone, Copy)]
pub struct RegexFlags {
    /// Enable case-insensitive matching (`(?i)`).
    pub case_insensitive: bool,
    /// Enable multi-line mode (`(?m)`).
    pub multi_line: bool,
    /// Allow `.` to match newline characters (`(?s)`).
    pub dot_matches_new_line: bool,
}

impl RegexFlags {
    /// Returns the default flag set used by Guard Core (case-insensitive,
    /// multi-line, dot-does-not-match-newline).
    pub const fn default_flags() -> Self {
        Self { case_insensitive: true, multi_line: true, dot_matches_new_line: false }
    }

    fn key_suffix(&self) -> u8 {
        let mut v = 0u8;
        if self.case_insensitive {
            v |= 1;
        }
        if self.multi_line {
            v |= 2;
        }
        if self.dot_matches_new_line {
            v |= 4;
        }
        v
    }
}

impl Default for RegexFlags {
    fn default() -> Self {
        Self::default_flags()
    }
}

struct CacheInner {
    compiled: HashMap<String, Regex>,
    order: VecDeque<String>,
}

/// LRU cache and compiler for regex patterns.
///
/// Enforces a hard cap of 5000 entries regardless of the caller-provided
/// `max_cache_size`. Patterns are validated via
/// [`crate::detection_engine::compiler::PatternCompiler::validate_pattern_safety`]
/// before they are compiled through user-facing APIs.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use guard_core_rs::detection_engine::compiler::{PatternCompiler, RegexFlags};
///
/// # async fn run() {
/// let compiler = PatternCompiler::new(Duration::from_secs(2), 100);
/// let re = compiler.compile_pattern(r"(?i)union\s+select", RegexFlags::default_flags()).await;
/// assert!(re.is_ok());
/// # }
/// ```
pub struct PatternCompiler {
    default_timeout: Duration,
    max_cache_size: usize,
    cache: Arc<Mutex<CacheInner>>,
}

impl std::fmt::Debug for PatternCompiler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternCompiler")
            .field("default_timeout", &self.default_timeout)
            .field("max_cache_size", &self.max_cache_size)
            .finish()
    }
}

impl Default for PatternCompiler {
    fn default() -> Self {
        Self::new(Duration::from_secs(5), MAX_CACHE_SIZE)
    }
}

impl PatternCompiler {
    /// Creates a new compiler with the supplied default timeout and cache
    /// size (capped at 5000).
    pub fn new(default_timeout: Duration, max_cache_size: usize) -> Self {
        Self {
            default_timeout,
            max_cache_size: max_cache_size.min(MAX_CACHE_SIZE_HARD),
            cache: Arc::new(Mutex::new(CacheInner {
                compiled: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    fn cache_key(pattern: &str, flags: RegexFlags) -> String {
        format!("{}:{}", pattern, flags.key_suffix())
    }

    /// Returns the compiled [`regex::Regex`] for `pattern`, evicting the LRU
    /// entry if the cache is full.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Pattern`] if `pattern` is
    /// syntactically invalid.
    pub async fn compile_pattern(&self, pattern: &str, flags: RegexFlags) -> Result<Regex> {
        let key = Self::cache_key(pattern, flags);
        let mut guard = self.cache.lock().await;
        if let Some(existing) = guard.compiled.get(&key).cloned() {
            if let Some(pos) = guard.order.iter().position(|k| k == &key) {
                guard.order.remove(pos);
            }
            guard.order.push_back(key);
            return Ok(existing);
        }
        if guard.compiled.len() >= self.max_cache_size
            && let Some(oldest) = guard.order.pop_front()
        {
            guard.compiled.remove(&oldest);
        }
        let compiled = Self::build_regex(pattern, flags)?;
        guard.compiled.insert(key.clone(), compiled.clone());
        guard.order.push_back(key);
        Ok(compiled)
    }

    /// Synchronous variant that bypasses the cache.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GuardCoreError::Pattern`] on syntax errors.
    pub fn compile_pattern_sync(&self, pattern: &str, flags: RegexFlags) -> Result<Regex> {
        Self::build_regex(pattern, flags)
    }

    fn build_regex(pattern: &str, flags: RegexFlags) -> Result<Regex> {
        RegexBuilder::new(pattern)
            .case_insensitive(flags.case_insensitive)
            .multi_line(flags.multi_line)
            .dot_matches_new_line(flags.dot_matches_new_line)
            .build()
            .map_err(GuardCoreError::from)
    }

    /// Validates `pattern` against a list of dangerous constructs and exercises
    /// it with the supplied test strings. Returns `(is_safe, reason)`.
    pub fn validate_pattern_safety(
        &self,
        pattern: &str,
        test_strings: Option<Vec<String>>,
    ) -> (bool, String) {
        let dangerous_patterns = [
            r"\(\.\*\)\+",
            r"\(\.\+\)\+",
            r"\([^)]*\*\)\+",
            r"\([^)]*\+\)\+",
            r"(?:\.\*){2,}",
            r"(?:\.\+){2,}",
        ];

        for dangerous in dangerous_patterns {
            if let Ok(re) = Regex::new(dangerous)
                && re.is_match(pattern)
            {
                return (false, format!("Pattern contains dangerous construct: {dangerous}"));
            }
        }

        let test_strings = test_strings.unwrap_or_else(|| {
            vec![
                "a".repeat(10),
                "a".repeat(100),
                "a".repeat(1000),
                format!("{}{}", "x".repeat(50), "y".repeat(50)),
                format!("{}{}", "<".repeat(100), ">".repeat(100)),
            ]
        });

        let compiled = match Self::build_regex(pattern, RegexFlags::default_flags()) {
            Ok(c) => c,
            Err(e) => return (false, format!("Pattern validation failed: {e}")),
        };

        for test_str in &test_strings {
            let start = Instant::now();
            let _ = compiled.is_match(test_str);
            if start.elapsed() > Duration::from_millis(50) {
                return (
                    false,
                    format!("Pattern timed out on test string of length {}", test_str.len()),
                );
            }
        }

        (true, "Pattern appears safe".into())
    }

    /// Compiles a batch of patterns, optionally validating each one first.
    ///
    /// Returns a map of pattern-source → compiled-regex for every pattern that
    /// passed validation and compilation.
    pub async fn batch_compile(
        &self,
        patterns: &[String],
        validate: bool,
    ) -> HashMap<String, Regex> {
        let mut out = HashMap::new();
        for pattern in patterns {
            if validate {
                let (safe, _) = self.validate_pattern_safety(pattern, None);
                if !safe {
                    continue;
                }
            }
            if let Ok(re) = self.compile_pattern(pattern, RegexFlags::default_flags()).await {
                out.insert(pattern.clone(), re);
            }
        }
        out
    }

    /// Clears the compiled-pattern cache.
    pub async fn clear_cache(&self) {
        let mut guard = self.cache.lock().await;
        guard.compiled.clear();
        guard.order.clear();
    }

    /// Returns the default execution timeout.
    pub const fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Returns the effective cache capacity.
    pub const fn max_cache_size(&self) -> usize {
        self.max_cache_size
    }
}
