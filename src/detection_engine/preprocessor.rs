//! Content preprocessing pipeline applied before pattern matching.
//!
//! [`crate::detection_engine::preprocessor::ContentPreprocessor`] normalises
//! unicode, decodes common encodings, strips null bytes, removes noise, and
//! truncates large payloads while preserving potential attack regions.

use std::time::Duration;

use percent_encoding_like::percent_decode;
use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value, json};
use tokio::time::timeout;
use tracing::error;
use unicode_normalization::UnicodeNormalization;

use crate::protocols::agent::DynAgentHandler;

const ATTACK_INDICATORS: &[&str] = &[
    r"<script",
    r"javascript:",
    r"on\w+=",
    r"SELECT\s+.{0,50}?\s+FROM",
    r"UNION\s+SELECT",
    r"\.\./",
    r"eval\s*\(",
    r"exec\s*\(",
    r"system\s*\(",
    r"<\?php",
    r"<%",
    r"\{\{",
    r"\{%",
    r"<iframe",
    r"<object",
    r"<embed",
    r"onerror\s*=",
    r"onload\s*=",
    r"\$\{",
    r"\\x[0-9a-fA-F]{2}",
    r"%[0-9a-fA-F]{2}",
];

/// Normalises and truncates request content before pattern matching.
///
/// Configuration knobs are surface as public fields so callers can tune size
/// limits and attack-preservation semantics without cloning the struct.
///
/// # Examples
///
/// ```no_run
/// use guard_core_rs::detection_engine::preprocessor::ContentPreprocessor;
///
/// # async fn run() {
/// let pre = ContentPreprocessor::new(10_000, true, None, None);
/// let safe = pre.preprocess("   <Script>alert(1)</Script>   ").await;
/// assert!(safe.contains("script"));
/// # }
/// ```
pub struct ContentPreprocessor {
    /// Maximum length of the output produced by
    /// [`crate::detection_engine::preprocessor::ContentPreprocessor::preprocess`].
    pub max_content_length: usize,
    /// When `true`, truncation preserves regions matching known attack
    /// indicators.
    pub preserve_attack_patterns: bool,
    /// Optional Guard Agent handler used for decoding-error events.
    pub agent_handler: Option<DynAgentHandler>,
    /// Optional correlation id for tracing events.
    pub correlation_id: Option<String>,
    compiled_indicators: Vec<Regex>,
}

impl std::fmt::Debug for ContentPreprocessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentPreprocessor")
            .field("max_content_length", &self.max_content_length)
            .field("preserve_attack_patterns", &self.preserve_attack_patterns)
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

impl Default for ContentPreprocessor {
    fn default() -> Self {
        Self::new(10_000, true, None, None)
    }
}

impl ContentPreprocessor {
    /// Builds a preprocessor with the supplied truncation and attack
    /// preservation settings. Compiles the attack-indicator regexes up front.
    pub fn new(
        max_content_length: usize,
        preserve_attack_patterns: bool,
        agent_handler: Option<DynAgentHandler>,
        correlation_id: Option<String>,
    ) -> Self {
        let compiled_indicators = ATTACK_INDICATORS
            .iter()
            .filter_map(|p| RegexBuilder::new(p).case_insensitive(true).build().ok())
            .collect();
        Self {
            max_content_length,
            preserve_attack_patterns,
            agent_handler,
            correlation_id,
            compiled_indicators,
        }
    }

    async fn send_preprocessor_event(
        &self,
        event_type: &str,
        action_taken: &str,
        reason: &str,
        extra: Map<String, Value>,
    ) {
        let Some(agent) = &self.agent_handler else { return };
        let mut metadata = Map::new();
        metadata.insert("component".into(), json!("ContentPreprocessor"));
        metadata.insert("correlation_id".into(), json!(self.correlation_id));
        for (k, v) in extra {
            metadata.insert(k, v);
        }
        let event = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": event_type,
            "ip_address": "system",
            "action_taken": action_taken,
            "reason": reason,
            "metadata": metadata,
        });
        if let Err(e) = agent.send_event(event).await {
            error!("Failed to send preprocessor event to agent: {e}");
        }
    }

    /// Normalises `content` using NFKC and replaces known Unicode lookalikes
    /// (fullwidth forms, zero-width characters, etc.) with their ASCII
    /// equivalents.
    pub fn normalize_unicode(&self, content: &str) -> String {
        let normalized: String = content.nfkc().collect();
        let lookalikes = [
            ('\u{2044}', "/"),
            ('\u{ff0f}', "/"),
            ('\u{29f8}', "/"),
            ('\u{0130}', "I"),
            ('\u{0131}', "i"),
            ('\u{200b}', ""),
            ('\u{200c}', ""),
            ('\u{200d}', ""),
            ('\u{feff}', ""),
            ('\u{00ad}', ""),
            ('\u{034f}', ""),
            ('\u{180e}', ""),
            ('\u{2028}', "\n"),
            ('\u{2029}', "\n"),
            ('\u{e000}', ""),
            ('\u{fff0}', ""),
            ('\u{01c0}', "|"),
            ('\u{037e}', ";"),
            ('\u{2215}', "/"),
            ('\u{2216}', "\\"),
            ('\u{ff1c}', "<"),
            ('\u{ff1e}', ">"),
        ];
        let mut out = normalized;
        for (ch, replacement) in lookalikes {
            if out.contains(ch) {
                out = out.replace(ch, replacement);
            }
        }
        out
    }

    /// Collapses runs of whitespace to single spaces and trims the result.
    pub fn remove_excessive_whitespace(&self, content: &str) -> String {
        let re = Regex::new(r"\s+").expect("static pattern");
        re.replace_all(content, " ").trim().to_string()
    }

    /// Scans `content` for attack-indicator regions and returns a merged list
    /// of `(start, end)` byte offsets surrounding each hit.
    pub async fn extract_attack_regions(&self, content: &str) -> Vec<(usize, usize)> {
        let max_regions = 100.min(self.max_content_length / 100);
        let mut regions: Vec<(usize, usize)> = Vec::new();
        for indicator in &self.compiled_indicators {
            let indicator = indicator.clone();
            let content_owned = content.to_string();
            let cap = max_regions.saturating_sub(regions.len());
            let found = timeout(
                Duration::from_millis(500),
                tokio::task::spawn_blocking(move || find_regions(&indicator, &content_owned, cap)),
            )
            .await;
            match found {
                Ok(Ok(regs)) => regions.extend(regs),
                _ => continue,
            }
            if regions.len() >= max_regions {
                break;
            }
        }
        if regions.is_empty() {
            return Vec::new();
        }
        regions.sort();
        let mut merged: Vec<(usize, usize)> = vec![regions[0]];
        for (start, end) in regions.into_iter().skip(1) {
            let last = merged.last_mut().expect("non-empty");
            if start <= last.1 {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        merged.truncate(max_regions);
        merged
    }

    fn extract_and_concatenate_attack_regions(
        &self,
        content: &str,
        regions: &[(usize, usize)],
    ) -> String {
        let mut result = String::new();
        let mut remaining = self.max_content_length;
        for (start, end) in regions {
            if remaining == 0 {
                break;
            }
            let available = end.saturating_sub(*start);
            let chunk_len = available.min(remaining);
            let slice_end = (*start + chunk_len).min(content.len());
            result.push_str(&content[*start..slice_end]);
            remaining = remaining.saturating_sub(chunk_len);
        }
        result
    }

    fn build_result_with_regions_and_context(
        &self,
        content: &str,
        regions: &[(usize, usize)],
    ) -> String {
        let attack_length: usize = regions.iter().map(|(s, e)| e.saturating_sub(*s)).sum();
        let mut parts: Vec<String> = regions.iter().map(|(s, e)| content[*s..*e].to_string()).collect();
        let mut remaining = self.max_content_length.saturating_sub(attack_length);

        let mut last_end = 0usize;
        for (start, end) in regions {
            if last_end < *start && remaining > 0 {
                let available = start - last_end;
                let chunk_len = available.min(remaining);
                let non_attack = content[last_end..last_end + chunk_len].to_string();
                parts.insert(0, non_attack);
                remaining = remaining.saturating_sub(chunk_len);
            }
            last_end = *end;
        }
        parts.concat()
    }

    /// Truncates `content` to `max_content_length`, preserving attack regions
    /// when
    /// [`crate::detection_engine::preprocessor::ContentPreprocessor::preserve_attack_patterns`]
    /// is `true`.
    pub async fn truncate_safely(&self, content: &str) -> String {
        if content.len() <= self.max_content_length {
            return content.to_string();
        }
        if !self.preserve_attack_patterns {
            return content[..self.max_content_length].to_string();
        }
        let regions = self.extract_attack_regions(content).await;
        if regions.is_empty() {
            return content[..self.max_content_length].to_string();
        }
        let attack_length: usize = regions.iter().map(|(s, e)| e - s).sum();
        if attack_length >= self.max_content_length {
            return self.extract_and_concatenate_attack_regions(content, &regions);
        }
        self.build_result_with_regions_and_context(content, &regions)
    }

    /// Removes `NUL` bytes and most control characters from `content`.
    pub fn remove_null_bytes(&self, content: &str) -> String {
        let without_nulls = content.replace('\u{0}', "");
        without_nulls
            .chars()
            .filter(|c| *c as u32 >= 32 || *c == '\t' || *c == '\n' || *c == '\r')
            .collect()
    }

    /// Iteratively decodes percent- and HTML-entity encodings up to three
    /// times or until the output stabilises.
    pub async fn decode_common_encodings(&self, content: &str) -> String {
        let max_iterations = 3;
        let mut current = content.to_string();
        for _ in 0..max_iterations {
            let original = current.clone();

            match percent_decode(current.as_bytes()) {
                Ok(decoded) => {
                    if decoded != current {
                        current = decoded;
                    }
                }
                Err(e) => {
                    let mut extra = Map::new();
                    extra.insert("error".into(), json!(e));
                    extra.insert("error_type".into(), json!("url_decode"));
                    self.send_preprocessor_event(
                        "decoding_error",
                        "decode_failed",
                        "Failed to URL decode content",
                        extra,
                    )
                    .await;
                }
            }

            let decoded_html = decode_html_entities(&current);
            if decoded_html != current {
                current = decoded_html;
            }

            if current == original {
                break;
            }
        }
        current
    }

    /// Runs every preprocessing step in order: unicode normalisation, encoding
    /// decoding, null-byte stripping, whitespace collapsing, and safe
    /// truncation.
    pub async fn preprocess(&self, content: &str) -> String {
        if content.is_empty() {
            return String::new();
        }
        let content = self.normalize_unicode(content);
        let content = self.decode_common_encodings(&content).await;
        let content = self.remove_null_bytes(&content);
        let content = self.remove_excessive_whitespace(&content);
        self.truncate_safely(&content).await
    }

    /// Preprocesses every element in `contents` sequentially and returns the
    /// results in order.
    pub async fn preprocess_batch(&self, contents: &[String]) -> Vec<String> {
        let mut out = Vec::with_capacity(contents.len());
        for c in contents {
            out.push(self.preprocess(c).await);
        }
        out
    }
}

fn find_regions(pattern: &Regex, text: &str, cap: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for m in pattern.find_iter(text) {
        if out.len() >= cap {
            break;
        }
        let start = m.start().saturating_sub(100);
        let end = (m.end() + 100).min(text.len());
        out.push((start, end));
    }
    out
}

mod percent_encoding_like {
    pub(super) fn percent_decode(bytes: &[u8]) -> Result<String, String> {
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .map_err(|e| format!("{e}"))?;
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8(out).or_else(|e| Ok(String::from_utf8_lossy(e.as_bytes()).into_owned()))
    }
}

fn decode_html_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            let search_end = bytes.len().min(i + 10);
            if let Some(end) = (i..search_end).find(|&j| bytes[j] == b';')
                && input.is_char_boundary(i + 1)
                && input.is_char_boundary(end)
            {
                let entity = &input[i + 1..end];
                if let Some(decoded) = map_html_entity(entity) {
                    out.push_str(decoded);
                    i = end + 1;
                    continue;
                } else if let Some(stripped) = entity.strip_prefix('#') {
                    if let Some(hex) = stripped.strip_prefix('x').or_else(|| stripped.strip_prefix('X'))
                    {
                        if let Ok(code) = u32::from_str_radix(hex, 16)
                            && let Some(ch) = char::from_u32(code)
                        {
                            out.push(ch);
                            i = end + 1;
                            continue;
                        }
                    } else if let Ok(code) = stripped.parse::<u32>()
                        && let Some(ch) = char::from_u32(code)
                    {
                        out.push(ch);
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn map_html_entity(entity: &str) -> Option<&'static str> {
    match entity {
        "lt" => Some("<"),
        "gt" => Some(">"),
        "amp" => Some("&"),
        "quot" => Some("\""),
        "apos" => Some("'"),
        "nbsp" => Some(" "),
        "copy" => Some("©"),
        "reg" => Some("®"),
        "trade" => Some("™"),
        _ => None,
    }
}
