use std::sync::LazyLock;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

// visually ambiguous unicode chars mapped to their ASCII equivalents
const LOOKALIKES: &[(char, &str)] = &[
    ('\u{2044}', "/"),
    ('\u{FF0F}', "/"),
    ('\u{29F8}', "/"),
    ('\u{0130}', "I"),
    ('\u{0131}', "i"),
    ('\u{200B}', ""),
    ('\u{200C}', ""),
    ('\u{200D}', ""),
    ('\u{FEFF}', ""),
    ('\u{00AD}', ""),
    ('\u{034F}', ""),
    ('\u{180E}', ""),
    ('\u{2028}', "\n"),
    ('\u{2029}', "\n"),
    ('\u{E000}', ""),
    ('\u{FFF0}', ""),
    ('\u{01C0}', "|"),
    ('\u{037E}', ";"),
    ('\u{2215}', "/"),
    ('\u{2216}', "\\"),
    ('\u{FF1C}', "<"),
    ('\u{FF1E}', ">"),
];

static ATTACK_INDICATORS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let patterns = [
        r"(?i)<script",
        r"(?i)javascript:",
        r"(?i)on\w+=",
        r"(?i)SELECT\s+.{0,50}?\s+FROM",
        r"(?i)UNION\s+SELECT",
        r"\.\./",
        r"(?i)eval\s*\(",
        r"(?i)exec\s*\(",
        r"(?i)system\s*\(",
        r"<\?php",
        r"<%",
        r"\{\{",
        r"\{%",
        r"(?i)<iframe",
        r"(?i)<object",
        r"(?i)<embed",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
        r"\$\{",
        r"\\x[0-9a-fA-F]{2}",
        r"%[0-9a-fA-F]{2}",
    ];
    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
});

/// NFKC normalization + unicode lookalike replacement
/// (fullwidth forms, zero-width characters, etc.).
#[must_use]
pub fn normalize_unicode(content: &str) -> String {
    let normalized: String = content.nfkc().collect();
    let mut result = normalized;

    for &(ch, replacement) in LOOKALIKES {
        if result.contains(ch) {
            result = result.replace(ch, replacement);
        }
    }

    result
}

#[doc(hidden)]
#[must_use]
pub fn collapse_whitespace(content: &str) -> String {
    content.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[doc(hidden)]
#[must_use]
pub fn remove_null_bytes(content: &str) -> String {
    content
        .chars()
        .filter(|&c| {
            let code = c as u32;
            code >= 32 || matches!(code, 9 | 10 | 13)
        })
        .collect()
}

/// Iteratively URL-decode and HTML-unescape
/// (up to 3 rounds to handle double/triple encoding).
#[must_use]
pub fn decode_common_encodings(content: &str) -> String {
    let mut current = content.to_owned();

    for _ in 0..3 {
        let before = current.clone();

        let decoded = percent_encoding::percent_decode_str(&current)
            .decode_utf8_lossy()
            .into_owned();
        if decoded != current {
            current = decoded;
        }

        let unescaped = htmlescape::decode_html(&current).unwrap_or_else(|_| current.clone());
        if unescaped != current {
            current = unescaped;
        }

        if current == before {
            break;
        }
    }
    current
}

/// Scan for attack indicator matches, returning merged `(start, end)`
/// byte regions with 100-char context padding on each side.
#[doc(hidden)]
#[must_use]
pub fn extract_attack_regions(content: &str, max_content_length: usize) -> Vec<(usize, usize)> {
    let max_regions = (max_content_length / 100).min(100);
    let mut regions: Vec<(usize, usize)> = Vec::new();

    for indicator in ATTACK_INDICATORS.iter() {
        for m in indicator.find_iter(content) {
            let start = m.start().saturating_sub(100);
            let end = (m.end() + 100).min(content.len());
            regions.push((start, end));

            if regions.len() >= max_regions {
                break;
            }
        }

        if regions.len() >= max_regions {
            break;
        }
    }

    merge_regions(&mut regions);
    regions.truncate(max_regions);
    regions
}

/// Truncate to `max_length`, giving budget priority to attack regions
/// over surrounding content when `preserve_attacks` is true.
#[doc(hidden)]
#[must_use]
pub fn truncate_safely(content: &str, max_length: usize, preserve_attacks: bool) -> String {
    if content.len() <= max_length {
        return content.to_owned();
    }
    if !preserve_attacks {
        return safe_truncate(content, max_length);
    }

    let regions = extract_attack_regions(content, max_length);
    if regions.is_empty() {
        return safe_truncate(content, max_length);
    }

    let mut budget = max_length;
    let mut attack_slices: Vec<&str> = Vec::with_capacity(regions.len());

    for &(start, end) in &regions {
        let take = (end - start).min(budget);
        attack_slices.push(&content[start..start + take]);
        budget -= take;

        if budget == 0 {
            break;
        }
    }

    let mut gap_slices: Vec<&str> = Vec::new();

    if budget > 0 {
        let mut last_end = 0;
        for &(start, end) in &regions {
            if last_end < start && budget > 0 {
                let take = (start - last_end).min(budget);
                gap_slices.push(&content[last_end..last_end + take]);
                budget -= take;
            }

            last_end = end;
        }
    }

    let mut result = String::with_capacity(max_length);
    let mut gap_iter = gap_slices.iter();

    for slice in &attack_slices {
        if let Some(gap) = gap_iter.next() {
            result.push_str(gap);
        }

        result.push_str(slice);
    }

    for gap in gap_iter {
        result.push_str(gap);
    }

    result
}

/// Full preprocessing pipeline: normalize unicode, decode URL/HTML
/// encodings, strip null bytes, collapse whitespace, truncate.
#[must_use]
pub fn preprocess(content: &str, max_length: usize, preserve_attacks: bool) -> String {
    if content.is_empty() {
        return String::new();
    }

    let mut result = normalize_unicode(content);
    result = decode_common_encodings(&result);
    result = remove_null_bytes(&result);
    result = collapse_whitespace(&result);
    result = truncate_safely(&result, max_length, preserve_attacks);
    result
}

fn safe_truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_owned();
    }

    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    s[..end].to_owned()
}

fn merge_regions(regions: &mut Vec<(usize, usize)>) {
    if regions.len() < 2 {
        return;
    }

    regions.sort_unstable();
    let mut write = 0;

    for read in 1..regions.len() {
        if regions[read].0 <= regions[write].1 {
            regions[write].1 = regions[write].1.max(regions[read].1);
        } else {
            write += 1;
            regions[write] = regions[read];
        }
    }
    
    regions.truncate(write + 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_normalization_basic() {
        assert_eq!(normalize_unicode("\u{FF0F}"), "/");
        assert_eq!(normalize_unicode("\u{200B}test\u{200C}"), "test");
        assert_eq!(normalize_unicode("\u{FF1C}script\u{FF1E}"), "<script>");
    }

    #[test]
    fn unicode_zero_width_removal() {
        let input = format!("<scr{}ipt>", '\u{200B}');
        assert_eq!(normalize_unicode(&input), "<script>");
    }

    #[test]
    fn whitespace_collapsing() {
        assert_eq!(
            collapse_whitespace("test  multiple   spaces"),
            "test multiple spaces"
        );
        assert_eq!(
            collapse_whitespace("test\t\ttabs\n\nnewlines"),
            "test tabs newlines"
        );
        assert_eq!(
            collapse_whitespace("  leading trailing  "),
            "leading trailing"
        );
    }

    #[test]
    fn null_byte_removal() {
        assert_eq!(remove_null_bytes("test\x00null\x00bytes"), "testnullbytes");
        assert_eq!(remove_null_bytes("test\x01\x02control"), "testcontrol");
        // preserves tab, newline, carriage return
        assert_eq!(
            remove_null_bytes("test\ttab\nnewline\rcarriage"),
            "test\ttab\nnewline\rcarriage"
        );
    }

    #[test]
    fn url_decoding() {
        assert_eq!(decode_common_encodings("%3Cscript%3E"), "<script>");
    }

    #[test]
    fn html_decoding() {
        assert_eq!(decode_common_encodings("&lt;script&gt;"), "<script>");
    }

    #[test]
    fn double_encoded() {
        // %253C -> first pass: %3C -> second pass: <
        assert_eq!(decode_common_encodings("%253Cscript%253E"), "<script>");
    }

    #[test]
    fn mixed_encoding() {
        let result = decode_common_encodings("%26lt%3Bscript%26gt%3B");
        assert_eq!(result, "<script>");
    }

    #[test]
    fn attack_region_extraction() {
        let content = "normal text <script>alert(1)</script> more text";
        let regions = extract_attack_regions(content, 10000);
        assert!(!regions.is_empty());
    }

    #[test]
    fn no_attack_regions_in_clean_content() {
        let content = "this is perfectly normal text without any attack patterns";
        let regions = extract_attack_regions(content, 10000);
        assert!(regions.is_empty());
    }

    #[test]
    fn truncate_short_content() {
        let content = "short";
        assert_eq!(truncate_safely(content, 1000, true), "short");
    }

    #[test]
    fn truncate_without_preserve() {
        let content = "a".repeat(100);
        let result = truncate_safely(&content, 50, false);
        assert_eq!(result.len(), 50);
    }

    #[test]
    fn truncate_preserves_attack() {
        // attack near the start so the context window captures it within budget
        let content = format!(
            "{}  <script>alert(1)</script>  {}",
            "a".repeat(50),
            "b".repeat(500)
        );
        let result = truncate_safely(&content, 200, true);
        assert!(result.contains("script"));
    }

    #[test]
    fn truncate_deeply_buried_attack() {
        // attack deep in padding - with enough budget it should still be found
        let content = format!(
            "{}<script>alert(1)</script>{}",
            "a".repeat(500),
            "b".repeat(500)
        );
        let result = truncate_safely(&content, 500, true);
        assert!(result.contains("script"));
    }

    #[test]
    fn full_preprocess_pipeline() {
        let zwsp = '\u{200B}';
        let fullwidth_slash = '\u{FF0F}';
        let content = format!(
            "{zwsp}<script>{fullwidth_slash}alert(1)</script>  multiple   spaces %3Cimg%3E\x00null"
        );
        let result = preprocess(&content, 200, true);

        assert!(!result.contains('\u{200B}'));
        assert!(!result.contains('\u{FF0F}'));
        assert!(!result.contains("  "));
        assert!(result.contains("<img>"));
        assert!(!result.contains('\x00'));
        assert!(result.len() <= 200);
    }

    #[test]
    fn preprocess_empty() {
        assert_eq!(preprocess("", 100, true), "");
    }

    #[test]
    fn xss_bypass_attempt() {
        let input = format!(
            "<scr{}ipt>al{}ert(1)</sc{}ript>",
            '\u{200B}', '\u{200C}', '\u{200D}'
        );
        let result = preprocess(&input, 10000, true);
        assert!(result.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn sql_injection_bypass() {
        let result = preprocess("1' %55NION %53ELECT * FROM users--", 10000, true);
        assert!(result.contains("UNION SELECT"));
    }

    #[test]
    fn merge_overlapping_regions() {
        let mut regions = vec![(0, 10), (5, 15), (20, 30)];
        merge_regions(&mut regions);
        assert_eq!(regions, vec![(0, 15), (20, 30)]);
    }

    #[test]
    fn safe_truncate_multibyte() {
        let content = "hello\u{1F600}world"; // emoji is 4 bytes
        let result = safe_truncate(content, 6);
        assert_eq!(result, "hello");
    }

    #[test]
    fn normalize_lookalike_slash_variants() {
        for (input, expected) in [
            ("\u{2044}", "/"),
            ("\u{FF0F}", "/"),
            ("\u{29F8}", "/"),
            ("\u{0131}", "i"),
            ("\u{200B}", ""),
            ("\u{200C}", ""),
            ("\u{200D}", ""),
            ("\u{FEFF}", ""),
            ("\u{00AD}", ""),
            ("\u{037E}", ";"),
            ("\u{FF1C}", "<"),
            ("\u{FF1E}", ">"),
        ] {
            let result = normalize_unicode(&format!("test{input}test"));
            assert_eq!(
                result,
                format!("test{expected}test"),
                "failed for input char"
            );
        }
    }

    #[test]
    fn normalize_malicious_script() {
        let malicious = format!(
            "<script{}>{}alert(1){}/script>",
            '\u{200B}', '\u{FF0F}', '\u{FF1C}'
        );
        let normalized = normalize_unicode(&malicious);
        assert_eq!(normalized, "<script>/alert(1)</script>");
    }

    #[test]
    fn whitespace_mixed() {
        assert_eq!(
            collapse_whitespace("  mixed\t \n  whitespace  "),
            "mixed whitespace"
        );
    }

    #[test]
    fn null_bytes_preserves_safe_control() {
        let content = "test\ttab\nnewline\rcarriage";
        assert_eq!(remove_null_bytes(content), content);
    }

    #[test]
    fn attack_region_non_overlapping() {
        let content = format!(
            "<script>test</script>{}SELECT * FROM users",
            "x".repeat(500)
        );
        let regions = extract_attack_regions(&content, 10000);
        assert!(regions.len() >= 2);
        assert!(regions[1].0 > regions[0].1);
    }

    #[test]
    fn attack_indicators_match_real_payloads() {
        let test_content = "<script>alert(1)</script> SELECT * FROM users <?php eval() <iframe>";
        let regions = extract_attack_regions(test_content, 10000);
        assert!(!regions.is_empty());
    }

    #[test]
    fn decode_iterations_double() {
        // %253C -> %3C -> <
        assert_eq!(decode_common_encodings("%253Cscript%253E"), "<script>");
    }

    #[test]
    fn decode_html_then_url() {
        assert_eq!(
            decode_common_encodings("%26lt%3Bscript%26gt%3B"),
            "<script>"
        );
    }

    #[test]
    fn preprocess_batch_equivalent() {
        let inputs = ["<script>alert(1)</script>", "%3Cimg%3E", "normal text", ""];
        let results: Vec<String> = inputs.iter().map(|s| preprocess(s, 10000, true)).collect();
        assert_eq!(results.len(), 4);
        assert_eq!(results[0], "<script>alert(1)</script>");
        assert!(results[1].contains("<img>"));
        assert_eq!(results[2], "normal text");
        assert_eq!(results[3], "");
    }

    #[test]
    fn integration_padding_attack() {
        let attack = format!(
            "{}<script>alert(1)</script>{}",
            "a".repeat(50),
            "b".repeat(2000)
        );
        let result = preprocess(&attack, 200, true);
        assert!(result.len() <= 200);
        assert!(result.contains("script"));
    }

    #[test]
    fn fullwidth_unicode_script() {
        let content = "\u{FF53}\u{FF43}\u{FF52}\u{FF49}\u{FF50}\u{FF54}";
        let processed = preprocess(content, 10000, true);
        assert!(processed.to_lowercase().contains("script"));
    }

    #[test]
    fn attack_truncation_preserves_tag() {
        let attack = format!("<script>alert('xss')</script>{}", "a".repeat(10000));
        let processed = preprocess(&attack, 10000, true);
        assert!(processed.contains("<script>"));
        assert!(processed.len() <= 10000);
    }
}
