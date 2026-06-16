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
    patterns
        .iter()
        .map(|p| Regex::new(p).expect("static pattern must compile"))
        .collect()
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

/// Iteratively URL-decode, HTML-unescape, hex/unicode-escape decode,
/// base64-candidate decode, and SQL comment strip (up to 7 rounds).
///
/// Matches Python's 7-stage decode pipeline including SQL block/line comment
/// stripping. Ports stages 1-7 from `guard_core/detection_engine/preprocessor.py`.
#[must_use]
pub fn decode_common_encodings(content: &str) -> String {
    let mut current = content.to_owned();

    for _ in 0..7 {
        let before = current.clone();

        let decoded = percent_encoding::percent_decode_str(&current)
            .decode_utf8_lossy()
            .into_owned();
        if decoded != current {
            current = decoded;
        }

        let unescaped = html_escape::decode_html_entities(&current);
        if unescaped != current {
            current = unescaped.into_owned();
        }

        current = decode_hex_escapes(&current);
        current = decode_unicode_escapes(&current);
        current = decode_base64_candidates(&current);
        current = strip_sql_comments(&current);

        if current == before {
            break;
        }
    }

    current
}

fn decode_hex_escapes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1] == b'x'
            && let Some(b) = from_hex2(bytes[i + 2], bytes[i + 3])
        {
            out.push(b as char);
            i += 4;
            continue;
        }

        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn decode_unicode_escapes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 5 < bytes.len() && bytes[i + 1] == b'u' {
            let h = [bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]];
            if let Some(c) = from_hex4(h).and_then(char::from_u32) {
                out.push(c);
                i += 6;
                continue;
            }
        }

        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn decode_base64_candidates(s: &str) -> String {
    // 8+ non-padding chars = at least 6 decoded bytes; avoids short alphanumeric false positives
    static B64_CANDIDATE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"[A-Za-z0-9+/]{8,}={0,2}").unwrap());

    let mut out = String::with_capacity(s.len());
    let mut last = 0;

    for m in B64_CANDIDATE.find_iter(s) {
        out.push_str(&s[last..m.start()]);
        let candidate = m.as_str();
        let pad_needed = candidate.len().next_multiple_of(4) - candidate.len();
        let mut padded = candidate.to_owned();
        padded.extend(std::iter::repeat_n('=', pad_needed));

        if let Some(decoded) = try_base64_decode(&padded) {
            out.push_str(&decoded);
        } else {
            out.push_str(candidate);
        }

        last = m.end();
    }

    out.push_str(&s[last..]);
    out
}

/// Strip SQL block comments, including inner-word variants (`SEL/**/ECT`).
/// Hand-rolled to avoid lookbehind (not supported by `regex` crate).
fn strip_sql_comments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;

    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            let before_letter = i > 0 && bytes[i - 1].is_ascii_alphabetic();
            if let Some(close) = bytes[i + 2..].windows(2).position(|w| w == b"*/") {
                let after_pos = i + 2 + close + 2;
                let after_letter =
                    after_pos < bytes.len() && bytes[after_pos].is_ascii_alphabetic();

                // inner-word comment: letter/*...*/letter -> remove (no space)
                // standalone comment: replace with space to avoid word-joining
                if !(before_letter && after_letter) {
                    out.push(' ');
                }

                i = after_pos;
                continue;
            }
        }
        if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] == b'-' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn from_hex2(hi: u8, lo: u8) -> Option<u8> {
    let h = from_hex_digit(hi)?;
    let l = from_hex_digit(lo)?;
    Some((h << 4) | l)
}

fn from_hex4(digits: [u8; 4]) -> Option<u32> {
    let mut v: u32 = 0;
    for d in digits {
        v = (v << 4) | u32::from(from_hex_digit(d)?);
    }
    Some(v)
}

const fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 255 = invalid, 254 = padding (`=`)
const B64_TABLE: [u8; 256] = {
    let mut t = [255u8; 256];
    let mut i = 0u8;
    loop {
        t[i as usize] = match i {
            b'A'..=b'Z' => i - b'A',
            b'a'..=b'z' => i - b'a' + 26,
            b'0'..=b'9' => i - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 254,
            _ => 255,
        };
        if i == 255 {
            break;
        }
        i += 1;
    }
    t
};

fn try_base64_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;

    while i < bytes.len() {
        let v = [
            B64_TABLE[bytes[i] as usize],
            B64_TABLE[bytes[i + 1] as usize],
            B64_TABLE[bytes[i + 2] as usize],
            B64_TABLE[bytes[i + 3] as usize],
        ];
        if v[0] == 255 || v[1] == 255 {
            return None;
        }

        out.push((v[0] << 2) | (v[1] >> 4));
        if v[2] != 254 {
            if v[2] == 255 {
                return None;
            }
            out.push((v[1] << 4) | (v[2] >> 2));
        }
        if v[3] != 254 {
            if v[3] == 255 {
                return None;
            }
            out.push((v[2] << 6) | v[3]);
        }

        i += 4;
    }

    // only replace if decoded content is printable ASCII (same heuristic as Python)
    if out.iter().all(|&b| (0x20u8..0x7f).contains(&b)) {
        String::from_utf8(out).ok()
    } else {
        None
    }
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
            let start = content.floor_char_boundary(m.start().saturating_sub(100));
            let end = content.ceil_char_boundary(m.end() + 100);
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
        let slice_end = content.floor_char_boundary(start + take);
        attack_slices.push(&content[start..slice_end]);
        budget -= slice_end - start;

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
                let slice_end = content.floor_char_boundary(last_end + take);
                gap_slices.push(&content[last_end..slice_end]);
                budget -= slice_end - last_end;
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
    s[..s.floor_char_boundary(max_len)].to_owned()
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
    fn unicode_normalization() {
        assert_eq!(normalize_unicode("\u{FF0F}"), "/");
        assert_eq!(normalize_unicode("\u{200B}test\u{200C}"), "test");
        assert_eq!(normalize_unicode("\u{FF1C}script\u{FF1E}"), "<script>");
        // comprehensive lookalike table
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
                "failed for {input:?}"
            );
        }

        // zero-width chars inside tag name
        let malicious = format!(
            "<script{}>{}alert(1){}/script>",
            '\u{200B}', '\u{FF0F}', '\u{FF1C}'
        );
        assert_eq!(normalize_unicode(&malicious), "<script>/alert(1)</script>");
    }

    #[test]
    fn whitespace_and_null_bytes() {
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

        assert_eq!(remove_null_bytes("test\x00null\x00bytes"), "testnullbytes");
        assert_eq!(remove_null_bytes("test\x01\x02control"), "testcontrol");

        // preserves tab, newline, carriage return
        let safe = "test\ttab\nnewline\rcarriage";
        assert_eq!(remove_null_bytes(safe), safe);
    }

    #[test]
    fn decode_common_encodings_variants() {
        // URL
        assert_eq!(decode_common_encodings("%3Cscript%3E"), "<script>");
        // HTML
        assert_eq!(decode_common_encodings("&lt;script&gt;"), "<script>");
        // double-encoded: %253C -> %3C -> <
        assert_eq!(decode_common_encodings("%253Cscript%253E"), "<script>");
        // URL-encoded HTML entity: %26lt%3B -> &lt; -> <
        assert_eq!(
            decode_common_encodings("%26lt%3Bscript%26gt%3B"),
            "<script>"
        );
        // hex escape
        assert_eq!(decode_common_encodings(r"\x3Cscript\x3E"), "<script>");
        // SQL block comments
        let r = decode_common_encodings("SEL/**/ECT * FR/**/OM users");
        assert!(r.contains("SELECT") && r.contains("FROM"), "got: {r}");
        // SQL line comment
        assert!(!decode_common_encodings("' OR 1=1-- comment").contains("-- comment"));
    }

    #[test]
    fn decode_helpers_standalone() {
        assert_eq!(decode_hex_escapes(r"\x3Cscript\x3E"), "<script>");
        // base64("<script>") = "PHNjcmlwdD4="
        assert_eq!(decode_base64_candidates("PHNjcmlwdD4="), "<script>");
        assert_eq!(
            strip_sql_comments("SEL/**/ECT * FR/**/OM users"),
            "SELECT * FROM users"
        );
        assert!(!strip_sql_comments("' OR 1=1-- comment").contains("-- comment"));
        assert!(!strip_sql_comments("' OR 1=1# comment").contains("# comment"));
    }

    #[test]
    fn attack_regions() {
        // detects attacks, clean content has none
        assert!(
            !extract_attack_regions("normal text <script>alert(1)</script> more text", 10000)
                .is_empty()
        );
        assert!(extract_attack_regions("this is perfectly normal text", 10000).is_empty());

        // two distant attacks produce two non-overlapping regions
        let content = format!(
            "<script>test</script>{}SELECT * FROM users",
            "x".repeat(500)
        );
        let regions = extract_attack_regions(&content, 10000);
        assert!(regions.len() >= 2);
        assert!(regions[1].0 > regions[0].1);
    }

    #[test]
    fn truncate_safely_variants() {
        // no-op when under limit
        assert_eq!(truncate_safely("short", 1000, true), "short");
        // simple truncation
        assert_eq!(truncate_safely(&"a".repeat(100), 50, false).len(), 50);

        // preserve_attacks keeps script tag visible
        let content = format!(
            "{}  <script>alert(1)</script>  {}",
            "a".repeat(50),
            "b".repeat(500)
        );
        assert!(truncate_safely(&content, 200, true).contains("script"));

        // buried attack
        let content = format!(
            "{}<script>alert(1)</script>{}",
            "a".repeat(500),
            "b".repeat(500)
        );
        assert!(truncate_safely(&content, 500, true).contains("script"));

        // multibyte: doesn't panic, result is non-empty
        let pad = "\u{1F600}".repeat(40);
        let content = format!("{pad}<script>alert(1)</script>{pad}");
        assert!(!truncate_safely(&content, 100, true).is_empty());
    }

    #[test]
    fn safe_truncate_multibyte() {
        // emoji is 4 bytes — must not split it
        assert_eq!(safe_truncate("hello\u{1F600}world", 6), "hello");
    }

    #[test]
    fn merge_overlapping_regions() {
        let mut regions = vec![(0, 10), (5, 15), (20, 30)];
        merge_regions(&mut regions);
        assert_eq!(regions, vec![(0, 15), (20, 30)]);
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
    fn preprocess_xss_bypass() {
        let input = format!(
            "<scr{}ipt>al{}ert(1)</sc{}ript>",
            '\u{200B}', '\u{200C}', '\u{200D}'
        );
        assert!(preprocess(&input, 10000, true).contains("<script>alert(1)</script>"));
    }

    #[test]
    fn preprocess_sql_bypass() {
        assert!(
            preprocess("1' %55NION %53ELECT * FROM users--", 10000, true).contains("UNION SELECT")
        );
    }

    #[test]
    fn preprocess_batch_and_multibyte() {
        // batch equivalence
        let inputs = ["<script>alert(1)</script>", "%3Cimg%3E", "normal text", ""];
        let results: Vec<String> = inputs.iter().map(|s| preprocess(s, 10000, true)).collect();
        assert_eq!(results[0], "<script>alert(1)</script>");
        assert!(results[1].contains("<img>"));
        assert_eq!(results[2], "normal text");
        assert_eq!(results[3], "");

        // multibyte content at region edges must not panic
        let pad = "\u{1F600}".repeat(50);
        let content = format!("{pad}<script>alert(1)</script>{pad}");
        let r = preprocess(&content, 200, true);
        assert!(!r.is_empty());

        // attack region boundary chars must be valid
        let pad = "\u{1F600}".repeat(40);
        let content = format!("{pad}<script>alert(1)</script>{pad}");
        for &(s, e) in &extract_attack_regions(&content, 10_000) {
            assert!(content.is_char_boundary(s), "start {s} not boundary");
            assert!(content.is_char_boundary(e), "end {e} not boundary");
        }
    }

    #[test]
    fn fullwidth_unicode_script() {
        let content = "\u{FF53}\u{FF43}\u{FF52}\u{FF49}\u{FF50}\u{FF54}";
        assert!(
            preprocess(content, 10000, true)
                .to_lowercase()
                .contains("script")
        );
    }
}
