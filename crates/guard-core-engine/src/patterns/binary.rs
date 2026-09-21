//! Binary artifact density gate and binary-content heuristic, ported from
//! `guard_core/detection_engine/binary_prefix.py` and `semantic.py`
//! (`looks_like_binary_content`), spec 4.0.2.

/// Cumulative artifact-count prefix: `counts[i]` = artifacts in `s[..i]`.
/// Built over code points; indexing is by code-point index (the same space
/// the structural matchers and threat positions use).
#[must_use]
pub fn build_binary_prefix(text: &str) -> Vec<u32> {
    let mut counts = Vec::with_capacity(text.chars().count() + 1);
    counts.push(0u32);
    let mut count = 0u32;
    for c in text.chars() {
        if is_binary_artifact(c) {
            count += 1;
        }
        counts.push(count);
    }
    counts
}

const BINARY_DENSITY_RADIUS: usize = 64;
const BINARY_DENSITY_LIMIT: u32 = 4;

#[must_use]
pub fn match_is_binary_density(
    binary_prefix: &[u32],
    match_start: usize,
    match_end: usize,
) -> bool {
    if binary_prefix.is_empty() {
        return false;
    }
    let high = (match_end + BINARY_DENSITY_RADIUS).min(binary_prefix.len() - 1);
    let low = match_start.saturating_sub(BINARY_DENSITY_RADIUS);
    binary_prefix[high].saturating_sub(binary_prefix[low]) >= BINARY_DENSITY_LIMIT
}

#[must_use]
fn is_binary_artifact(c: char) -> bool {
    let cp = c as u32;
    // control characters (except tab/LF/CR) and DEL
    if (cp < 0x20 && !matches!(cp, 0x09 | 0x0A | 0x0D)) || cp == 0x7F {
        return true;
    }
    // replacement character
    if cp == 0xFFFD {
        return true;
    }
    // surrogateescape byte range (raw undecodable bytes)
    if (0xDC80..=0xDCFF).contains(&cp) {
        return true;
    }
    // Latin-1/Latin-Ext-A artifact, minus the text allowlist
    if (0x80..=0x024F).contains(&cp) {
        return !is_text_allowlist(c);
    }
    false
}

/// The only characters in `0x80..=0x024F` treated as text.
#[must_use]
fn is_text_allowlist(c: char) -> bool {
    let cp = c as u32;
    if (0x00DF..=0x00FF).contains(&cp) && cp != 0x00F7 {
        return true;
    }
    if (0x00C0..=0x00DE).contains(&cp) && cp != 0x00D7 {
        return true;
    }
    if matches!(
        cp,
        0x00A3 | 0x00A5 | 0x00AA | 0x00B0 | 0x00B1 | 0x00B2 | 0x00B3 | 0x00B5 | 0x00B9 | 0x00BA
    ) {
        return true;
    }
    (0x0100..=0x017F).contains(&cp)
}

const BINARY_CONTENT_RATIO_THRESHOLD: f64 = 0.2;

/// `looks_like_binary_content` from semantic.py.
#[must_use]
pub fn looks_like_binary_content(content: &str) -> bool {
    if content.is_empty() {
        return false;
    }
    let mut non_text = 0usize;
    let mut len = 0usize;
    for c in content.chars() {
        len += 1;
        let cp = c as u32;
        let is_ws = matches!(c, '\t' | '\r' | '\n');
        let printable = !c.is_control() && !matches!(cp, 0xFFFD);
        if !is_ws && (!printable || cp == 0xFFFD) {
            non_text += 1;
        }
    }
    let ratio = non_text as f64 / len as f64;
    ratio >= BINARY_CONTENT_RATIO_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_text_has_zero_artifacts() {
        let prefix = build_binary_prefix("hello <script> world\t\n");
        assert_eq!(prefix.last(), Some(&0));
    }

    #[test]
    fn control_bytes_count() {
        let prefix = build_binary_prefix("a\u{1}b\u{2}c\u{3}d\u{4}");
        assert!(match_is_binary_density(&prefix, 0, 8));
    }

    #[test]
    fn accented_text_is_allowed() {
        let prefix = build_binary_prefix("caf\u{00e9} cr\u{00e8}me br\u{00fb}l\u{00e9}");
        assert_eq!(prefix.last(), Some(&0));
    }
}
