//! Binary islands reduction, ported from `guard_core/detection_engine/
//! binary_islands.py` (upstream commit 5f399234).
//!
//! A multipart file-part payload whose binary artifact characters fill at
//! least a fifth of it is reduced to its printable runs before pattern
//! scanning: compressed or encrypted upload bytes stop producing attack-shaped
//! matches whose rate grows with file size, while text genuinely embedded in
//! an upload (a script inside a PDF, a stored path inside an archive) forms
//! printable runs past the minimum length and is still scanned in full.
//!
//! String model: like the binary artifact gate ([`crate::patterns::binary`]),
//! artifact classes are evaluated over decoded code points. Invalid UTF-8
//! bytes of an engine body surface as U+FFFD at the decode boundary (Python
//! decodes with surrogateescape, so one binary byte is one surrogate rune
//! there and one U+FFFD per maximal invalid run here); U+FFFD is part of the
//! artifact class and is excluded from the printable-run class, so binary
//! bytes end islands exactly like the surrogateescape range does in Python.

/// `_BINARY_LIKE_ARTIFACT_RATIO`: a payload is binary-like when artifact
/// characters make up at least this fraction of it.
pub const BINARY_LIKE_ARTIFACT_RATIO: f64 = 0.2;

/// `value_is_binary_like`: the artifact-character ratio of the content
/// reaches [`BINARY_LIKE_ARTIFACT_RATIO`].
#[must_use]
pub fn value_is_binary_like(content: &str) -> bool {
    if content.is_empty() {
        return false;
    }
    let total = content.chars().count();
    let artifacts = content
        .chars()
        .filter(|c| crate::patterns::binary::is_binary_artifact(*c))
        .count();
    (artifacts as f64) / (total as f64) >= BINARY_LIKE_ARTIFACT_RATIO
}

/// Whether `r` belongs to the island run class `_ISLAND_RUN_RE` from
/// `guard_core/detection_engine/binary_islands.py`.
///
/// That class is tab, newline, carriage return, printable ASCII, and the wide
/// non-control Unicode ranges. The Unicode replacement character (and every
/// other artifact) is excluded, so binary bytes end a run.
#[must_use]
pub fn printable_island_rune(r: char) -> bool {
    let cp = r as u32;
    matches!(cp, 0x09 | 0x0A | 0x0D)
        || (0x20..=0x7E).contains(&cp)
        || (0xA1..=0xD7FF).contains(&cp)
        || (0xE000..=0xFFFC).contains(&cp)
        || (0xFFFE..=0xFFFF).contains(&cp)
        || (0x1_0000..=0x10_FFFF).contains(&cp)
}

/// `extract_binary_islands`: the maximal printable runs of the content whose
/// code-point length reaches `min_run_length`, in order.
///
/// A minimum of 1 or below keeps the whole content (the reference returns
/// `[content]`).
#[must_use]
pub fn extract_binary_islands(content: &str, min_run_length: usize) -> Vec<&str> {
    if min_run_length <= 1 {
        return vec![content];
    }
    let mut islands = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut run_len = 0_usize;
    for (offset, r) in content.char_indices() {
        if printable_island_rune(r) {
            if run_start.is_none() {
                run_start = Some(offset);
            }
            run_len += 1;
            continue;
        }
        if let Some(start) = run_start
            && run_len >= min_run_length
        {
            islands.push(&content[start..offset]);
        }
        run_start = None;
        run_len = 0;
    }
    if let Some(start) = run_start
        && run_len >= min_run_length
    {
        islands.push(&content[start..]);
    }
    islands
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Python tests decode binary fixtures with surrogateescape; the
    // engine's string model maps undecodable bytes to U+FFFD at the decode
    // boundary, so the fixtures here embed U+FFFD (or ASCII control bytes,
    // which are artifacts too) directly.

    #[test]
    fn extract_keeps_runs_at_or_above_min_length() {
        let content = "\u{FFFD}abc\u{FFFD}".to_owned() + &"x".repeat(16) + "\u{FFFD}def\u{FFFD}";
        assert_eq!(extract_binary_islands(&content, 16), vec!["x".repeat(16)]);
    }

    #[test]
    fn extract_returns_runs_separately() {
        let content =
            "\u{FFFD}".to_owned() + &"a".repeat(16) + "\u{FFFD}" + &"b".repeat(16) + "\u{FFFD}";
        assert_eq!(
            extract_binary_islands(&content, 16),
            vec!["a".repeat(16), "b".repeat(16)]
        );
    }

    #[test]
    fn extract_preserves_non_ascii_text_runs() {
        let text = "Caf\u{e9} r\u{e9}sum\u{e9} na\u{ef}ve d\u{e9}cor s\u{e9}lection";
        assert_eq!(extract_binary_islands(text, 16), vec![text]);
    }

    #[test]
    fn extract_below_min_run_length_returns_content() {
        let content = "anything\u{0}at all";
        assert_eq!(extract_binary_islands(content, 1), vec![content]);
    }

    #[test]
    fn extract_keeps_tab_newline_carriage_return_inside_runs() {
        let content = "\u{0}select 1\nfrom t\r\nwhere x=1\u{0}";
        assert_eq!(
            extract_binary_islands(content, 16),
            vec!["select 1\nfrom t\r\nwhere x=1"]
        );
    }

    #[test]
    fn binary_like_rejects_text_and_accepts_noise() {
        assert!(!value_is_binary_like(""));
        assert!(!value_is_binary_like(
            "plain text body with attack 1 OR 1=1"
        ));
        assert!(!value_is_binary_like("one null\u{0}byte"));
        assert!(value_is_binary_like(&noise_string(7, 4096)));
    }

    #[test]
    fn replacement_character_is_an_artifact_and_ends_runs() {
        // U+FFFD counts toward the artifact ratio ...
        assert!(value_is_binary_like(&("\u{FFFD}".repeat(2) + "ab")));
        // ... and is excluded from the printable-run class (the Python class
        // deliberately skips U+FFFD: its run range is E000..FFFC, FFFE..).
        let content = "a".repeat(16);
        let islands = extract_binary_islands(&content, 16);
        assert_eq!(islands, vec!["a".repeat(16)]);
        let split = "\u{FFFD}x".repeat(16);
        assert!(extract_binary_islands(&split, 16).is_empty());
    }

    /// Deterministic pseudo-random "noise" text: the engine's string model of
    /// random raw bytes (ASCII bytes pass through, with the control range
    /// counting as artifacts; every other byte decodes to U+FFFD, also an
    /// artifact).
    fn noise_string(seed: u64, size: usize) -> String {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1);
        let mut out = String::with_capacity(size);
        for _ in 0..size {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let byte = (state % 256) as u8;
            if byte < 0x80 {
                out.push(byte as char);
            } else {
                out.push('\u{FFFD}');
            }
        }
        out
    }
}
