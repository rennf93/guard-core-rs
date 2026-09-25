//! File-upload matchers ported from
//! `guard_core/handlers/_suspatterns_file_upload.py` (spec 4.0.2).
//!
//! All four patterns anchor on a `filename = "<quoted>"` token whose boundary
//! is located by walking back over whitespace to a required boundary char.
//! The dangerous-extension marker carries a `(?![A-Za-z0-9])` guard; the
//! guard is enforced with per-branch suffix checks in the reference's
//! alternation order (`php\d*` first with digit backtracking, then the
//! literal branches), which reproduces the lookahead exactly.

use super::chars_util::{char_at, char_before};
use super::pyregex::Candidate;

/// Dangerous extension alternation with `com` (terminal-extension pattern).
pub const DANGEROUS_EXT: &[&str] = &[
    "phtml", "shtml", "asax", "ascx", "ashx", "asmx", "aspx", "bash", "jspx", "phar", "phps",
    "asa", "asp", "bat", "cer", "cfc", "cfm", "cgi", "cmd", "com", "exe", "hta", "jsp", "msi",
    "pht", "vbe", "vbs", "war", "wsf", "js", "pl", "py", "rb", "sh", "ws",
];

/// Dangerous extension alternation for the double-extension marker (no `com`).
pub const DOUBLE_EXT: &[&str] = &[
    "phtml", "shtml", "asax", "ascx", "ashx", "asmx", "aspx", "bash", "jspx", "phar", "phps",
    "asa", "asp", "bat", "cer", "cfc", "cfm", "cgi", "cmd", "exe", "hta", "jsp", "msi", "pht",
    "vbe", "vbs", "war", "wsf", "js", "pl", "py", "rb", "sh", "ws",
];

/// Benign terminal extensions for the double-extension shape.
pub const BENIGN_TERMINAL: &[&str] = &[
    "docx", "jpeg", "pptx", "tiff", "webm", "webp", "xlsx", "avi", "bmp", "doc", "gif", "ico",
    "jpg", "mkv", "mov", "mp3", "mp4", "odt", "pdf", "png", "ppt", "svg", "tif", "wav", "xls",
];

const fn is_whitespace(c: char) -> bool {
    c.is_whitespace()
}

/// ASCII case-folded `starts_with` at a byte position: the reference's builtin
/// `re.IGNORECASE` folding for the row's extension literals.
fn ascii_starts_with_ignore_case(haystack: &str, pos: usize, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let Some(window) = bytes.get(pos..pos + needle.len()) else {
        return false;
    };
    window
        .iter()
        .zip(needle.bytes())
        .all(|(a, b)| a.eq_ignore_ascii_case(&b))
}

/// Anchored-`pos` matcher for `\.(?:php\d*|<alternation>)(?![A-Za-z0-9])`.
///
/// Returns the marker end. Branches are tried in reference order with the
/// `php\d*` digit backtracking; the lookahead is a suffix check per branch.
/// The row carries the reference's builtin IGNORECASE, so the extension
/// literals fold ASCII case.
#[must_use]
pub fn dangerous_marker_at(body: &str, pos: usize, extensions: &[&str]) -> Option<usize> {
    if char_at(body, pos).map(|(_, c)| c) != Some('.') {
        return None;
    }
    let after_dot = pos + 1;
    // branch 1: php\d* with backtracking over the greedy digits
    if ascii_starts_with_ignore_case(body, after_dot, "php") {
        let mut end = after_dot + 3;
        while char_at(body, end).is_some_and(|(_, c)| c.is_ascii_digit()) {
            end += 1;
        }
        loop {
            if char_at(body, end).is_none_or(|(_, c)| !c.is_ascii_alphanumeric()) {
                return Some(end);
            }
            if end == after_dot + 3 {
                break;
            }
            end -= 1;
        }
    }
    for ext in extensions {
        let end = after_dot + ext.len();
        if ascii_starts_with_ignore_case(body, after_dot, ext)
            && char_at(body, end).is_none_or(|(_, c)| !c.is_ascii_alphanumeric())
        {
            return Some(end);
        }
    }
    None
}

/// `\.(?:php\d*|<alternation>)\Z` on the body (case-insensitive).
fn terminal_extension(body: &str, extensions: &[&str], include_php_digits: bool) -> bool {
    let Some(dot) = body.rfind('.') else {
        return false;
    };
    let tail = &body[dot + 1..];
    if tail.is_empty() {
        return false;
    }
    if tail.eq_ignore_ascii_case("php") {
        return true;
    }
    if include_php_digits
        && tail.len() > 3
        && tail[..3].eq_ignore_ascii_case("php")
        && tail[3..].bytes().all(|b| b.is_ascii_digit())
    {
        return true;
    }
    extensions.iter().any(|ext| tail.eq_ignore_ascii_case(ext))
}

fn benign_terminal(body: &str) -> bool {
    let Some(dot) = body.rfind('.') else {
        return false;
    };
    let tail = &body[dot + 1..];
    BENIGN_TERMINAL
        .iter()
        .any(|ext| tail.eq_ignore_ascii_case(ext))
}

fn is_double_extension(body: &str) -> bool {
    if !benign_terminal(body) {
        return false;
    }
    let Some(final_dot) = body.rfind('.') else {
        return false;
    };
    for (idx, c) in body.char_indices() {
        if c != '.' || idx >= final_dot {
            continue;
        }
        let Some(marker_end) = dangerous_marker_at(body, idx, DOUBLE_EXT) else {
            continue;
        };
        if marker_end > final_dot {
            continue;
        }
        let suffix_ok =
            char_at(body, marker_end).is_none_or(|(_, c)| !matches!(c, ' ' | '"' | '\''));
        if marker_end == final_dot || (marker_end < final_dot && suffix_ok) {
            return true;
        }
    }
    false
}

/// Truncation marker: `(?:%00|\u0000|\x00|\0|<NUL>|;)` raw, `(?:<NUL>|;)`
/// decoded, each also allowing `.` + end of body.
fn truncation_marker_at(body: &str, pos: usize, decoded: bool) -> bool {
    if pos > body.len() {
        return false;
    }
    if pos == body.len() - 1 && body.as_bytes()[pos] == b'.' {
        return true;
    }
    if decoded {
        return body[pos..].starts_with('\u{0}') || body[pos..].starts_with(';');
    }
    body[pos..].starts_with("%00")
        // the `\u0000`/`\x00` escape texts fold case under the row's builtin
        // IGNORECASE (`\U0000`, `\X00`)
        || ascii_starts_with_ignore_case(body, pos, r"\u0000")
        || ascii_starts_with_ignore_case(body, pos, r"\x00")
        || body[pos..].starts_with(r"\0")
        || body[pos..].starts_with('\u{0}')
        || body[pos..].starts_with(';')
}

fn is_truncation(body: &str, decoded: bool) -> bool {
    for (idx, c) in body.char_indices() {
        if c != '.' {
            continue;
        }
        let Some(marker_end) = dangerous_marker_at(body, idx, DOUBLE_EXT) else {
            continue;
        };
        if truncation_marker_at(body, marker_end, decoded) {
            return true;
        }
    }
    false
}

fn kind_matches(
    body: &str,
    source: &str,
    dangerous_source: &str,
    double_source: &str,
    trunc_source: &str,
    decoded_trunc_source: &str,
) -> bool {
    if source == dangerous_source {
        return terminal_extension(body, DANGEROUS_EXT, true);
    }
    if source == double_source {
        return is_double_extension(body);
    }
    if source == trunc_source {
        return is_truncation(body, false);
    }
    if source == decoded_trunc_source {
        return is_truncation(body, true);
    }
    false
}

fn file_upload_match_start(content: &str, filename_start: usize) -> Option<usize> {
    let mut cursor = filename_start;
    let mut first_newline: Option<usize> = None;
    loop {
        if cursor == 0 {
            return Some(0);
        }
        let Some((i, c)) = char_before(content, cursor) else {
            return Some(0);
        };
        if is_whitespace(c) {
            if c == '\n' {
                first_newline = Some(i);
            }
            cursor = i;
            continue;
        }
        if matches!(c, ';' | ',' | ':' | '\n') {
            return Some(i);
        }
        return first_newline;
    }
}

fn skip_whitespace(content: &str, mut cursor: usize) -> usize {
    while let Some((i, c)) = char_at(content, cursor)
        && is_whitespace(c)
    {
        cursor = i + c.len_utf8();
    }
    cursor
}

fn quoted_candidate(content: &str, filename_start: usize) -> Option<(usize, usize, usize)> {
    let match_start = file_upload_match_start(content, filename_start)?;
    let mut cursor = skip_whitespace(content, filename_start + "filename".len());
    if char_at(content, cursor).map(|(_, c)| c) != Some('=') {
        return None;
    }
    cursor = skip_whitespace(content, cursor + 1);
    let open = char_at(content, cursor).map(|(_, c)| c)?;
    if open != '"' && open != '\'' {
        return None;
    }
    let body_start = cursor + 1;
    let tail = &content[body_start..];
    let quote_index = tail.find(['"', '\''])?;
    Some((match_start, body_start, body_start + quote_index + 1))
}

/// `_file_upload_scan_matches`: candidates from `filename` tokens, classified
/// per pattern; the emitted match spans the validated `[match_start, end)`.
#[must_use]
pub fn file_upload_scan_matches(
    content: &str,
    source: &str,
    dangerous_source: &str,
    double_source: &str,
    trunc_source: &str,
    decoded_trunc_source: &str,
) -> Vec<Candidate> {
    let mut matches = Vec::new();
    let Ok(filename_re) = super::pyregex::PyRegex::compile("(?i)filename", false) else {
        return matches;
    };
    let mut last_end = 0usize;
    for m in filename_re.re().find_iter(content) {
        let Some((start, body_start, end)) = quoted_candidate(content, m.start()) else {
            continue;
        };
        if start < last_end {
            continue;
        }
        let body = &content[body_start..end - 1];
        if !kind_matches(
            body,
            source,
            dangerous_source,
            double_source,
            trunc_source,
            decoded_trunc_source,
        ) {
            continue;
        }
        matches.push(Candidate::new(start, end));
        last_end = end;
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    const DANGEROUS: &str = "DANGEROUS";
    const DOUBLE: &str = "DOUBLE";
    const TRUNC: &str = "TRUNC";
    const DECODED_TRUNC: &str = "DECODED_TRUNC";

    #[test]
    fn dangerous_extension_fires() {
        let ms = file_upload_scan_matches(
            "; filename=\"shell.php\"",
            DANGEROUS,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
        assert_eq!(
            ms[0].text("; filename=\"shell.php\""),
            "; filename=\"shell.php\""
        );
    }

    #[test]
    fn double_extension_fires() {
        let ms = file_upload_scan_matches(
            "filename=\"report.php.jpg\"",
            DOUBLE,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn plain_image_is_benign() {
        assert!(
            file_upload_scan_matches(
                "filename=\"photo.jpg\"",
                DOUBLE,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
        assert!(
            file_upload_scan_matches(
                "filename=\"doc.pdf\"",
                DANGEROUS,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
    }

    #[test]
    fn truncation_fires() {
        let ms = file_upload_scan_matches(
            "filename=\"shell.php%00.jpg\"",
            TRUNC,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
        let ms = file_upload_scan_matches(
            "filename=\"shell.php;.jpg\"",
            TRUNC,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn phps_branch_reached_after_php_digits() {
        // php\d* fails via the alnum suffix check; the phps branch must win
        let ms = file_upload_scan_matches(
            "filename=\"x.phps.jpg\"",
            DOUBLE,
            DANGEROUS,
            DOUBLE,
            TRUNC,
            DECODED_TRUNC,
        );
        assert_eq!(ms.len(), 1);
    }

    #[test]
    fn filename_needs_boundary() {
        // "myfilename" has no boundary before `filename` at offset 2
        assert!(
            file_upload_scan_matches(
                "myfilename=\"shell.php\"",
                DANGEROUS,
                DANGEROUS,
                DOUBLE,
                TRUNC,
                DECODED_TRUNC
            )
            .is_empty()
        );
    }
}
