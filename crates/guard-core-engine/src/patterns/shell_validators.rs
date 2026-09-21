//! Candidate-rejection validators ported from
//! `guard_core/handlers/_suspatterns_shell_validators.py` (spec 4.0.2).
//!
//! A validator receives a candidate match plus the detection context and
//! decides whether the match is a true injection; returning false rejects the
//! candidate and lets the scan continue with later matches.

use super::chars_util::char_before;
use super::pyregex::PyRegex;

pub const AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS: &[&str] = &["query_param", "url_path"];

const STRONG_SQL_KEYWORD_GLUED_PREFIX_RE: &str =
    r"\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|GROUP\s+BY)\z";
const STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE: &str =
    r"\A(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|GROUP\s+BY)\b";
const BARE_SHELL_PARAMETER_NAME_RE: &str =
    r"\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\z";

const BACKTICK_WINDOW_DELIMITERS: &[char] = &['`', '\'', '"', '\n', '\r'];

const fn is_ascii_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn shell_text_is_printable_ascii(token: &str) -> bool {
    token
        .chars()
        .all(|c| c == '\t' || ('\u{20}'..='\u{7e}').contains(&c))
}

#[allow(clippy::missing_const_for_fn)] // clippy version drift: newer lints flag these
fn backtick_token_has_chained_shell_operators(token: &str) -> bool {
    let mut count = 0usize;
    let bytes = token.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b';' => {
                count += 1;
                i += 1;
            }
            b'|' | b'&' => {
                count += 1;
                if i + 1 < bytes.len() && bytes[i + 1] == bytes[i] {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    count >= 2
}

fn backtick_pair_glued(content: &str, start: usize, end: usize) -> bool {
    let prefix_glued =
        start > 0 && char_before(content, start).is_some_and(|(_, c)| is_ascii_word(c));
    let suffix_glued = content[end..].chars().next().is_some_and(is_ascii_word);
    prefix_glued || suffix_glued
}

const BACKTICK_CLAUSE_BOUNDARY_CHARS: &[char] = &['.', '!', '?', ';', '&', '|'];

fn backtick_pair_tail_anchored(content: &str, end: usize) -> bool {
    content[end..].trim().is_empty()
}

fn backtick_pair_clause_initial(content: &str, start: usize) -> bool {
    if start == 0 {
        return false;
    }
    if !char_before(content, start).is_some_and(|(_, c)| matches!(c, ' ' | '\t' | '\r' | '\n')) {
        return false;
    }
    let prefix = content[..start].trim_end();
    if prefix.is_empty() {
        return false;
    }
    prefix
        .chars()
        .next_back()
        .is_some_and(|c| BACKTICK_CLAUSE_BOUNDARY_CHARS.contains(&c))
}

fn backtick_pair_appended_clause(content: &str, start: usize, end: usize) -> bool {
    backtick_pair_tail_anchored(content, end) && backtick_pair_clause_initial(content, start)
}

fn backtick_window_start(content: &str, position: usize) -> usize {
    let mut index = position;
    while index > 0
        && char_before(content, index)
            .is_some_and(|(_, c)| !BACKTICK_WINDOW_DELIMITERS.contains(&c))
    {
        index = char_before(content, index).map_or(0, |(i, _)| i);
    }
    index
}

fn backtick_window_end(content: &str, position: usize) -> usize {
    content[position..]
        .char_indices()
        .find(|(_, c)| BACKTICK_WINDOW_DELIMITERS.contains(c))
        .map_or(content.len(), |(i, _)| position + i)
}

fn backtick_pair_context_window(content: &str, start: usize, end: usize) -> &str {
    let window_start = backtick_window_start(content, start);
    let window_end = backtick_window_end(content, end);
    &content[window_start..window_end]
}

fn token_is_implausible_sql_identifier(token: &str) -> bool {
    // [\s/.;|&$()]
    token.chars().any(|c| {
        matches!(
            c,
            ' ' | '\t'
                | '\n'
                | '\r'
                | '\x0b'
                | '\x0c'
                | '/'
                | '.'
                | ';'
                | '|'
                | '&'
                | '$'
                | '('
                | ')'
        )
    })
}

fn strong_sql_keyword_glued_to_pair(content: &str, start: usize, end: usize) -> bool {
    let window_start = backtick_window_start(content, start);
    let window_end = backtick_window_end(content, end);
    let prefix = &content[window_start..start];
    let suffix = &content[end..window_end];
    let Ok(prefix_re) = PyRegex::compile(STRONG_SQL_KEYWORD_GLUED_PREFIX_RE, true) else {
        return false;
    };
    if prefix_re.re().is_match(prefix) {
        return true;
    }
    let Ok(suffix_re) = PyRegex::compile(STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE, true) else {
        return false;
    };
    suffix_re.re().is_match(suffix)
}

/// `_glued_backtick_pair_is_injection`.
#[must_use]
pub fn glued_backtick_pair_is_injection(
    content: &str,
    candidate: super::pyregex::Candidate,
    request_context: &str,
) -> bool {
    let start = candidate.start;
    let end = candidate.end;
    let token = &content[start + 1..end - 1];
    if !shell_text_is_printable_ascii(token) {
        return false;
    }
    if backtick_token_has_chained_shell_operators(token) {
        return true;
    }
    let appended_clause = backtick_pair_appended_clause(content, start, end);
    if !backtick_pair_glued(content, start, end) && !appended_clause {
        return false;
    }
    if token_is_implausible_sql_identifier(token) {
        return true;
    }
    let window = backtick_pair_context_window(content, start, end);
    if shell_metacharacter_window(window) {
        return true;
    }
    if strong_sql_keyword_glued_to_pair(content, start, end) {
        return false;
    }
    let normalized = request_context.split(':').next().unwrap_or(request_context);
    AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS.contains(&normalized) || appended_clause
}

/// `(?:;|\|\||\||&&)\s*(?:\x60|[A-Za-z_][\w-]*|[~./][\w./-]*|-[\w-]*)|\$\(|\$\{`
#[allow(clippy::missing_const_for_fn)] // clippy version drift: newer lints flag these
fn shell_metacharacter_window(window: &str) -> bool {
    let bytes = window.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // operator
        let op_len = if bytes[i] == b';' {
            1
        } else if (bytes[i] == b'|' || bytes[i] == b'&')
            && i + 1 < bytes.len()
            && bytes[i + 1] == bytes[i]
        {
            2
        } else if bytes[i] == b'|' || bytes[i] == b'&' {
            1
        } else {
            i += 1;
            continue;
        };
        let mut j = i + op_len;
        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        if j >= bytes.len() {
            i += op_len;
            continue;
        }
        // `\x60` (backtick) or `$(`/`${`
        if bytes[j] == b'`' {
            return true;
        }
        if bytes[j] == b'$' && j + 1 < bytes.len() && (bytes[j + 1] == b'(' || bytes[j + 1] == b'{')
        {
            return true;
        }
        // [A-Za-z_][\w-]*
        if bytes[j] == b'_' || bytes[j].is_ascii_alphabetic() {
            let mut k = j + 1;
            while k < bytes.len()
                && (bytes[k] == b'_' || bytes[k] == b'-' || bytes[k].is_ascii_alphanumeric())
            {
                k += 1;
            }
            return true;
        }
        // [~./][\w./-]*
        if matches!(bytes[j], b'~' | b'.' | b'/') {
            let mut k = j + 1;
            while k < bytes.len()
                && (bytes[k] == b'_'
                    || bytes[k] == b'.'
                    || bytes[k] == b'/'
                    || bytes[k] == b'-'
                    || bytes[k].is_ascii_alphanumeric())
            {
                k += 1;
            }
            return true;
        }
        // -[\w-]*
        if bytes[j] == b'-' {
            return true;
        }
        i = j;
    }
    false
}

fn dollar_substitution_token_is_implausible(token: &str, delimiter: char) -> bool {
    let stripped = token.trim().to_lowercase();
    if stripped == "ifs" {
        return true;
    }
    if delimiter == '{' {
        let Ok(re) = PyRegex::compile(BARE_SHELL_PARAMETER_NAME_RE, false) else {
            return true;
        };
        return re
            .re()
            .find(token.trim())
            .is_none_or(|m| m.start() != 0 || m.end() != token.trim().len());
    }
    // [/.;|&$()]
    token
        .chars()
        .any(|c| matches!(c, '/' | '.' | ';' | '|' | '&' | '$' | '(' | ')'))
}

fn dollar_substitution_pair_backtick_quoted(content: &str, start: usize, end: usize) -> bool {
    let prefix_quoted = start > 0 && char_before(content, start).is_some_and(|(_, c)| c == '`');
    let suffix_quoted = content[end..].chars().next().is_some_and(|c| c == '`');
    prefix_quoted || suffix_quoted
}

/// `_dollar_substitution_pair_is_injection`.
#[must_use]
pub fn dollar_substitution_pair_is_injection(
    content: &str,
    candidate: super::pyregex::Candidate,
    request_context: &str,
) -> bool {
    let start = candidate.start;
    let end = candidate.end;
    if dollar_substitution_pair_backtick_quoted(content, start, end) {
        return false;
    }
    let Some(delimiter) = content[start + 1..].chars().next() else {
        return false;
    };
    let token = &content[start + 2..end - 1];
    if dollar_substitution_token_is_implausible(token, delimiter) {
        return true;
    }
    if strong_sql_keyword_glued_to_pair(content, start, end) {
        return false;
    }
    let normalized = request_context.split(':').next().unwrap_or(request_context);
    AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS.contains(&normalized)
}

/// `_quote_splice_token_is_dangerous_command`: >= 3 consecutive 1-char
/// fragments when splitting the token on quote runs.
#[must_use]
pub fn quote_splice_token_is_dangerous_command(token: &str) -> bool {
    let mut run = 0usize;
    for fragment in token.split(['\'', '"']) {
        let chars = fragment.chars().count();
        run = if chars == 1 { run + 1 } else { 0 };
        if run >= 3 {
            return true;
        }
    }
    false
}

const GLOB_WILDCARD_COMMAND_SUFFIX_CHARS: &[char] = &[' ', '\t', '\r', '\n', ';', '|', '&'];
const GLOB_WILDCARD_VALUE_START_CONTEXTS: &[&str] = &["request_body"];

fn glob_wildcard_token_is_word_shaped(token: &str) -> bool {
    let chars: Vec<char> = token.chars().collect();
    for (index, c) in chars.iter().enumerate() {
        if *c != '?' && *c != '*' {
            continue;
        }
        let mut left = 0usize;
        let mut position = index;
        while position > 0 && chars[position - 1].is_ascii_alphabetic() {
            left += 1;
            position -= 1;
        }
        let mut right = 0usize;
        position = index + 1;
        while position < chars.len() && chars[position].is_ascii_alphabetic() {
            right += 1;
            position += 1;
        }
        if left + right >= 2 {
            return true;
        }
    }
    false
}

/// `_glob_wildcard_token_is_dangerous_command`.
#[must_use]
pub fn glob_wildcard_token_is_dangerous_command(
    content: &str,
    candidate: super::pyregex::Candidate,
    request_context: &str,
) -> bool {
    if !glob_wildcard_token_is_word_shaped(candidate.text(content)) {
        return false;
    }
    let suffix = content[candidate.end..].chars().next();
    if let Some(c) = suffix
        && !GLOB_WILDCARD_COMMAND_SUFFIX_CHARS.contains(&c)
    {
        return false;
    }
    let prefix = &content[..candidate.start];
    if glob_command_boundary_prefix(prefix) {
        return true;
    }
    if GLOB_WILDCARD_VALUE_START_CONTEXTS.contains(&request_context) {
        return prefix.trim().is_empty();
    }
    false
}

/// `(?:;|\|\||\||&&|\$\(|\x60)\s*$`
fn glob_command_boundary_prefix(prefix: &str) -> bool {
    let trimmed = prefix.trim_end_matches(|c: char| c.is_whitespace());
    let Some(last) = trimmed.chars().next_back() else {
        return false;
    };
    match last {
        // `||`, `&&`, `|`, `&` all end with the same char, as do `;` and backtick
        ';' | '`' | '|' | '&' => true,
        '$' => trimmed.as_bytes().get(trimmed.len() - 2) == Some(&b'('),
        _ => false,
    }
}

/// `_brace_expansion_is_dangerous_command`: any comma-separated item is a
/// word-shaped token containing a letter.
#[must_use]
pub fn brace_expansion_is_dangerous_command(candidate_text: &str) -> bool {
    let Some(start) = candidate_text.find('{') else {
        return false;
    };
    let Some(end) = candidate_text.rfind('}') else {
        return false;
    };
    if end <= start {
        return false;
    }
    candidate_text[start + 1..end].split(',').any(|item| {
        !item.is_empty()
            && item
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '~' | '-'))
            && item.chars().any(|c| c.is_ascii_alphabetic())
    })
}

#[cfg(test)]
mod tests {
    use super::super::pyregex::Candidate;
    use super::*;

    #[test]
    fn quote_splice_three_single_char_fragments() {
        assert!(quote_splice_token_is_dangerous_command("a'b'c"));
        assert!(!quote_splice_token_is_dangerous_command("ab'cd"));
        assert!(!quote_splice_token_is_dangerous_command("it's"));
    }

    #[test]
    fn brace_expansion_word_items() {
        assert!(brace_expansion_is_dangerous_command(";{a,b,c}"));
        assert!(brace_expansion_is_dangerous_command(";{echo,id}"));
        assert!(!brace_expansion_is_dangerous_command(";{1,2,3}"));
        // word-shaped items with dashes are still dangerous
        assert!(brace_expansion_is_dangerous_command(";{a-b,c}"));
    }

    #[test]
    fn glob_word_shaped_after_boundary() {
        // `*.txt` has no adjacent letters: not word-shaped, never dangerous
        assert!(!glob_wildcard_token_is_dangerous_command(
            "ls *.txt",
            Candidate::new(3, 8),
            "unknown"
        ));
        // word-shaped token after a command boundary
        assert!(glob_wildcard_token_is_dangerous_command(
            "; file* ",
            Candidate::new(2, 7),
            "unknown"
        ));
        // word-shaped but no command boundary before it
        assert!(!glob_wildcard_token_is_dangerous_command(
            "file* ",
            Candidate::new(0, 5),
            "unknown"
        ));
    }

    #[test]
    fn glob_value_start_only_in_request_body() {
        assert!(glob_wildcard_token_is_dangerous_command(
            "file* ",
            Candidate::new(0, 5),
            "request_body"
        ));
        assert!(!glob_wildcard_token_is_dangerous_command(
            "file* ",
            Candidate::new(0, 5),
            "query_param"
        ));
    }

    #[test]
    fn backtick_glued_injection() {
        // glued backtick pairs only fire in the ambiguous contexts
        let content = "x`id`y";
        assert!(glued_backtick_pair_is_injection(
            content,
            Candidate::new(1, 5),
            "query_param"
        ));
        assert!(!glued_backtick_pair_is_injection(
            content,
            Candidate::new(1, 5),
            "request_body"
        ));
    }

    #[test]
    fn backtick_sql_glue_negated() {
        let content = "SELECT`a`FROM";
        assert!(!glued_backtick_pair_is_injection(
            content,
            Candidate::new(6, 9),
            "request_body"
        ));
    }

    #[test]
    fn dollar_substitution_implausible() {
        // implausible $() token (path separator inside)
        let content = ";$(rm -rf /)";
        assert!(dollar_substitution_pair_is_injection(
            content,
            Candidate::new(1, 12),
            "request_body"
        ));
        // plausible $() token: only ambiguous contexts accept it
        let content = ";$(rm -rf)";
        assert!(dollar_substitution_pair_is_injection(
            content,
            Candidate::new(1, 9),
            "query_param"
        ));
        let content = ";${IFS}";
        assert!(dollar_substitution_pair_is_injection(
            content,
            Candidate::new(1, 7),
            "request_body"
        ));
        let content = ";${PATH}";
        assert!(!dollar_substitution_pair_is_injection(
            content,
            Candidate::new(1, 8),
            "request_body"
        ));
    }
}
