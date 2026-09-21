//! LDAP breakout window analysis and legacy IPv4 host validation, ported
//! from `guard_core/handlers/_suspatterns_ldap_ipv4.py` (spec 4.0.2).

use super::chars_util::char_before;
use super::pyregex::{Candidate, PyRegex};

pub const LDAP_WILDCARD_CHAIN_RE: &str = r#"\*\)[|&]?\(+\s*(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?="#;
pub const LDAP_WILDCARD_EQUALS_RE: &str = r#"\*\s*\)+\s*(?:[|&!]\s*)?\(+\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?=#";
pub const LDAP_PAREN_BREAKOUT_RE: &str = r#"\)\s*\(\s*(?:[&|!]|(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?[=~<>])"#;
pub const LDAP_PAREN_CONJUNCTION_RE: &str = r"\(\s*[&|]\s*";

pub const LEGACY_IPV4_HOST_RE: &str = r"://(?:[^/@\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)){0,3})(?=[:/\s]|$)";

/// Structural matcher for `_LEGACY_IPV4_HOST_RE`: the terminating lookahead
/// `(?=[:/\s]|$)` is enforced as a suffix check on the host part. If the
/// greedy host fails the guard, every shorter host at the same start ends in
/// a host character (never a terminator), so the check is exact.
#[must_use]
pub fn legacy_ipv4_finditer(haystack: &str) -> Vec<Candidate> {
    let Ok(compiled) = PyRegex::compile(
        r"://(?:[^/@\s]*@)?((?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|[1-9]\d*|0)){0,3})",
        true,
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for m in compiled.re().find_iter(haystack) {
        let after = m.end();
        let guard_ok = if after == haystack.len() {
            true
        } else if haystack[after..]
            .chars()
            .next()
            .is_some_and(|c| c == '\n' && after + 1 == haystack.len())
        {
            // Python `$` also matches just before a trailing newline
            true
        } else {
            haystack[after..]
                .chars()
                .next()
                .is_some_and(|c| matches!(c, ':' | '/') || c.is_whitespace())
        };
        if guard_ok {
            out.push(Candidate::new(m.start(), m.end()));
        }
    }
    out
}

// Blocked networks as [lo, hi] u32 ranges (IPv4).
const BLOCKED_IPV4_RANGES: &[(u32, u32)] = &[
    (0, 0x00ff_ffff),           // 0.0.0.0/8
    (0x7f00_0000, 0x7fff_ffff), // 127.0.0.0/8
    (0x0a00_0000, 0x0aff_ffff), // 10.0.0.0/8
    (0xac10_0000, 0xac1f_ffff), // 172.16.0.0/12
    (0xc0a8_0000, 0xc0a8_ffff), // 192.168.0.0/16
    (0xa9fe_0000, 0xa9fe_ffff), // 169.254.0.0/16
    (0x6464_64c8, 0x6464_64c8), // 100.100.100.200/32
];

fn decode_legacy_ipv4_part(part: &str) -> Option<u64> {
    if let Some(digits) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(digits, 16).ok();
    }
    if part.len() > 1 && part.starts_with('0') {
        let digits = &part[1..];
        if !digits.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        return u64::from_str_radix(digits, 8).ok();
    }
    if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) {
        return part.parse::<u64>().ok();
    }
    None
}

fn is_bare_decimal(part: &str) -> bool {
    part == "0" || !part.starts_with('0')
}

/// `decodeLegacyIpv4Host`: 1-4 parts of decimal/octal/hex; ambiguous bare
/// decimal values < 2^24 (which look like ports) are rejected.
#[must_use]
pub fn decode_legacy_ipv4_host(host: &str) -> Option<u64> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut decoded = Vec::with_capacity(parts.len());
    for part in &parts {
        decoded.push(decode_legacy_ipv4_part(part)?);
    }
    if decoded.len() == 1 && decoded[0] != 0 && decoded[0] < (1 << 24) && is_bare_decimal(parts[0])
    {
        return None;
    }
    for value in &decoded[..decoded.len() - 1] {
        if *value > 255 {
            return None;
        }
    }
    let remaining_bits = 8 * (5 - decoded.len());
    let last = decoded[decoded.len() - 1];
    if remaining_bits >= 64 || last >= (1u64 << remaining_bits) {
        return None;
    }
    let mut result = 0u64;
    for value in &decoded[..decoded.len() - 1] {
        result = (result << 8) | value;
    }
    Some((result << remaining_bits) | last)
}

fn is_blocked_legacy_ipv4(ip: u64) -> bool {
    BLOCKED_IPV4_RANGES
        .iter()
        .any(|(lo, hi)| ip >= u64::from(*lo) && ip <= u64::from(*hi))
}

/// `_legacy_ipv4_match_is_blocked`: the candidate match spans `://[userinfo@]host`;
/// group 1 is the host after the optional userinfo.
#[must_use]
pub fn legacy_ipv4_match_is_blocked(candidate_text: &str) -> bool {
    let Some(rest) = candidate_text.strip_prefix("://") else {
        return false;
    };
    let host = match rest.find('@') {
        Some(at) => &rest[at + 1..],
        None => rest,
    };
    let Some(ip) = decode_legacy_ipv4_host(host) else {
        return false;
    };
    is_blocked_legacy_ipv4(ip)
}

struct BreakoutWindow {
    window: String,
    depth: i64,
    depth_unresolved: bool,
}

fn ldap_breakout_backward_window(text: &str, close_paren_pos: usize) -> BreakoutWindow {
    let backward_start = close_paren_pos.saturating_sub(40);
    let mut position: i64 = close_paren_pos as i64;
    let mut depth = 0i64;
    loop {
        if position < backward_start as i64 {
            break;
        }
        let Some(c) = text.get(position as usize..).and_then(|s| s.chars().next())
        else {
            break;
        };
        if matches!(c, '"' | '\'' | '\n' | '&') {
            break;
        }
        match c {
            ')' => depth -= 1,
            '(' => depth += 1,
            _ => {}
        }
        // step left one char; past the start means the window opened at 0
        match if position == 0 {
            None
        } else {
            char_before(text, position as usize).map(|(i, _)| i as i64)
        } {
            Some(prev) => position = prev,
            None => {
                position = -1;
                break;
            }
        }
    }
    let from = (position + 1).max(0) as usize;
    let window = text[from..close_paren_pos.min(text.len())].to_owned();
    let depth_unresolved = backward_start > 0 && position < backward_start as i64;
    BreakoutWindow {
        window,
        depth,
        depth_unresolved,
    }
}

fn ldap_next_candidate_scan_limit(
    compiled: &PyRegex,
    text: &str,
    candidate: &Candidate,
) -> usize {
    compiled
        .re()
        .find_at(text, candidate.end)
        .map_or(text.len(), |m| m.end())
}

/// Forward extent through the filter expression, respecting paren nesting.
#[must_use]
fn ldap_filter_expression_forward_extent(
    text: &str,
    start: usize,
    scan_limit: usize,
) -> usize {
    let mut position = start;
    let mut depth = 0i64;
    loop {
        let Some(next) = text[position..]
            .char_indices()
            .find(|(_, c)| matches!(c, '(' | ')' | '"' | '\'' | '\n'))
            .map(|(i, _)| position + i)
        else {
            return scan_limit;
        };
        if next >= scan_limit {
            return scan_limit;
        }
        match text[next..].chars().next() {
            Some('"' | '\'' | '\n') => return next,
            Some('(') => depth += 1,
            Some(')') if depth == 0 => return next,
            Some(')') => depth -= 1,
            _ => {}
        }
        position = next + 1;
    }
}

fn ldap_breakout_forward_window(
    compiled: &PyRegex,
    text: &str,
    candidate: &Candidate,
    close_paren_pos: usize,
) -> String {
    let scan_limit = ldap_next_candidate_scan_limit(compiled, text, candidate);
    let extent = ldap_filter_expression_forward_extent(text, close_paren_pos + 1, scan_limit);
    text[close_paren_pos..extent].to_owned()
}

fn search_in(source: &str, text: &str) -> bool {
    let Ok(re) = PyRegex::compile(source, true) else {
        return false;
    };
    re.re().is_match(text)
}

/// `_ldap_wildcard_chain_is_injection` over any of the three LDAP breakout
/// patterns.
#[must_use]
pub fn ldap_wildcard_chain_is_injection(
    compiled: &PyRegex,
    haystack: &str,
    candidate: &Candidate,
) -> bool {
    let text = candidate.text(haystack);
    let Some(paren_rel) = text.find(')') else {
        return false;
    };
    let close_paren_pos = candidate.start + paren_rel;

    let backward = ldap_breakout_backward_window(haystack, close_paren_pos);
    let forward = ldap_breakout_forward_window(compiled, haystack, candidate, close_paren_pos);

    let wildcard_adjacent = text.starts_with('*');
    let depth_proves_breakout =
        backward.depth <= 0 && (wildcard_adjacent || !backward.depth_unresolved);
    let wildcard_clause_end = search_in(r"=[^()]+\*\s*\z", &backward.window);
    if !(depth_proves_breakout || wildcard_clause_end) {
        return false;
    }
    let attack_token = r"\*|\(\s*[&|!]|\x00|\(\s*\(|~=|>=|<=";
    search_in(attack_token, &backward.window) || search_in(attack_token, &forward)
}

/// `_ldap_paren_conjunction_is_injection`.
#[must_use]
pub fn ldap_paren_conjunction_is_injection(
    compiled: &PyRegex,
    haystack: &str,
    candidate: &Candidate,
) -> bool {
    let scan_limit = ldap_next_candidate_scan_limit(compiled, haystack, candidate);
    let tail_end = ldap_filter_expression_forward_extent(haystack, candidate.end, scan_limit);
    let tail = &haystack[candidate.end..tail_end];
    if search_in(r"\A\s*(?:[!(]|\*)", tail) {
        return true;
    }
    if !tail.contains('=') {
        return false;
    }
    search_in(
        r"\A\s*(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)(?:;[\w.-]+)*(?::[\w.-]+)*\s*:?=",
        tail,
    )
}

/// `_source_extension_path_is_probe`: accepted only in embedded-JSON leaf
/// context.
#[must_use]
pub fn source_extension_path_is_probe(validator_context: &str) -> bool {
    !validator_context.ends_with(":embedded_json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_ipv4_decoding() {
        assert_eq!(decode_legacy_ipv4_host("127.0.0.1"), Some(0x7f00_0001));
        assert_eq!(decode_legacy_ipv4_host("0x7f.0.0.1"), Some(0x7f00_0001));
        assert_eq!(decode_legacy_ipv4_host("0177.0.0.1"), Some(0x7f00_0001));
        assert_eq!(decode_legacy_ipv4_host("2130706433"), Some(0x7f00_0001));
        // bare decimal that looks like a port
        assert_eq!(decode_legacy_ipv4_host("966"), None);
        assert_eq!(decode_legacy_ipv4_host("1.2.3.4.5"), None);
        assert_eq!(decode_legacy_ipv4_host("256.1.1.1"), None);
    }

    #[test]
    fn blocked_networks() {
        assert!(is_blocked_legacy_ipv4(0x7f00_0001));
        assert!(is_blocked_legacy_ipv4(0x0a00_0001));
        assert!(!is_blocked_legacy_ipv4(0x0808_0808));
    }

    #[test]
    fn legacy_ipv4_matcher_finds_blocked_host() {
        let ms = legacy_ipv4_finditer("curl http://127.0.0.1:8080/");
        assert_eq!(ms.len(), 1);
        assert!(legacy_ipv4_match_is_blocked(ms[0].text("curl http://127.0.0.1:8080/")));
        let ms = legacy_ipv4_finditer("curl http://example.com/");
        assert!(ms.is_empty() || !legacy_ipv4_match_is_blocked(ms[0].text("curl http://example.com/")));
    }

    #[test]
    fn ldap_conjunction_followup_decides() {
        let compiled = PyRegex::compile(LDAP_PAREN_CONJUNCTION_RE, false).unwrap();
        // a conjunction followed by another clause is the injection canary
        let haystack = "(&(objectClass=user))";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(ldap_paren_conjunction_is_injection(&compiled, haystack, &cand));
        // a bare conjunction with no followup is rejected
        let haystack = "(|x";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(!ldap_paren_conjunction_is_injection(&compiled, haystack, &cand));
    }

    #[test]
    fn ldap_conjunction_accepts_followup_symbol() {
        let compiled = PyRegex::compile(LDAP_PAREN_CONJUNCTION_RE, false).unwrap();
        let haystack = "(&(cn=*)(!(cn=admin)))";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(ldap_paren_conjunction_is_injection(&compiled, haystack, &cand));
    }

    #[test]
    fn wildcard_chain_detects_breakout() {
        let compiled = PyRegex::compile(LDAP_WILDCARD_CHAIN_RE, false).unwrap();
        // chain shape: `*` `)` `(` attr `=`
        let haystack = "(uid=*)((mail=";
        let c = compiled.re().find(haystack).unwrap();
        let cand = Candidate::new(c.start(), c.end());
        assert!(ldap_wildcard_chain_is_injection(&compiled, haystack, &cand));
    }
}
