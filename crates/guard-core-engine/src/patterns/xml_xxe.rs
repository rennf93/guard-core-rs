//! XML/XXE structural matchers ported from
//! `guard_core/handlers/_suspatterns_xml_xxe.py` (spec 4.0.2).

use super::pyregex::{Candidate, PyRegex};

const SYSTEM_PREFIX: &str = r"<!(?:ENTITY|DOCTYPE)";
const PUBLIC_EXTERNAL_DTD_RE: &str =
    r#"<!DOCTYPE[^>\[]+PUBLIC[^>\[]+["']https?://(?!(?:www\.)?w3\.org/)[^"'>]+["'][^>\[]*>"#;

fn compile(source: &str) -> Option<PyRegex> {
    PyRegex::compile(source, true).ok()
}

fn find_positions(source: &str, haystack: &str) -> Vec<usize> {
    compile(source)
        .map(|re| re.re().find_iter(haystack).map(|m| m.start()).collect())
        .unwrap_or_default()
}

fn first_at_or_after(sorted: &[usize], floor: usize) -> Option<usize> {
    sorted.iter().copied().find(|p| *p >= floor)
}

fn search_between(re: &PyRegex, haystack: &str, start: usize, end: usize) -> bool {
    if start >= end || end > haystack.len() {
        return false;
    }
    re.re().is_match(&haystack[start..end])
}

/// `_xml_system_finditer`: from each `<!ENTITY`/`<!DOCTYPE` to the first `>`
/// after it, requiring `SYSTEM` inside; overlapping spans are skipped.
#[must_use]
pub fn xml_system_finditer(haystack: &str) -> Vec<Candidate> {
    let Some(gt) = compile(">") else {
        return Vec::new();
    };
    let Some(prefix) = compile(SYSTEM_PREFIX) else {
        return Vec::new();
    };
    let Some(keyword) = compile("SYSTEM") else {
        return Vec::new();
    };
    let ends: Vec<usize> = gt.re().find_iter(haystack).map(|m| m.start()).collect();
    let mut matches = Vec::new();
    let mut last_end = 0usize;
    for prefix_match in prefix.re().find_iter(haystack) {
        let prefix_start = prefix_match.start();
        let prefix_end = prefix_match.end();
        if prefix_start < last_end {
            continue;
        }
        let Some(end) = first_at_or_after(&ends, prefix_end) else {
            return matches;
        };
        last_end = end + 1;
        if search_between(&keyword, haystack, prefix_end + 1, end) {
            matches.push(Candidate::new(prefix_start, last_end));
        }
    }
    matches
}

/// `_xml_internal_entity_finditer`: DOCTYPE position, the first `>`/`[`
/// boundary must be `[`, then an `<!ENTITY` inside the bracket section.
#[must_use]
pub fn xml_internal_entity_finditer(haystack: &str) -> Vec<Candidate> {
    let boundaries = find_positions(r"[>\[]", haystack);
    let entities = find_positions("<!ENTITY", haystack);
    let doctypes = find_positions("<!DOCTYPE", haystack);
    let mut matches = Vec::new();
    let mut last_end = 0usize;
    for prefix_start in doctypes {
        let prefix_end = prefix_start + "<!DOCTYPE".len();
        if prefix_start < last_end {
            continue;
        }
        let Some(boundary) = first_at_or_after(&boundaries, prefix_end) else {
            return matches;
        };
        last_end = boundary + 1;
        if !haystack[boundary..].starts_with('[') {
            continue;
        }
        let Some(entity) = first_at_or_after(&entities, boundary + 1) else {
            return matches;
        };
        last_end = entity + "<!ENTITY".len();
        matches.push(Candidate::new(prefix_start, last_end));
    }
    matches
}

fn scheme_completion_end(
    haystack: &str,
    scheme_start: usize,
    class12_boundaries: &[usize],
    class3_boundaries: &[usize],
) -> Option<usize> {
    if scheme_start == 0
        || !haystack[..scheme_start]
            .chars()
            .next_back()
            .is_some_and(|c| c == '"' || c == '\'')
    {
        return None;
    }
    let scheme = compile(r"https?://")?;
    let m = scheme.re().find_at(haystack, scheme_start)?;
    if m.start() != scheme_start {
        return None;
    }
    let scheme_end = m.end();
    let w3 = compile(r"(?:www\.)?w3\.org/")?;
    if w3
        .re()
        .find_at(haystack, scheme_end)
        .is_some_and(|m| m.start() == scheme_end)
    {
        return None;
    }
    quoted_url_end(haystack, scheme_end, class12_boundaries, class3_boundaries)
}

fn quoted_url_end(
    haystack: &str,
    scheme_end: usize,
    class12_boundaries: &[usize],
    class3_boundaries: &[usize],
) -> Option<usize> {
    let quote2 = first_at_or_after(class3_boundaries, scheme_end)?;
    if quote2 == scheme_end || haystack[quote2..].starts_with('>') {
        return None;
    }
    let final_boundary = first_at_or_after(class12_boundaries, quote2 + 1)?;
    haystack[final_boundary..]
        .starts_with('>')
        .then_some(final_boundary)
}

/// `_xml_xxe_public_external_dtd_finditer`.
///
/// DOCTYPE before PUBLIC in the same boundary-delimited run (>= 10 chars
/// apart) plus a quoted http(s):// URL whose quoted form terminates before
/// the DOCTYPE's final `>`.
#[must_use]
pub fn xml_xxe_public_external_dtd_finditer(haystack: &str) -> Vec<Candidate> {
    let doctype_positions = find_positions("<!DOCTYPE", haystack);
    let public_positions = find_positions("PUBLIC", haystack);
    if doctype_positions.is_empty() || public_positions.is_empty() {
        return Vec::new();
    }
    let class12_boundaries = find_positions(r"[>\[]", haystack);
    let class3_boundaries = find_positions(r#"["'>]"#, haystack);
    let Some(scheme) = compile(r"https?://") else {
        return Vec::new();
    };
    let mut quote_positions: Vec<usize> = Vec::new();
    let mut quote_to_final_gt: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();
    for m in scheme.re().find_iter(haystack) {
        if let Some(final_gt) =
            scheme_completion_end(haystack, m.start(), &class12_boundaries, &class3_boundaries)
        {
            let quote_pos = m.start() - 1;
            quote_positions.push(quote_pos);
            quote_to_final_gt.insert(quote_pos, final_gt);
        }
    }
    if quote_positions.is_empty() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let mut last_end = 0usize;
    for public_pos in public_positions {
        if public_pos < last_end {
            continue;
        }
        // run bounds between class12 boundaries
        let run_start = class12_boundaries
            .iter()
            .copied()
            .rfind(|p| *p <= public_pos)
            .map_or(0, |p| p + 1);
        let run_end = class12_boundaries
            .iter()
            .copied()
            .find(|p| *p > public_pos)
            .unwrap_or(haystack.len());
        let Some(doctype_before) = first_at_or_after(&doctype_positions, run_start) else {
            continue;
        };
        if doctype_before >= public_pos.saturating_sub(9) {
            continue;
        }
        let Some(quote1) = first_at_or_after(&quote_positions, public_pos + 7) else {
            continue;
        };
        if quote1 >= run_end {
            continue;
        }
        let Some(final_gt) = quote_to_final_gt.get(&quote1) else {
            continue;
        };
        let candidate = Candidate::new(doctype_before, final_gt + 1);
        matches.push(candidate);
        last_end = candidate.end;
    }
    matches
}

#[must_use]
pub const fn public_external_dtd_source() -> &'static str {
    PUBLIC_EXTERNAL_DTD_RE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_entity_requires_system_keyword() {
        let hits = xml_system_finditer(r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#);
        assert_eq!(hits.len(), 1);
        assert!(xml_system_finditer(r#"<!ENTITY xxe "plain">"#).is_empty());
    }

    #[test]
    fn internal_entity_requires_bracket_section() {
        let text = "<!DOCTYPE foo [<!ENTITY xxe \"bar\">]>";
        let hits = xml_internal_entity_finditer(text);
        assert_eq!(hits.len(), 1);
        assert!(xml_internal_entity_finditer("<!DOCTYPE foo SYSTEM \"x\">").is_empty());
    }

    #[test]
    fn public_external_dtd_rejects_w3_org() {
        let good = r#"<!DOCTYPE foo PUBLIC "-//X//DTD//EN" "http://evil.example/dtd">"#;
        assert_eq!(xml_xxe_public_external_dtd_finditer(good).len(), 1);
        let w3 = r#"<!DOCTYPE foo PUBLIC "-//W3C//DTD//EN" "http://www.w3.org/dtd">"#;
        assert!(xml_xxe_public_external_dtd_finditer(w3).is_empty());
    }
}
