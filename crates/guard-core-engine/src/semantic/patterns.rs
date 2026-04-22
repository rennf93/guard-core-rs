use regex::Regex;

/// Compiled structural regexes that detect attack syntax (HTML tags, function
/// calls, command chains, path traversal, URLs).
///
/// Used by [`crate::extract_suspicious_patterns`] and token extraction.
/// Construct with `Default::default()` for the built-in pattern set.
pub struct AttackStructures {
    named: Vec<(&'static str, Regex)>,
}

impl Default for AttackStructures {
    fn default() -> Self {
        let definitions: &[(&str, &str)] = &[
            ("tag_like", r"<[^>]+>"),
            ("function_call", r"\w+\s*\([^)]*\)"),
            ("command_chain", r"[;&|]{1,2}"),
            ("path_traversal", r"\.{2,}[/\\]"),
            ("url_pattern", r"[a-z]+://"),
        ];

        let named = definitions
            .iter()
            .filter_map(|&(name, pat)| Regex::new(&format!("(?i){pat}")).ok().map(|re| (name, re)))
            .collect();

        Self { named }
    }
}

impl AttackStructures {
    #[must_use]
    pub fn named(&self) -> &[(&'static str, Regex)] {
        &self.named
    }

    pub fn compiled(&self) -> impl Iterator<Item = &Regex> {
        self.named.iter().map(|(_, re)| re)
    }
}
