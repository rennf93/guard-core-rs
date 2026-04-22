use std::collections::HashMap;
use std::collections::HashSet;

/// Keyword sets per attack category (xss, sql, command, path, template).
///
/// Used by [`crate::analyze_attack_probability`] for base score calculation.
/// Construct with `Default::default()` for the built-in keyword tables.
pub struct AttackKeywords {
    categories: HashMap<&'static str, HashSet<&'static str>>,
}

impl Default for AttackKeywords {
    fn default() -> Self {
        let categories = HashMap::from([
            (
                "xss",
                HashSet::from([
                    "script",
                    "javascript",
                    "onerror",
                    "onload",
                    "onclick",
                    "onmouseover",
                    "alert",
                    "eval",
                    "document",
                    "cookie",
                    "window",
                    "location",
                ]),
            ),
            (
                "sql",
                HashSet::from([
                    "select",
                    "union",
                    "insert",
                    "update",
                    "delete",
                    "drop",
                    "from",
                    "where",
                    "order",
                    "group",
                    "having",
                    "concat",
                    "substring",
                    "database",
                    "table",
                    "column",
                ]),
            ),
            (
                "command",
                HashSet::from([
                    "exec",
                    "system",
                    "shell",
                    "cmd",
                    "bash",
                    "powershell",
                    "wget",
                    "curl",
                    "nc",
                    "netcat",
                    "chmod",
                    "chown",
                    "sudo",
                    "passwd",
                ]),
            ),
            (
                "path",
                HashSet::from([
                    "etc", "passwd", "shadow", "hosts", "proc", "boot", "win", "ini",
                ]),
            ),
            (
                "template",
                HashSet::from([
                    "render",
                    "template",
                    "jinja",
                    "mustache",
                    "handlebars",
                    "ejs",
                    "pug",
                    "twig",
                ]),
            ),
        ]);
        Self { categories }
    }
}

impl AttackKeywords {
    #[must_use]
    pub const fn all(&self) -> &HashMap<&'static str, HashSet<&'static str>> {
        &self.categories
    }
}
