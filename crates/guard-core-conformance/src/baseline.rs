use std::collections::HashSet;
use std::fs;

use serde::Deserialize;

use crate::corpus::conformance_dir;

pub const BASELINE_FILE: &str = "xfail_baseline.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub spec_version: String,
    pub cases: Vec<BaselineEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineEntry {
    pub case: String,
    pub reason: String,
}

pub fn load_baseline() -> Result<Baseline, String> {
    let path = conformance_dir().join(BASELINE_FILE);
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let baseline: Baseline =
        toml::from_str(&raw).map_err(|e| format!("parse {BASELINE_FILE}: {e}"))?;

    if baseline.spec_version != crate::corpus::EXPECTED_SPEC_VERSION {
        return Err(format!(
            "baseline spec_version '{}' does not match runner requirement {}",
            baseline.spec_version,
            crate::corpus::EXPECTED_SPEC_VERSION
        ));
    }

    let mut seen = HashSet::new();
    for entry in &baseline.cases {
        if !seen.insert(&entry.case) {
            return Err(format!("case baselined more than once: {}", entry.case));
        }
    }

    Ok(baseline)
}

#[must_use]
pub fn baseline_keys(baseline: &Baseline) -> HashSet<String> {
    baseline.cases.iter().map(|c| c.case.clone()).collect()
}

#[must_use]
pub fn baseline_reason<'a>(baseline: &'a Baseline, key: &str) -> Option<&'a str> {
    baseline
        .cases
        .iter()
        .find(|c| c.case == key)
        .map(|c| c.reason.as_str())
}
