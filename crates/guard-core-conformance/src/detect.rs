use guard_core_engine::preprocessor;
use guard_core_engine::semantic::{self, AnalysisResult, AttackKeywords, AttackStructures};
use serde_json::{Map, Value, json};

use crate::knobs::Knobs;

pub const DETECTION_METHOD: &str = "enhanced";

#[derive(Debug)]
pub struct Verdict {
    pub is_threat: bool,
    pub threat_score: f64,
    pub threats: Vec<Value>,
    pub original_length: usize,
    pub processed_length: usize,
}

#[must_use]
pub fn detect(content: &str, knobs: &Knobs) -> Verdict {
    let processed = preprocessor::preprocess(
        content,
        knobs.max_truncate_bytes,
        knobs.preserve_attack_patterns,
    );

    let semantic_input: String = processed.chars().take(knobs.max_content_length).collect();
    let analysis = semantic::analyze(
        &semantic_input,
        &AttackKeywords::default(),
        &AttackStructures::default(),
    );
    let score = semantic::get_threat_score(&analysis);
    let threats = semantic_threats(&analysis, score, knobs.semantic_threshold);

    let regex_anomaly = 0.0;
    let is_threat = regex_anomaly >= knobs.threat_score_threshold || !threats.is_empty();

    let threat_score = if threats.is_empty() {
        0.0
    } else {
        semantic_max(&threats).min(1.0)
    };

    Verdict {
        is_threat,
        threat_score,
        threats,
        original_length: content.chars().count(),
        processed_length: processed.chars().count(),
    }
}

fn semantic_max(threats: &[Value]) -> f64 {
    threats
        .iter()
        .filter_map(|t| {
            t.get("probability")
                .or_else(|| t.get("threat_score"))
                .and_then(Value::as_f64)
        })
        .fold(0.0_f64, f64::max)
}

fn semantic_threats(analysis: &AnalysisResult, score: f64, threshold: f64) -> Vec<Value> {
    let mut threats = Vec::new();

    if score > threshold {
        let mut probs: Vec<(&str, f64)> = analysis
            .attack_probabilities
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        probs.sort_unstable_by(|a, b| a.0.cmp(b.0));

        for (attack_type, probability) in probs {
            if probability >= threshold {
                threats.push(json!({
                    "type": "semantic",
                    "attack_type": attack_type,
                    "probability": probability,
                    "analysis": analysis_json(analysis),
                }));
            }
        }

        if threats.is_empty() && score >= threshold {
            threats.push(json!({
                "type": "semantic",
                "attack_type": "suspicious",
                "threat_score": score,
                "analysis": analysis_json(analysis),
            }));
        }
    }

    threats
}

fn analysis_json(analysis: &AnalysisResult) -> Value {
    let mut probabilities = Map::new();
    let mut keys: Vec<&&str> = analysis.attack_probabilities.keys().collect();
    keys.sort();
    for key in keys {
        probabilities.insert(
            (*key).to_owned(),
            json!(analysis.attack_probabilities[*key]),
        );
    }

    let suspicious: Vec<Value> = analysis
        .suspicious_patterns
        .iter()
        .map(|p| {
            json!({
                "type": p.pattern_type,
                "pattern": p.matched,
                "position": p.position,
                "context": p.context,
            })
        })
        .collect();

    json!({
        "attack_probabilities": probabilities,
        "entropy": analysis.entropy,
        "encoding_layers": analysis.encoding_layers,
        "is_obfuscated": analysis.is_obfuscated,
        "suspicious_patterns": suspicious,
        "code_injection_risk": analysis.code_injection_risk,
        "token_count": analysis.token_count,
    })
}

impl Verdict {
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({
            "is_threat": self.is_threat,
            "threat_score": self.threat_score,
            "threats": self.threats,
            "original_length": self.original_length,
            "processed_length": self.processed_length,
            "detection_method": DETECTION_METHOD,
        })
    }
}
