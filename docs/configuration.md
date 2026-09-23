# Configuration

There is no global config struct yet (the Python `SecurityConfig` section is
not ported). Detection is tuned through one flat struct,
`guard_core_rs::detect::DetectConfig`, passed to every `detect` call.

## DetectConfig

| Field | Type | Corpus default | Notes |
|---|---|---|---|
| `max_content_length` | `usize` | `10000` | `detection_max_content_length`: the semantic budget; the processed content is truncated to this many code points before analysis, and it bounds truncation |
| `max_full_scan_bytes` | `usize` | `262144` | `detection_max_body_inspect_bytes`: the preprocessor's full-scan cap; content beyond it is handled by the attack-preserving truncation path |
| `preserve_attack_patterns` | `bool` | `true` | `detection_preserve_attack_patterns`: keep attack-relevant regions intact across the decode pipeline |
| `semantic_threshold` | `f64` | `0.7` | `detection_semantic_threshold`: per-attack-type semantic threats fire at or above this probability |
| `threat_score_threshold` | `f64` | `1.0` | `detection_threat_score_threshold`: the regex-anomaly weight sum at or above which the verdict is a threat |

## Scoring semantics

`is_threat` is `sum(regex weights) >= threat_score_threshold` or any semantic
threat. `threat_score` is `min(max(regex anomaly, semantic max), 1.0)` when
any threat exists, else `0.0`. Semantic threats are emitted per attack type
at or above `semantic_threshold`, with a `suspicious` fallback carrying the
overall score when no individual type crosses the line.

## Request contexts

`detect(content, request_context, config)` normalizes the context (the part
before the first `:`) to one of `query_param`, `header`, `url_path`,
`request_body`, or `unknown`. Unknown contexts relax the pattern view
filters; embedded-JSON leaf contexts (a `:embedded_json` suffix) keep the
suffix for validator scoping.

## What is not implemented (fail-closed honesty)

The port targets spec 4.0.2 and is not complete. Do not expect these yet:

- **The 4.x pattern-table scan stage**: the full reference regex table
  across all scan views has no Rust counterpart yet; the corpus xfail
  baseline records the resulting divergences (the dominant cause of xfail
  entries).
- **Config, pipeline, and handler sections** (Python sections 02, 03,
  07-12): no `SecurityConfig`, no middleware pipeline, no handlers,
  protocols, or decorators. There is no rate limiting, no IP banning, no
  cloud provider blocking, no Redis, and no response factory.
- **`PerformanceMonitor`** and per-scan timeouts, plus a handful of tracked
  detection knobs recorded as unmapped with reasons.

## Conformance knobs

The conformance harness maps the five `DetectConfig` fields above from the
corpus `config_knobs` and records every unmapped knob with a reason. Changing
engine behavior requires the ledger or xfail baseline to stay consistent:
the gate fails on unbaselined failures, stale xfails, and not-run corpus
cases alike.
