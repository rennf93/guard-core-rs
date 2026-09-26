# Configuration

There is no global config struct yet (the Python `SecurityConfig` section is
not ported). Detection is tuned through one flat struct,
`guard_core_rs::detect::DetectConfig`, passed to every `detect` call, and the
global IP gate through one flat struct, `guard_core_engine::ip_gate::IpGateConfig`.

## IpGateConfig (whitelist / blacklist / exempt_ips)

The global IP gate is the Rust family's minimal port of the reference
engine's global IP stage. Build it once at startup with
`IpGateConfig::new(whitelist, blacklist, exempt_ips)`, which fails closed on
an invalid entry, and evaluate request IPs with `IpGateConfig::evaluate`:

| List | Semantics |
|---|---|
| `whitelist` | Allowlist. When non-empty, every IP it does not match is denied (`IP not in whitelist`) |
| `blacklist` | Denylist, consulted when `whitelist` is empty (`IP is blacklisted`) |
| `exempt_ips` | Skip-list for known-friendly automation; sets the skip flag, never a deny path |

Matching semantics are identical for all three lists, mirroring the reference
whitelist matcher: a bare IP or a CIDR range (host bits cleared at parse
time), IPv4-mapped forms matched against their IPv4 canonical form
(`::ffff:203.0.113.7` matches `203.0.113.7` and `203.0.113.0/24`), and no
cross-family matching.

### exempt_ips vs whitelist

`exempt_ips` is noise reduction for known-friendly automation (monitoring
probes, VPN egress, a partner's server), not immunity: it is noise reduction
for known-friendly automation, not immunity; the blacklist, dynamic bans,
route rules and detection still apply. An exempt match sets the same skip
state a whitelist match sets (`IpGateDecision::is_exempt`) but never adds a
deny path of its own and never opens the whitelist gate: with a restrictive
whitelist, an exempt IP that is not itself whitelisted is still denied. The
Rust family ships no rate limiter, user-agent filter, cloud-provider blocker,
or violation counter yet, so there is nothing for the flag to skip today; a
stage that lands later must skip exactly what the reference skips for a
whitelist match (`is_whitelisted || is_exempt`) and must never skip
penetration detection.

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
  protocols, or decorators. The global IP gate (`whitelist`, `blacklist`,
  `exempt_ips`) exists (`ip_gate`), but there is no rate limiting, no IP
  banning, no cloud provider blocking, no Redis, and no response factory.
- **`PerformanceMonitor`** and per-scan timeouts, plus a handful of tracked
  detection knobs recorded as unmapped with reasons.

## Conformance knobs

The conformance harness maps the five `DetectConfig` fields above from the
corpus `config_knobs` and records every unmapped knob with a reason. Changing
engine behavior requires the ledger or xfail baseline to stay consistent:
the gate fails on unbaselined failures, stale xfails, and not-run corpus
cases alike.
