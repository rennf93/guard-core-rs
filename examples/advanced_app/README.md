# advanced_app

Production-shaped guarded service. Compared to [simple_app](../simple_app) it
demonstrates the two knobs a real deployment tunes: environment-driven engine
configuration and route-scoped guard configuration.

## What is production-shaped here

- **Env-driven engine configuration.** The engine `DetectConfig` and the body
  cap are read from environment variables at startup (see the table below),
  so tuning detection needs no rebuild.
- **Route-scoped guard configuration.** The engine surface has no route IDs,
  so the scoping is expressed the hyper way: `/admin/*` traffic is screened
  by a second, stricter guard tree (threat-score threshold 0.5 and semantic
  threshold 0.35 by default, versus 1.0 and 0.7 on general routes), while
  general routes use the default-derived configuration.
- **Excluded health endpoint.** `GET /health` is answered in front of both
  guards.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `APP_ADDR` | Listen address | `0.0.0.0:8080` |
| `GUARD_MAX_CONTENT_LENGTH` | Engine `max_content_length` | `10000` |
| `GUARD_MAX_FULL_SCAN_BYTES` | Engine `max_full_scan_bytes` (also the default body cap) | `262144` |
| `GUARD_PRESERVE_ATTACK_PATTERNS` | Engine `preserve_attack_patterns` | `true` |
| `GUARD_SEMANTIC_THRESHOLD` | Engine `semantic_threshold` (general routes) | `0.7` |
| `GUARD_THREAT_SCORE_THRESHOLD` | Engine `threat_score_threshold` (general routes) | `1.0` |
| `GUARD_BODY_CAP` | Body buffering cap | `GUARD_MAX_FULL_SCAN_BYTES` |
| `GUARD_ADMIN_SEMANTIC_THRESHOLD` | Semantic threshold for the `/admin` guard tree | half the general threshold |
| `GUARD_ADMIN_THREAT_SCORE_THRESHOLD` | Threat-score threshold for the `/admin` guard tree | half the general threshold |

## Routes

| Route | Guard tree | Behavior |
|---|---|---|
| `GET /health` | excluded | `200 ok` |
| `GET /` | general | `200`, greeting text |
| `GET /search?q=...` | general | `200`, or `403` on a threat |
| `POST /echo` | general | echoes the body; `403`/`413` from the guard |
| `GET /admin/stats` | admin (strict) | `200 stats`, or `403` on a threat |
| anything else | matching tree | `404 not found` |

## Not demonstrated (engine surface)

guard-core-rs currently ships the CPU-bound detection pipeline only. There is
no rate limiter, ban manager, IP intelligence, or Redis surface to drive, so
this example has no per-endpoint rate limits, admin ban/unban routes, or
`REDIS_URL` wiring. When the engine gains those capabilities, the admin route
tree is the natural place to hang the ban manager behind.

## Running

```sh
docker compose -f examples/advanced_app/docker-compose.yml up --build -d --wait
```

The compose stack builds the example from the repository root. Set
`SMOKE_PORT` to remap the host port.

Run natively instead:

```sh
cargo build -p guard-core-rs-advanced-app
GUARD_BODY_CAP=65536 APP_ADDR=127.0.0.1:8080 target/debug/guard-core-rs-advanced-app
```

## Smoke assertions

The `live-smoke` GitHub Actions workflow runs exactly these against the
compose stack (on port 8080; set `SMOKE_PORT` to remap the host port):

| Assertion | Expected |
|---|---|
| `GET /` | `200` |
| `GET /health` | `200` (excluded path) |
| `GET /admin/stats` | `200` |
| `GET /search?q=<script>alert(1)</script>` | `403`, body `{"detail":"Suspicious activity detected"}` |
| `GET /search?q=<img src=x onerror=alert(1)>` | `200` (borderline payload passes the general tree) |
| `GET /admin/stats?q=<img src=x onerror=alert(1)>` | `403` (the stricter admin tree catches it) |
| `POST /echo` with a 70 KB body | `413`, body `{"detail":"Payload too large"}` (`GUARD_BODY_CAP=65536`) |
| `POST /echo` with body `hello world` | `200`, body echoed |

Tear down with:

```sh
docker compose -f examples/advanced_app/docker-compose.yml down -v --remove-orphans
```
