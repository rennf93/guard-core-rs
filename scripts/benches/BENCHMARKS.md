# Benchmark Results: Rust vs Python Detection Engine

Machine: Linux 6.19.11, Rust 1.92 (stable), Python 3.13.5
Date: 2026-04-22

## Full Pipeline (preprocess + semantic analysis + threat score)

| Payload                             | Python (us) | Rust (us) |  Speedup |
| ----------------------------------- | ----------: | --------: | -------: |
| clean_get                           |       1,320 |      10.1 | **131x** |
| clean_json                          |       1,338 |      10.0 | **134x** |
| xss_basic                           |       1,208 |       9.7 | **124x** |
| xss_bypass (zero-width chars)       |       1,201 |       8.8 | **136x** |
| sqli_union                          |       1,250 |       9.5 | **132x** |
| sqli_encoded (URL-encoded keywords) |       1,208 |       9.3 | **130x** |
| cmd_injection                       |       1,259 |       9.6 | **131x** |
| path_traversal                      |       1,189 |       9.6 | **124x** |
| template_injection                  |       1,265 |      11.8 | **107x** |
| double_encoded                      |       1,239 |      11.1 | **112x** |
| mixed_attack (XSS + SQLi)           |       1,246 |      12.5 | **100x** |
| **100 mixed requests (batch)**      | **153,592** |   **855** | **180x** |

### Summary

- **Median speedup: ~125x** across all payload types
- **Batch throughput: 180x** (100 mixed requests)
- All payloads well above Renzo's 5-10x threshold

## Why the gap is so large

1. **ThreadPoolExecutor per regex match** - Python wraps every `re.search()` in a thread pool with 0.1-0.5s timeout. OS thread creation + future allocation per operation. The semantic analyzer alone spawns 5+ thread pools per `extract_tokens()` call
2. **Async on CPU work** - `ContentPreprocessor.preprocess()` is `async`, adding coroutine scheduling for pure computation
3. **O(n) LRU eviction** - `_cache_order.remove(cache_key)` is a list scan. Rust's `lru` crate is O(1)
4. **GIL contention** - thread pools + async = GIL bouncing on every operation
5. **String copies** - Python allocates new string objects at each pipeline step. Rust uses `&str` slices
6. **No ReDoS protection needed** - Rust's `regex` crate uses finite automata. No timeout wrappers, no thread pools, no `concurrent.futures` overhead. This is the single biggest difference

## Maturin/PyO3 Binding: Why per-call is only 2x

Per-call through PyO3:

```
Python -> GIL acquire -> argument conversion -> Rust (10us) -> dict construction -> GIL release -> Python
          ~500us overhead                       ~10us work     ~200us overhead
```

Each FFI crossing costs ~700us. The Rust work is 10us. **98% of the time is spent crossing the boundary, not doing work.** This is inherent to CPython's FFI model.

| Mode                  | What happens                    | Per request | vs Python |
| --------------------- | ------------------------------- | ----------: | --------: |
| Python pure           | everything in Python            |    1,250 us |  baseline |
| Rust+PyO3 per-call    | one FFI crossing per request    |      750 us |    **2x** |
| Rust+PyO3 batch       | one FFI crossing for N requests |     12.8 us | **~100x** |
| Rust pure (criterion) | no Python involved              |       10 us | **~125x** |

### When each mode makes sense

- **Per-call (2x)**: drop-in replacement in existing middleware. Free speedup, zero code changes. Works request-by-request
- **Batch API (~100x)**: buffered processing. Queue requests, process batch in Rust, return scores. Needs architectural change in the middleware
- **Pure Rust (~125x)**: standalone deployment, CLI tooling, or Rust-native middleware. No Python in the loop

For guard-core's middleware use case (one request at a time), the realistic gain from maturin is **2x**. The 100x+ numbers require either batching or dropping Python entirely.

## Reproducing

```bash
# Rust benchmarks (criterion)
cargo bench --bench detection_engine
cargo bench --bench compiler
cargo bench --bench preprocessor
cargo bench --bench semantic

# Python benchmarks
python scripts/benches/bench.py

# Python vs Rust+PyO3 comparison
python scripts/benches/bench.py --compare
```

## Raw data

- Rust: `target/criterion/` (HTML reports with histograms)
- Python: `scripts/benches/bench_results.json`
