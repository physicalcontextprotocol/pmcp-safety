"""
P-MCP Edge Benchmarks
========================
Micro-benchmarks for edge-deployed P-MCP servers:
  - JSON-RPC parse + dispatch throughput (requests/sec)
  - E-stop round-trip latency (percentiles)
  - Actuation queue drain rate
  - Rate limiter overhead
  - Input validator throughput

Run:
  python -m edge.benchmarks
  python -m edge.benchmarks --url http://localhost:8080 --remote
"""
from __future__ import annotations

import asyncio
import json
import statistics
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

SAMPLE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "pmcp/ping",
    "params": {},
}


def _percentile(data: List[float], p: float) -> float:
    if not data:
        return 0.0
    data_sorted = sorted(data)
    idx = int(len(data_sorted) * p / 100)
    return data_sorted[min(idx, len(data_sorted) - 1)]


class BenchmarkResult:
    def __init__(self, name: str, count: int, duration_s: float,
                 latencies: Optional[List[float]] = None) -> None:
        self.name = name
        self.count = count
        self.duration_s = duration_s
        self.latencies = latencies or []

    @property
    def rps(self) -> float:
        return self.count / self.duration_s if self.duration_s > 0 else 0

    @property
    def p50_ms(self) -> float:
        return _percentile(self.latencies, 50) * 1000

    @property
    def p95_ms(self) -> float:
        return _percentile(self.latencies, 95) * 1000

    @property
    def p99_ms(self) -> float:
        return _percentile(self.latencies, 99) * 1000

    def print_summary(self) -> None:
        print(f"\n{'─'*50}")
        print(f"Benchmark: {self.name}")
        print(f"  Iterations : {self.count}")
        print(f"  Duration   : {self.duration_s:.3f}s")
        print(f"  Throughput : {self.rps:.1f} req/s")
        if self.latencies:
            print(f"  P50 latency: {self.p50_ms:.2f} ms")
            print(f"  P95 latency: {self.p95_ms:.2f} ms")
            print(f"  P99 latency: {self.p99_ms:.2f} ms")


# ─────────────────────────────────────────────────────────────────────────────
#  Local benchmarks (no HTTP)
# ─────────────────────────────────────────────────────────────────────────────

async def bench_input_validator(n: int = 100_000) -> BenchmarkResult:
    from .hardening import InputValidator
    validator = InputValidator()
    latencies: List[float] = []
    t0 = time.perf_counter()
    for _ in range(n):
        ts = time.perf_counter()
        validator.validate(SAMPLE_REQUEST)
        latencies.append(time.perf_counter() - ts)
    return BenchmarkResult("InputValidator.validate", n,
                           time.perf_counter() - t0, latencies)


async def bench_rate_limiter(n: int = 100_000) -> BenchmarkResult:
    from .hardening import RateLimiter
    rl = RateLimiter(capacity=1e9, rate=1e9)  # Unlimited for pure overhead test
    latencies: List[float] = []
    t0 = time.perf_counter()
    for i in range(n):
        ts = time.perf_counter()
        rl.allow(f"peer-{i % 10}")
        latencies.append(time.perf_counter() - ts)
    return BenchmarkResult("RateLimiter.allow", n,
                           time.perf_counter() - t0, latencies)


async def bench_json_parse(n: int = 50_000) -> BenchmarkResult:
    raw = json.dumps(SAMPLE_REQUEST).encode()
    latencies: List[float] = []
    t0 = time.perf_counter()
    for _ in range(n):
        ts = time.perf_counter()
        json.loads(raw)
        latencies.append(time.perf_counter() - ts)
    return BenchmarkResult("json.loads (request)", n,
                           time.perf_counter() - t0, latencies)


# ─────────────────────────────────────────────────────────────────────────────
#  Remote benchmarks (against live robot)
# ─────────────────────────────────────────────────────────────────────────────

async def bench_remote_ping(url: str, n: int = 500, concurrency: int = 10) -> BenchmarkResult:
    import aiohttp

    sem = asyncio.Semaphore(concurrency)
    latencies: List[float] = []

    async def one_ping(session: aiohttp.ClientSession) -> None:
        async with sem:
            t0 = time.perf_counter()
            payload = {"jsonrpc": "2.0", "id": 1, "method": "pmcp/ping", "params": {}}
            async with session.post(url, json=payload) as resp:
                await resp.json()
            latencies.append(time.perf_counter() - t0)

    t_start = time.perf_counter()
    async with aiohttp.ClientSession() as sess:
        await asyncio.gather(*[one_ping(sess) for _ in range(n)])

    return BenchmarkResult("Remote pmcp/ping", n,
                           time.perf_counter() - t_start, latencies)


async def bench_remote_estop(url: str, n: int = 100) -> BenchmarkResult:
    import aiohttp
    latencies: List[float] = []
    t_start = time.perf_counter()

    async with aiohttp.ClientSession() as sess:
        for i in range(n):
            t0 = time.perf_counter()
            engage_payload = {"jsonrpc": "2.0", "id": i * 2, "method": "safety/estop/engage", "params": {}}
            async with sess.post(url, json=engage_payload) as resp:
                await resp.json()
            release_payload = {"jsonrpc": "2.0", "id": i * 2 + 1, "method": "safety/estop/release", "params": {}}
            async with sess.post(url, json=release_payload) as resp:
                await resp.json()
            latencies.append(time.perf_counter() - t0)

    return BenchmarkResult("Remote E-stop cycle", n,
                           time.perf_counter() - t_start, latencies)


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────

async def run_all(remote_url: Optional[str] = None) -> None:
    print("P-MCP Edge Benchmarks")
    print("=" * 50)

    # Local benchmarks
    for bench_fn in [bench_json_parse, bench_input_validator, bench_rate_limiter]:
        result = await bench_fn()
        result.print_summary()

    # Remote benchmarks
    if remote_url:
        print(f"\nRemote benchmarks against {remote_url}")
        for bench_fn in [
            lambda: bench_remote_ping(remote_url),
            lambda: bench_remote_estop(remote_url, 50),
        ]:
            result = await bench_fn()
            result.print_summary()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="P-MCP Edge Benchmarks")
    parser.add_argument("--url", default="", help="Remote robot URL for live benchmarks")
    parser.add_argument("--remote", action="store_true", help="Run remote benchmarks too")
    args = parser.parse_args()
    url = args.url if args.remote or args.url else None
    asyncio.run(run_all(url))
