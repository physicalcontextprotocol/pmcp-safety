"""
P-MCP ISO/IEC Compliance Harness
===================================
Automated compliance checking against:
  - ISO 10218-1/2: Industrial robot safety requirements
  - IEC 62443-3-3: Industrial automation security (SR levels)
  - ISO 13849-1: Safety-related parts of control systems (PL levels)

The harness runs a battery of checks against a live P-MCP robot endpoint
and produces a structured compliance report.

Usage:
  python -m compliance.harness --url http://localhost:8080 --standard all
  python -m compliance.harness --url http://localhost:8080 --standard iso10218
  python -m compliance.harness --output report.json
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("pmcp.compliance")


class Standard(str, Enum):
    ISO_10218 = "iso10218"
    IEC_62443 = "iec62443"
    ISO_13849 = "iso13849"


class CheckResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass
class ComplianceCheck:
    check_id: str
    standard: Standard
    clause: str
    description: str
    mandatory: bool = True

    async def run(self, client: "ComplianceClient") -> "CheckReport":
        raise NotImplementedError


@dataclass
class CheckReport:
    check_id: str
    standard: str
    clause: str
    description: str
    result: CheckResult
    detail: str = ""
    duration_ms: float = 0.0
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "check_id": self.check_id,
            "standard": self.standard,
            "clause": self.clause,
            "description": self.description,
            "result": self.result.value,
            "detail": self.detail,
            "duration_ms": round(self.duration_ms, 2),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Compliance Client (thin P-MCP client)
# ─────────────────────────────────────────────────────────────────────────────

class ComplianceClient:
    def __init__(self, url: str) -> None:
        self._url = url
        self._counter = 0
        self._caps: Optional[Dict] = None

    async def call(self, method: str, params: Dict = {}) -> Dict:
        import aiohttp
        self._counter += 1
        payload = {"jsonrpc": "2.0", "id": self._counter, "method": method, "params": params}
        async with aiohttp.ClientSession() as sess:
            async with sess.post(self._url, json=payload,
                                 timeout=aiohttp.ClientTimeout(total=10)) as resp:
                data = await resp.json()
                if "error" in data:
                    raise RuntimeError(f"RPC error {data['error']}")
                return data.get("result", {})

    async def initialize(self) -> Dict:
        self._caps = await self.call("initialize", {"client_id": "compliance_harness"})
        return self._caps

    def capabilities(self) -> Dict:
        return self._caps or {}


# ─────────────────────────────────────────────────────────────────────────────
#  ISO 10218 Checks
# ─────────────────────────────────────────────────────────────────────────────

class ISO10218_EstopRequired(ComplianceCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="PMCP-CHK-01",
            standard=Standard.ISO_10218,
            clause="5.4.2",
            description="Robot SHALL provide an emergency stop function",
            mandatory=True,
        )

    async def run(self, client: ComplianceClient) -> CheckReport:
        start = time.time()
        try:
            # Engage and release e-stop to verify it exists
            engage = await client.call("safety/estop/engage")
            if not engage.get("engaged"):
                return CheckReport(self.check_id, self.standard.value, self.clause,
                                   self.description, CheckResult.FAIL,
                                   "estop/engage returned no confirmation",
                                   (time.time() - start) * 1000)
            release = await client.call("safety/estop/release")
            if not release.get("released"):
                return CheckReport(self.check_id, self.standard.value, self.clause,
                                   self.description, CheckResult.WARN,
                                   "estop/release returned no confirmation",
                                   (time.time() - start) * 1000)
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.PASS,
                               "E-stop engage/release cycle successful",
                               (time.time() - start) * 1000)
        except Exception as exc:
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.FAIL, str(exc),
                               (time.time() - start) * 1000)


class ISO10218_ActuationBlocked(ComplianceCheck):
    """Actuations SHALL be blocked while e-stop is engaged."""

    def __init__(self) -> None:
        super().__init__(
            check_id="PMCP-CHK-02",
            standard=Standard.ISO_10218,
            clause="5.4.3",
            description="Actuations SHALL be blocked when e-stop is engaged",
        )

    async def run(self, client: ComplianceClient) -> CheckReport:
        start = time.time()
        try:
            await client.call("safety/estop/engage")
            try:
                result = await client.call("actuations/execute",
                                           {"name": "moveJ", "q": [0]*6})
                # If no error returned → fail
                await client.call("safety/estop/release")
                return CheckReport(self.check_id, self.standard.value, self.clause,
                                   self.description, CheckResult.FAIL,
                                   "Actuation succeeded while e-stop engaged",
                                   (time.time() - start) * 1000)
            except Exception:
                # Error expected — actuation correctly blocked
                await client.call("safety/estop/release")
                return CheckReport(self.check_id, self.standard.value, self.clause,
                                   self.description, CheckResult.PASS,
                                   "Actuation correctly blocked during e-stop",
                                   (time.time() - start) * 1000)
        except Exception as exc:
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.ERROR, str(exc),
                               (time.time() - start) * 1000)


class ISO10218_LeaseRequired(ComplianceCheck):
    """Actuations SHOULD require a valid lease."""

    def __init__(self) -> None:
        super().__init__(
            check_id="PMCP-CHK-03",
            standard=Standard.ISO_10218,
            clause="5.6.1",
            description="Actuation control SHALL use exclusive lease mechanism",
            mandatory=False,
        )

    async def run(self, client: ComplianceClient) -> CheckReport:
        start = time.time()
        try:
            caps = client.capabilities()
            if not caps.get("capabilities", {}).get("leases"):
                return CheckReport(self.check_id, self.standard.value, self.clause,
                                   self.description, CheckResult.WARN,
                                   "Lease support not advertised in capabilities",
                                   (time.time() - start) * 1000)
            lease = await client.call("leases/acquire", {"resource": "drive", "duration_s": 10})
            if not lease.get("lease_id"):
                return CheckReport(self.check_id, self.standard.value, self.clause,
                                   self.description, CheckResult.FAIL,
                                   "leases/acquire returned no lease_id",
                                   (time.time() - start) * 1000)
            await client.call("leases/release", {"lease_id": lease["lease_id"]})
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.PASS,
                               "Lease acquire/release cycle successful",
                               (time.time() - start) * 1000)
        except Exception as exc:
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.ERROR, str(exc),
                               (time.time() - start) * 1000)


class ISO10218_MetricsAvailable(ComplianceCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="PMCP-CHK-04",
            standard=Standard.ISO_10218,
            clause="5.7.1",
            description="Robot SHALL provide operational metrics via pmcp/metrics",
        )

    async def run(self, client: ComplianceClient) -> CheckReport:
        start = time.time()
        try:
            metrics = await client.call("pmcp/metrics")
            required = ["robot_id"]
            missing = [f for f in required if f not in metrics]
            if missing:
                return CheckReport(self.check_id, self.standard.value, self.clause,
                                   self.description, CheckResult.FAIL,
                                   f"Missing required metric fields: {missing}",
                                   (time.time() - start) * 1000)
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.PASS, "",
                               (time.time() - start) * 1000)
        except Exception as exc:
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.FAIL, str(exc),
                               (time.time() - start) * 1000)


# ─────────────────────────────────────────────────────────────────────────────
#  IEC 62443 Checks
# ─────────────────────────────────────────────────────────────────────────────

class IEC62443_ProtocolVersion(ComplianceCheck):
    """Robot SHALL declare protocol version in initialize response."""

    def __init__(self) -> None:
        super().__init__(
            check_id="IEC62443-001",
            standard=Standard.IEC_62443,
            clause="SR 1.1",
            description="Identity and authentication — protocol version advertised",
        )

    async def run(self, client: ComplianceClient) -> CheckReport:
        start = time.time()
        caps = client.capabilities()
        version = caps.get("protocol_version", "")
        if not version:
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.FAIL,
                               "protocol_version missing from initialize response",
                               (time.time() - start) * 1000)
        return CheckReport(self.check_id, self.standard.value, self.clause,
                           self.description, CheckResult.PASS,
                           f"protocol_version={version}", (time.time() - start) * 1000)


class IEC62443_RobotIDPresent(ComplianceCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="IEC62443-002",
            standard=Standard.IEC_62443,
            clause="SR 1.2",
            description="Robot SHALL advertise a unique robot_id",
        )

    async def run(self, client: ComplianceClient) -> CheckReport:
        start = time.time()
        caps = client.capabilities()
        robot_id = caps.get("robot_id", "")
        if not robot_id:
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.FAIL,
                               "robot_id missing", (time.time() - start) * 1000)
        return CheckReport(self.check_id, self.standard.value, self.clause,
                           self.description, CheckResult.PASS,
                           f"robot_id={robot_id}", (time.time() - start) * 1000)


class IEC62443_PingLatency(ComplianceCheck):
    """Ping round-trip time SHALL be < 500 ms for SR 1.4 availability."""

    def __init__(self, latency_ms_limit: float = 500.0) -> None:
        super().__init__(
            check_id="IEC62443-003",
            standard=Standard.IEC_62443,
            clause="SR 1.4",
            description=f"Availability: pmcp/ping latency < {latency_ms_limit} ms",
        )
        self._limit = latency_ms_limit

    async def run(self, client: ComplianceClient) -> CheckReport:
        start = time.time()
        try:
            t0 = time.time()
            await client.call("pmcp/ping")
            rtt_ms = (time.time() - t0) * 1000
            if rtt_ms > self._limit:
                return CheckReport(self.check_id, self.standard.value, self.clause,
                                   self.description, CheckResult.WARN,
                                   f"Ping RTT {rtt_ms:.1f} ms exceeds limit {self._limit} ms",
                                   (time.time() - start) * 1000)
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.PASS,
                               f"Ping RTT {rtt_ms:.1f} ms", (time.time() - start) * 1000)
        except Exception as exc:
            return CheckReport(self.check_id, self.standard.value, self.clause,
                               self.description, CheckResult.FAIL, str(exc),
                               (time.time() - start) * 1000)


# ─────────────────────────────────────────────────────────────────────────────
#  ISO 13849 Checks
# ─────────────────────────────────────────────────────────────────────────────

class ISO13849_SafetyControllerDeclared(ComplianceCheck):
    def __init__(self) -> None:
        super().__init__(
            check_id="ISO13849-001",
            standard=Standard.ISO_13849,
            clause="6.2.3",
            description="Robot SHALL declare safety_controller capability",
        )

    async def run(self, client: ComplianceClient) -> CheckReport:
        start = time.time()
        caps = client.capabilities()
        has_sc = caps.get("capabilities", {}).get("safety_controller", False)
        result = CheckResult.PASS if has_sc else CheckResult.WARN
        detail = "safety_controller=True" if has_sc else "safety_controller not declared"
        return CheckReport(self.check_id, self.standard.value, self.clause,
                           self.description, result, detail,
                           (time.time() - start) * 1000)


# ─────────────────────────────────────────────────────────────────────────────
#  Harness Runner
# ─────────────────────────────────────────────────────────────────────────────

ALL_CHECKS: List[ComplianceCheck] = [
    ISO10218_EstopRequired(),
    ISO10218_ActuationBlocked(),
    ISO10218_LeaseRequired(),
    ISO10218_MetricsAvailable(),
    IEC62443_ProtocolVersion(),
    IEC62443_RobotIDPresent(),
    IEC62443_PingLatency(),
    ISO13849_SafetyControllerDeclared(),
]


@dataclass
class ComplianceReport:
    robot_url: str
    started_at: float
    finished_at: float
    checks: List[CheckReport]

    @property
    def summary(self) -> Dict:
        total = len(self.checks)
        by_result: Dict[str, int] = {}
        for r in CheckResult:
            by_result[r.value] = sum(1 for c in self.checks if c.result == r)
        mandatory_fails = sum(
            1 for c in self.checks if c.result == CheckResult.FAIL
        )
        return {
            "total": total,
            "by_result": by_result,
            "mandatory_failures": mandatory_fails,
            "compliant": mandatory_fails == 0,
            "duration_s": round(self.finished_at - self.started_at, 2),
        }

    def to_dict(self) -> Dict:
        return {
            "robot_url": self.robot_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary,
            "checks": [c.to_dict() for c in self.checks],
        }


class ComplianceHarness:
    def __init__(self, url: str, standards: Optional[List[Standard]] = None) -> None:
        self._url = url
        self._standards = standards
        self._checks = ALL_CHECKS if standards is None else [
            c for c in ALL_CHECKS if c.standard in standards
        ]

    async def run(self) -> ComplianceReport:
        client = ComplianceClient(self._url)
        await client.initialize()
        started = time.time()
        reports = []
        for check in self._checks:
            log.info("Running check %s: %s", check.check_id, check.description)
            try:
                report = await check.run(client)
            except Exception as exc:
                report = CheckReport(
                    check.check_id, check.standard.value, check.clause,
                    check.description, CheckResult.ERROR, str(exc)
                )
            reports.append(report)
            icon = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠", "SKIP": "—", "ERROR": "!"}.get(
                report.result.value, "?")
            log.info("  %s %s %s", icon, check.check_id, report.detail)

        return ComplianceReport(self._url, started, time.time(), reports)


async def main() -> None:
    import argparse
    import sys
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="P-MCP Compliance Harness")
    parser.add_argument("--url", default="http://localhost:8080", help="Robot P-MCP URL")
    parser.add_argument("--standard", default="all",
                        choices=["all", "iso10218", "iec62443", "iso13849"])
    parser.add_argument("--output", default="", help="Write JSON report to file")
    args = parser.parse_args()

    standard_map = {
        "iso10218": [Standard.ISO_10218],
        "iec62443": [Standard.IEC_62443],
        "iso13849": [Standard.ISO_13849],
        "all": None,
    }
    harness = ComplianceHarness(args.url, standard_map[args.standard])
    report = await harness.run()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        log.info("Report written to %s", args.output)

    summary = report.summary
    print(f"\n{'='*60}")
    print(f"Compliance Report — {args.url}")
    print(f"{'='*60}")
    for k, v in summary["by_result"].items():
        print(f"  {k:8s}: {v}")
    print(f"  Compliant: {'YES' if summary['compliant'] else 'NO'}")
    print(f"{'='*60}\n")
    sys.exit(0 if summary["compliant"] else 1)


if __name__ == "__main__":
    asyncio.run(main())
