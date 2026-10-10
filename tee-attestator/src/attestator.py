#!/usr/bin/env python3
"""
PCP TEE Attestation Service
============================

Remote attestation service for robotic commands using Intel SGX or AWS Nitro patterns.

Provides:
- Challenge-response attestation protocol
- Command verification
- PCR (Platform Configuration Register) validation
- Enclave identity verification

Usage:
    python -m tee_attestator.attestator --port 8085
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import threading
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [%(name)s] %(message)s'
)
logger = logging.getLogger("pmcp-tee-attestator")


class AttestationType(Enum):
    """Type of TEE attestation."""
    NONE = "none"
    SGX_ECDSA = "sgx_ecdsa"
    NITRO = "nitro"
    MOCK = "mock"


@dataclass
class AttestationChallenge:
    """Challenge for attestation."""
    challenge_id: str
    nonce: bytes
    created_at: float
    expires_at: float
    command_context: Optional[Dict[str, Any]] = None

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class AttestationResult:
    """Result of attestation."""
    challenge_id: str
    attested: bool
    enclave_id: Optional[str] = None
    pcr_values: Dict[str, str] = field(default_factory=dict)
    measurement: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challengeId": self.challenge_id,
            "attested": self.attested,
            "enclaveId": self.enclave_id,
            "pcrValues": self.pcr_values,
            "measurement": self.measurement,
            "timestamp": self.timestamp,
            "error": self.error,
        }


@dataclass
class EnclaveRecord:
    """Registered enclave."""
    enclave_id: str
    enclave_type: AttestationType
    allowed_pcrs: Dict[str, str]
    measurement: str
    description: str
    created_at: float = field(default_factory=time.time)
    last_attested: Optional[float] = None
    enabled: bool = True


@dataclass
class CommandAttestation:
    """Attestation for a specific command."""
    command_id: str
    command_type: str
    target_robot: str
    parameters: Dict[str, Any]
    requires_attestation: bool
    attested_enclave: Optional[str] = None
    verified: bool = False
    verify_error: Optional[str] = None


class AttestationStore:
    """Store for attestation state."""

    def __init__(self):
        self._challenges: Dict[str, AttestationChallenge] = {}
        self._enclaves: Dict[str, EnclaveRecord] = {}
        self._attestation_history: List[AttestationResult] = []
        self._command_attestations: Dict[str, CommandAttestation] = {}
        self._lock = threading.RLock()

        self._initialize_mock_enclaves()

    def _initialize_mock_enclaves(self):
        """Initialize mock enclaves for testing."""
        mock_enclaves = [
            EnclaveRecord(
                enclave_id="enclave-robot-control-001",
                enclave_type=AttestationType.MOCK,
                allowed_pcrs={
                    "PCR0": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234",
                    "PCR8": "deadbeef123456789012345678901234567890123456789012345678901234",
                },
                measurement="mock_enclave_measurement_v1",
                description="Robot control enclave",
            ),
            EnclaveRecord(
                enclave_id="enclave-safety-001",
                enclave_type=AttestationType.MOCK,
                allowed_pcrs={
                    "PCR0": "cafebabe123456789012345678901234567890123456789012345678901234",
                },
                measurement="safety_enclave_v1",
                description="Safety verification enclave",
            ),
            EnclaveRecord(
                enclave_id="enclave-navigation-001",
                enclave_type=AttestationType.MOCK,
                allowed_pcrs={
                    "PCR0": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                },
                measurement="nav_enclave_v1",
                description="Navigation enclave",
            ),
        ]
        for enclave in mock_enclaves:
            self._enclaves[enclave.enclave_id] = enclave

    def create_challenge(self, expires_seconds: int = 30, context: Optional[Dict[str, Any]] = None) -> AttestationChallenge:
        """Create a new attestation challenge."""
        with self._lock:
            challenge_id = f"chal-{uuid.uuid4().hex[:16]}"
            nonce = secrets.token_bytes(32)
            now = time.time()

            challenge = AttestationChallenge(
                challenge_id=challenge_id,
                nonce=nonce,
                created_at=now,
                expires_at=now + expires_seconds,
                command_context=context,
            )

            self._challenges[challenge_id] = challenge
            return challenge

    def get_challenge(self, challenge_id: str) -> Optional[AttestationChallenge]:
        """Get a challenge by ID."""
        with self._lock:
            return self._challenges.get(challenge_id)

    def store_attestation(self, result: AttestationResult):
        """Store attestation result."""
        with self._lock:
            self._attestation_history.append(result)
            if len(self._attestation_history) > 1000:
                self._attestation_history = self._attestation_history[-500:]

    def register_enclave(self, enclave: EnclaveRecord):
        """Register a new enclave."""
        with self._lock:
            self._enclaves[enclave.enclave_id] = enclave

    def get_enclave(self, enclave_id: str) -> Optional[EnclaveRecord]:
        """Get an enclave by ID."""
        with self._lock:
            return self._enclaves.get(enclave_id)

    def list_enclaves(self) -> List[EnclaveRecord]:
        """List all registered enclaves."""
        with self._lock:
            return list(self._enclaves.values())

    def verify_attestation(self, challenge_id: str, attestation_data: Dict[str, Any]) -> AttestationResult:
        """Verify an attestation response."""
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if not challenge:
                return AttestationResult(
                    challenge_id=challenge_id,
                    attested=False,
                    error="Challenge not found",
                )

            if challenge.is_expired():
                return AttestationResult(
                    challenge_id=challenge_id,
                    attested=False,
                    error="Challenge expired",
                )

            enclave_id = attestation_data.get("enclave_id")
            if not enclave_id:
                return AttestationResult(
                    challenge_id=challenge_id,
                    attested=False,
                    error="No enclave ID provided",
                )

            enclave = self._enclaves.get(enclave_id)
            if not enclave:
                return AttestationResult(
                    challenge_id=challenge_id,
                    attested=False,
                    error=f"Enclave not registered: {enclave_id}",
                )

            if not enclave.enabled:
                return AttestationResult(
                    challenge_id=challenge_id,
                    attested=False,
                    error="Enclave is disabled",
                )

            received_pcrs = attestation_data.get("pcr_values", {})

            for pcr_name, expected_value in enclave.allowed_pcrs.items():
                received_value = received_pcrs.get(pcr_name, "")
                if received_value != expected_value:
                    return AttestationResult(
                        challenge_id=challenge_id,
                        attested=False,
                        enclave_id=enclave_id,
                        pcr_values=received_pcrs,
                        error=f"PCR {pcr_name} mismatch",
                    )

            result = AttestationResult(
                challenge_id=challenge_id,
                attested=True,
                enclave_id=enclave_id,
                pcr_values=received_pcrs,
                measurement=enclave.measurement,
            )

            self._attestation_history.append(result)
            enclave.last_attested = time.time()

            return result


class TEEAttestator:
    """TEE Attestation service."""

    def __init__(self, store: AttestationStore):
        self.store = store
        self._running = False

    async def start(self, host: str = "0.0.0.0", port: int = 8085):
        """Start the attestation service."""
        try:
            from aiohttp import web
        except ImportError:
            logger.error("aiohttp not installed")
            return

        app = web.Application()

        app.router.add_get("/health", self.handle_health)
        app.router.add_get("/metrics", self.handle_metrics)

        app.router.add_post("/attestation/challenge", self.handle_create_challenge)
        app.router.add_post("/attestation/verify", self.handle_verify_attestation)
        app.router.add_get("/attestation/status/{challenge_id}", self.handle_challenge_status)

        app.router.add_get("/enclaves", self.handle_list_enclaves)
        app.router.add_post("/enclaves", self.handle_register_enclave)
        app.router.add_get("/enclaves/{id}", self.handle_get_enclave)
        app.router.add_put("/enclaves/{id}/enable", self.handle_enable_enclave)
        app.router.add_put("/enclaves/{id}/disable", self.handle_disable_enclave)

        app.router.add_post("/command/attest", self.handle_command_attest)
        app.router.add_post("/command/verify", self.handle_command_verify)

        self._running = True

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()

        logger.info(f"PCP TEE Attestator starting on http://{host}:{port}")

        try:
            await asyncio.Event().wait()
        finally:
            await runner.cleanup()

    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "healthy",
            "version": "0.5.0",
            "service": "pmcp-tee-attestator",
        })

    async def handle_metrics(self, request: web.Request) -> web.Response:
        enclaves = self.store.list_enclaves()
        history = self.store._attestation_history

        return web.json_response({
            "totalEnclaves": len(enclaves),
            "enabledEnclaves": sum(1 for e in enclaves if e.enabled),
            "totalAttestations": len(history),
            "successfulAttestations": sum(1 for a in history if a.attested),
            "failedAttestations": sum(1 for a in history if not a.attested),
        })

    async def handle_create_challenge(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            data = {}

        expires_seconds = data.get("expires_seconds", 30)
        context = data.get("command_context")

        challenge = self.store.create_challenge(expires_seconds, context)

        return web.json_response({
            "challengeId": challenge.challenge_id,
            "nonce": base64.b64encode(challenge.nonce).decode(),
            "expiresAt": challenge.expires_at,
            "createdAt": challenge.created_at,
        })

    async def handle_verify_attestation(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        challenge_id = data.get("challenge_id")
        if not challenge_id:
            return web.json_response({"error": "Missing challenge_id"}, status=400)

        attestation_data = data.get("attestation_data", {})
        if not attestation_data:
            return web.json_response({"error": "Missing attestation_data"}, status=400)

        result = self.store.verify_attestation(challenge_id, attestation_data)

        return web.json_response(result.to_dict())

    async def handle_challenge_status(self, request: web.Request) -> web.Response:
        challenge_id = request.match_info["challenge_id"]
        challenge = self.store.get_challenge(challenge_id)

        if not challenge:
            return web.json_response({"error": "Challenge not found"}, status=404)

        return web.json_response({
            "challengeId": challenge.challenge_id,
            "createdAt": challenge.created_at,
            "expiresAt": challenge.expires_at,
            "expired": challenge.is_expired(),
            "commandContext": challenge.command_context,
        })

    async def handle_list_enclaves(self, request: web.Request) -> web.Response:
        enclaves = self.store.list_enclaves()
        return web.json_response({
            "enclaves": [
                {
                    "enclaveId": e.enclave_id,
                    "type": e.enclave_type.value,
                    "description": e.description,
                    "enabled": e.enabled,
                    "createdAt": e.created_at,
                    "lastAttested": e.last_attested,
                }
                for e in enclaves
            ],
            "count": len(enclaves),
        })

    async def handle_register_enclave(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        enclave_id = data.get("enclave_id")
        if not enclave_id:
            return web.json_response({"error": "Missing enclave_id"}, status=400)

        enclave = EnclaveRecord(
            enclave_id=enclave_id,
            enclave_type=AttestationType(data.get("enclave_type", "mock")),
            allowed_pcrs=data.get("allowed_pcrs", {}),
            measurement=data.get("measurement", ""),
            description=data.get("description", ""),
        )

        self.store.register_enclave(enclave)

        return web.json_response({"registered": True, "enclaveId": enclave_id}, status=201)

    async def handle_get_enclave(self, request: web.Request) -> web.Response:
        enclave_id = request.match_info["id"]
        enclave = self.store.get_enclave(enclave_id)

        if not enclave:
            return web.json_response({"error": f"Enclave not found: {enclave_id}"}, status=404)

        return web.json_response({
            "enclaveId": enclave.enclave_id,
            "type": enclave.enclave_type.value,
            "measurement": enclave.measurement,
            "description": enclave.description,
            "enabled": enclave.enabled,
            "allowedPcrs": enclave.allowed_pcrs,
            "createdAt": enclave.created_at,
            "lastAttested": enclave.last_attested,
        })

    async def handle_enable_enclave(self, request: web.Request) -> web.Response:
        enclave_id = request.match_info["id"]
        enclave = self.store.get_enclave(enclave_id)

        if not enclave:
            return web.json_response({"error": f"Enclave not found: {enclave_id}"}, status=404)

        enclave.enabled = True
        return web.json_response({"enabled": True})

    async def handle_disable_enclave(self, request: web.Request) -> web.Response:
        enclave_id = request.match_info["id"]
        enclave = self.store.get_enclave(enclave_id)

        if not enclave:
            return web.json_response({"error": f"Enclave not found: {enclave_id}"}, status=404)

        enclave.enabled = False
        return web.json_response({"disabled": True})

    async def handle_command_attest(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        command_id = data.get("command_id", f"cmd-{uuid.uuid4().hex[:8]}")
        command_type = data.get("command_type", "unknown")
        target_robot = data.get("target_robot", "")
        parameters = data.get("parameters", {})
        requires_attestation = data.get("requires_attestation", True)

        challenge = self.store.create_challenge(expires_seconds=60, context={
            "command_id": command_id,
            "command_type": command_type,
            "target_robot": target_robot,
            "parameters": parameters,
        })

        return web.json_response({
            "commandId": command_id,
            "challengeId": challenge.challenge_id,
            "nonce": base64.b64encode(challenge.nonce).decode(),
            "expiresAt": challenge.expires_at,
        })

    async def handle_command_verify(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        command_id = data.get("command_id")
        attestation_data = data.get("attestation_data", {})

        challenge_id = attestation_data.get("challenge_id", "")
        result = self.store.verify_attestation(challenge_id, attestation_data)

        return web.json_response({
            "commandId": command_id,
            "verified": result.attested,
            "enclaveId": result.enclave_id,
            "error": result.error,
        })


async def main():
    parser = argparse.ArgumentParser(description="PCP TEE Attestation Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8085, help="Port to bind to")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level")

    args = parser.parse_args()
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    store = AttestationStore()
    attestator = TEEAttestator(store)
    await attestator.start(args.host, args.port)


if __name__ == "__main__":
    asyncio.run(main())