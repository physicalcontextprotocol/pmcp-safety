#!/usr/bin/env python3
"""
PCP Quote Generation Service
===============================

Generate attestation quotes for TEE verification.

Usage:
    python -m tee_attestator.quote_service
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s [%(name)s] %(message)s')
logger = logging.getLogger("pmcp-quote-service")


class QuoteType(Enum):
    """Types of attestation quotes."""
    SGX_QUOTE = "sgx_quote"
    NITRO_ATTESTATION = "nitro_attestation"
    MOCK_QUOTE = "mock_quote"


@dataclass
class PCRValue:
    """Platform Configuration Register value."""
    pcr_index: str
    value: str
    hash_algorithm: str = "sha256"
    extended: bool = False


@dataclass
class AttestationQuote:
    """Attestation quote from TEE."""
    quote_id: str
    quote_type: QuoteType
    enclave_measurement: str
    user_data: bytes
    pcr_values: List[PCRValue] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    expiration: Optional[float] = None
    signature: Optional[bytes] = None


@dataclass
class QuoteRequest:
    """Request for quote generation."""
    request_id: str
    enclave_id: str
    user_data: bytes
    pcr_selection: List[str] = field(default_factory=list)
    nonce: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    created_at: float = field(default_factory=time.time)


class QuoteGenerator:
    """Generate attestation quotes."""

    def __init__(self):
        self._pending_requests: Dict[str, QuoteRequest] = {}
        self._completed_quotes: Dict[str, AttestationQuote] = {}
        self._enclave_keys: Dict[str, Dict[str, bytes]] = {}
        self._initialize_mock_enclave()

    def _initialize_mock_enclave(self):
        """Initialize mock enclave keys."""
        self._enclave_keys = {
            "enclave-robot-control-001": {
                "public": b"mock_public_key_001",
                "private": b"mock_private_key_001",
            },
            "enclave-safety-001": {
                "public": b"mock_public_key_safety",
                "private": b"mock_private_key_safety",
            },
        }

    def create_request(
        self,
        enclave_id: str,
        user_data: bytes,
        pcr_selection: Optional[List[str]] = None
    ) -> QuoteRequest:
        """Create a new quote request."""
        request_id = f"quote-req-{uuid.uuid4().hex[:16]}"

        if pcr_selection is None:
            pcr_selection = ["PCR0", "PCR8", "PCR15"]

        request = QuoteRequest(
            request_id=request_id,
            enclave_id=enclave_id,
            user_data=user_data,
            pcr_selection=pcr_selection,
        )

        self._pending_requests[request_id] = request
        return request

    def generate_quote(self, request: QuoteRequest) -> AttestationQuote:
        """Generate an attestation quote."""
        enclave_keys = self._enclave_keys.get(request.enclave_id)
        if not enclave_keys:
            raise ValueError(f"Enclave not registered: {request.enclave_id}")

        pcr_values = []
        for pcr_index in request.pcr_selection:
            pcr_value = self._calculate_pcr(pcr_index, request, enclave_keys)
            pcr_values.append(pcr_value)

        measurement = self._calculate_enclave_measurement(request, enclave_keys)

        quote_data = self._create_quote_payload(
            measurement, request.user_data, pcr_values
        )

        signature = self._sign_quote(quote_data, enclave_keys["private"])

        quote = AttestationQuote(
            quote_id=f"quote-{uuid.uuid4().hex[:16]}",
            quote_type=QuoteType.MOCK_QUOTE,
            enclave_measurement=measurement,
            user_data=request.user_data,
            pcr_values=pcr_values,
            timestamp=time.time(),
            expiration=time.time() + 3600,
            signature=signature,
        )

        self._completed_quotes[quote.quote_id] = quote
        return quote

    def _calculate_pcr(
        self,
        pcr_index: str,
        request: QuoteRequest,
        enclave_keys: Dict[str, bytes]
    ) -> PCRValue:
        """Calculate PCR value."""
        pcr_data = f"{pcr_index}:{request.enclave_id}:{request.nonce.hex()}".encode()

        if pcr_index == "PCR8":
            pcr_data += b":user_data:" + request.user_data

        pcr_hash = hashlib.sha256(pcr_data).hexdigest()

        return PCRValue(
            pcr_index=pcr_index,
            value=pcr_hash,
            hash_algorithm="sha256",
            extended=True,
        )

    def _calculate_enclave_measurement(
        self,
        request: QuoteRequest,
        enclave_keys: Dict[str, bytes]
    ) -> str:
        """Calculate enclave measurement (MRENCLAVE)."""
        measurement_data = (
            enclave_keys["public"] +
            request.user_data +
            request.nonce
        )
        return hashlib.sha256(measurement_data).hexdigest()

    def _create_quote_payload(
        self,
        measurement: str,
        user_data: bytes,
        pcr_values: List[PCRValue]
    ) -> bytes:
        """Create quote payload."""
        payload = {
            "measurement": measurement,
            "user_data": user_data.hex(),
            "pcrs": [
                {"index": p.pcr_index, "value": p.value}
                for p in pcr_values
            ],
            "timestamp": time.time(),
        }
        return json.dumps(payload).encode()

    def _sign_quote(self, payload: bytes, private_key: bytes) -> bytes:
        """Sign the quote payload."""
        signature = hmac.new(private_key, payload, hashlib.sha256).digest()
        return signature

    def verify_quote(
        self,
        quote: AttestationQuote,
        expected_measurement: str,
        expected_pcrs: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, Optional[str]]:
        """Verify an attestation quote."""
        if quote.enclave_measurement != expected_measurement:
            return False, f"Measurement mismatch: {quote.enclave_measurement} != {expected_measurement}"

        if expected_pcrs:
            quote_pcrs = {p.pcr_index: p.value for p in quote.pcr_values}
            for pcr_index, expected_value in expected_pcrs.items():
                if quote_pcrs.get(pcr_index) != expected_value:
                    return False, f"PCR {pcr_index} mismatch"

        if quote.expiration and time.time() > quote.expiration:
            return False, "Quote has expired"

        return True, None

    def get_quote(self, quote_id: str) -> Optional[AttestationQuote]:
        """Get a quote by ID."""
        return self._completed_quotes.get(quote_id)

    def list_quotes(self, enclave_id: Optional[str] = None) -> List[AttestationQuote]:
        """List all quotes."""
        if enclave_id:
            return [q for q in self._completed_quotes.values() if q.enclave_measurement]
        return list(self._completed_quotes.values())


class QuoteService:
    """Quote generation service API."""

    def __init__(self, generator: QuoteGenerator):
        self.generator = generator

    async def handle_create_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle quote request creation."""
        enclave_id = data.get("enclave_id")
        if not enclave_id:
            return {"error": "Missing enclave_id"}, 400

        user_data_hex = data.get("user_data", "")
        user_data = bytes.fromhex(user_data_hex) if user_data_hex else secrets.token_bytes(64)

        pcr_selection = data.get("pcr_selection")

        request = self.generator.create_request(enclave_id, user_data, pcr_selection)

        return {
            "requestId": request.request_id,
            "enclaveId": request.enclave_id,
            "nonce": request.nonce.hex(),
            "pcrSelection": request.pcr_selection,
            "createdAt": request.created_at,
        }

    async def handle_generate_quote(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle quote generation."""
        request_id = data.get("request_id")
        if not request_id:
            return {"error": "Missing request_id"}, 400

        request = self.generator._pending_requests.get(request_id)
        if not request:
            return {"error": "Request not found"}, 404

        quote = self.generator.generate_quote(request)

        del self.generator._pending_requests[request_id]

        return {
            "quoteId": quote.quote_id,
            "quoteType": quote.quote_type.value,
            "enclaveMeasurement": quote.enclave_measurement,
            "pcrValues": [
                {"index": p.pcr_index, "value": p.value}
                for p in quote.pcr_values
            ],
            "timestamp": quote.timestamp,
            "expiration": quote.expiration,
            "signature": quote.signature.hex() if quote.signature else None,
        }

    async def handle_verify_quote(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle quote verification."""
        quote_id = data.get("quote_id")
        expected_measurement = data.get("expected_measurement")
        expected_pcrs = data.get("expected_pcrs")

        quote = self.generator.get_quote(quote_id)
        if not quote:
            return {"error": "Quote not found"}, 404

        if not expected_measurement:
            return {"error": "Missing expected_measurement"}, 400

        valid, error = self.generator.verify_quote(quote, expected_measurement, expected_pcrs)

        return {
            "quoteId": quote_id,
            "valid": valid,
            "error": error,
            "enclaveMeasurement": quote.enclave_measurement,
            "timestamp": quote.timestamp,
        }


async def main():
    """Run quote service."""
    generator = QuoteGenerator()
    service = QuoteService(generator)

    request = generator.create_request(
        "enclave-robot-control-001",
        b"test_user_data",
        ["PCR0", "PCR8"]
    )
    logger.info(f"Created request: {request.request_id}")

    quote = generator.generate_quote(request)
    logger.info(f"Generated quote: {quote.quote_id}")
    logger.info(f"Enclave measurement: {quote.enclave_measurement}")

    valid, error = generator.verify_quote(quote, quote.enclave_measurement)
    logger.info(f"Verification result: valid={valid}, error={error}")

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())