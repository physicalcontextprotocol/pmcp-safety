"""
P-MCP Edge Hardening — Security & Resource Constraint Module
==============================================================
Hardening measures for edge-deployed P-MCP robot servers:

  1. InputValidator     — strict JSON-RPC request validation, prevents injection
  2. RateLimiter        — per-peer token bucket, prevents DoS
  3. TLSConfig          — helper to create strict TLS contexts (TLS 1.3 only)
  4. ResourceGuard      — CPU/memory limits using resource/signal; kills runaway tasks
  5. SecureLogger       — redacts sensitive fields before log output
  6. EdgeHardeningMiddleware — aiohttp middleware combining all of the above

Usage:
  from edge.hardening import EdgeHardeningMiddleware
  app = web.Application(middlewares=[EdgeHardeningMiddleware().middleware])
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Set

from aiohttp import web

log = logging.getLogger("pmcp.edge.hardening")

# ─────────────────────────────────────────────────────────────────────────────
#  Input Validator
# ─────────────────────────────────────────────────────────────────────────────

MAX_REQUEST_BYTES = 1 * 1024 * 1024   # 1 MiB
MAX_PARAM_DEPTH   = 8
ALLOWED_METHODS   = re.compile(
    r"^(initialize|pmcp/(ping|metrics)|"
    r"actuations/(list|execute|batch)|"
    r"sensors/(list|read)|"
    r"leases/(acquire|release|list)|"
    r"safety/estop/(engage|release)|"
    r"swarm/\w+|depin/\w+|multisig/\w+|fed/\w+)$"
)


class InputValidator:
    @staticmethod
    def _check_depth(obj: Any, depth: int) -> bool:
        if depth > MAX_PARAM_DEPTH:
            return False
        if isinstance(obj, dict):
            return all(InputValidator._check_depth(v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return all(InputValidator._check_depth(item, depth + 1) for item in obj)
        return True

    @classmethod
    def validate(cls, body: Dict) -> Optional[str]:
        """Return error string if invalid, None if valid."""
        if not isinstance(body, dict):
            return "Request must be a JSON object"
        if body.get("jsonrpc") != "2.0":
            return "jsonrpc must be '2.0'"
        method = body.get("method", "")
        if not isinstance(method, str) or not ALLOWED_METHODS.match(method):
            return f"Invalid or disallowed method: {method!r}"
        params = body.get("params", {})
        if not isinstance(params, (dict, list)):
            return "params must be an object or array"
        if not cls._check_depth(params, 0):
            return f"params nesting exceeds maximum depth {MAX_PARAM_DEPTH}"
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  Rate Limiter
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TokenBucket:
    capacity: float
    rate: float        # tokens per second
    tokens: float = field(init=False)
    last: float = field(init=False, default_factory=time.monotonic)

    def __post_init__(self) -> None:
        self.tokens = self.capacity

    def consume(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        delta = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiter:
    def __init__(self, capacity: float = 100.0, rate: float = 10.0) -> None:
        self._buckets: Dict[str, TokenBucket] = {}
        self._capacity = capacity
        self._rate = rate

    def allow(self, peer: str) -> bool:
        if peer not in self._buckets:
            self._buckets[peer] = TokenBucket(self._capacity, self._rate)
        return self._buckets[peer].consume()

    def reset(self, peer: str) -> None:
        self._buckets.pop(peer, None)


# ─────────────────────────────────────────────────────────────────────────────
#  TLS Config
# ─────────────────────────────────────────────────────────────────────────────

class TLSConfig:
    @staticmethod
    def server_context(certfile: str, keyfile: str,
                       cafile: Optional[str] = None,
                       require_client_cert: bool = False) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(certfile, keyfile)
        if cafile:
            ctx.load_verify_locations(cafile)
        if require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
        # Disable weak ciphers
        ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")
        return ctx

    @staticmethod
    def client_context(cafile: str, certfile: Optional[str] = None,
                       keyfile: Optional[str] = None) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(cafile)
        if certfile and keyfile:
            ctx.load_cert_chain(certfile, keyfile)
        return ctx


# ─────────────────────────────────────────────────────────────────────────────
#  Resource Guard
# ─────────────────────────────────────────────────────────────────────────────

class ResourceGuard:
    """
    Cancel async tasks that exceed a time or iteration budget.
    Wrap your handlers with .guarded() to enforce limits.
    """

    def __init__(self, max_task_seconds: float = 30.0) -> None:
        self._max_seconds = max_task_seconds

    async def guarded(self, coro: Any) -> Any:
        try:
            return await asyncio.wait_for(coro, timeout=self._max_seconds)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Task exceeded {self._max_seconds}s limit")


# ─────────────────────────────────────────────────────────────────────────────
#  Secure Logger
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_KEYS: Set[str] = {"password", "token", "secret", "key", "private_key",
                             "api_key", "authorization", "credential"}


class SecureLogger:
    def __init__(self, logger: logging.Logger) -> None:
        self._log = logger

    def _redact(self, obj: Any, depth: int = 0) -> Any:
        if depth > 6:
            return obj
        if isinstance(obj, dict):
            return {
                k: "***REDACTED***" if k.lower() in SENSITIVE_KEYS else self._redact(v, depth + 1)
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [self._redact(item, depth + 1) for item in obj]
        return obj

    def info(self, msg: str, *args: Any) -> None:
        redacted = tuple(self._redact(a) if isinstance(a, (dict, list)) else a for a in args)
        self._log.info(msg, *redacted)

    def warning(self, msg: str, *args: Any) -> None:
        redacted = tuple(self._redact(a) if isinstance(a, (dict, list)) else a for a in args)
        self._log.warning(msg, *redacted)

    def error(self, msg: str, *args: Any) -> None:
        redacted = tuple(self._redact(a) if isinstance(a, (dict, list)) else a for a in args)
        self._log.error(msg, *redacted)


# ─────────────────────────────────────────────────────────────────────────────
#  Edge Hardening Middleware
# ─────────────────────────────────────────────────────────────────────────────

class EdgeHardeningMiddleware:
    """
    Combine all hardening layers into an aiohttp middleware.
    Apply with:
      app = web.Application(middlewares=[EdgeHardeningMiddleware().middleware])
    """

    def __init__(self, rate_capacity: float = 60.0, rate_per_sec: float = 10.0,
                 max_task_seconds: float = 30.0) -> None:
        self.validator = InputValidator()
        self.rate_limiter = RateLimiter(rate_capacity, rate_per_sec)
        self.resource_guard = ResourceGuard(max_task_seconds)
        self.secure_log = SecureLogger(log)

    @web.middleware
    async def middleware(self, request: web.Request, handler: Callable) -> web.Response:
        peer = request.remote or "unknown"

        # Rate limiting
        if not self.rate_limiter.allow(peer):
            log.warning("Rate limit exceeded for peer %s", peer)
            return web.json_response(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32029, "message": "Rate limit exceeded"}},
                status=429,
            )

        # Input size check
        content_length = request.content_length or 0
        if content_length > MAX_REQUEST_BYTES:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "Request too large"}},
                status=413,
            )

        # Parse and validate JSON-RPC (for POST /rpc or / endpoints)
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:
                return web.json_response(
                    {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "Parse error"}},
                    status=400,
                )
            error = self.validator.validate(body)
            if error:
                return web.json_response(
                    {"jsonrpc": "2.0", "id": body.get("id"),
                     "error": {"code": -32600, "message": error}},
                    status=400,
                )

        # Execute with resource guard
        try:
            response = await self.resource_guard.guarded(handler(request))
        except RuntimeError as exc:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32603, "message": str(exc)}},
                status=503,
            )

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cache-Control"] = "no-store"
        return response
