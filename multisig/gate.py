"""
P-MCP Human-AI Multisig Safety Gate
=====================================
Implements a multi-signature approval gate for high-risk robot commands.

An actuation request that exceeds a risk threshold is held in a *Pending* queue.
A quorum of human operators and/or autonomous AI validators must co-sign the
request before it is forwarded to the robot.

Concepts
--------
SigningParty  — a human operator or AI validator that can sign/reject
PendingApproval — a held actuation waiting for quorum
MultisigPolicy  — defines the quorum rule (e.g. "2-of-3 humans + 1 AI")
MultisigGate    — the main gate: submits requests, collects signatures,
                  executes when policy satisfied, expires/rejects on timeout

Wire protocol (JSON-RPC 2.0):
  multisig/submit    { robot_id, method, params, risk_score } → approval_id
  multisig/sign      { approval_id, party_id, decision, comment } → status
  multisig/list      { [status] } → list of pending/approved/rejected
  multisig/status    { approval_id } → detail
  multisig/policies  {} → list of active policies
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("pmcp.multisig")


class PartyType(str, Enum):
    HUMAN = "human"
    AI = "ai"


class Decision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"


# ─────────────────────────────────────────────────────────────────────────────
#  Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SigningParty:
    party_id: str
    name: str
    party_type: PartyType
    public_key: str = ""     # Ed25519 pubkey (hex) for production; empty = trust-all dev mode


@dataclass
class Signature:
    party_id: str
    party_type: PartyType
    decision: Decision
    comment: str
    signed_at: float = field(default_factory=time.time)
    sig_hash: str = ""       # HMAC of (approval_id + decision + comment) in production


@dataclass
class MultisigPolicy:
    policy_id: str
    name: str
    risk_threshold: float       # requests with risk_score >= this value require multisig
    required_human_approvals: int
    required_ai_approvals: int
    timeout_s: float = 300.0   # 5 minutes default
    allow_self_reject: bool = True

    def is_satisfied(self, sigs: List[Signature]) -> bool:
        approved = [s for s in sigs if s.decision == Decision.APPROVE]
        h = sum(1 for s in approved if s.party_type == PartyType.HUMAN)
        a = sum(1 for s in approved if s.party_type == PartyType.AI)
        return h >= self.required_human_approvals and a >= self.required_ai_approvals

    def is_rejected(self, sigs: List[Signature]) -> bool:
        rejected = [s for s in sigs if s.decision == Decision.REJECT]
        return len(rejected) > 0  # any single rejection blocks


@dataclass
class PendingApproval:
    approval_id: str
    robot_id: str
    method: str
    params: Dict
    risk_score: float
    policy_id: str
    submitted_at: float
    expires_at: float
    signatures: List[Signature] = field(default_factory=list)
    status: ApprovalStatus = ApprovalStatus.PENDING
    digest: str = ""           # SHA-256 of request for integrity

    def to_dict(self) -> Dict:
        return {
            "approval_id": self.approval_id,
            "robot_id": self.robot_id,
            "method": self.method,
            "params": self.params,
            "risk_score": self.risk_score,
            "policy_id": self.policy_id,
            "submitted_at": self.submitted_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "signatures": [
                {"party_id": s.party_id, "type": s.party_type.value,
                 "decision": s.decision.value, "comment": s.comment,
                 "signed_at": s.signed_at}
                for s in self.signatures
            ],
            "digest": self.digest,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Multisig Gate
# ─────────────────────────────────────────────────────────────────────────────

class MultisigGate:
    """
    Central coordinator for multi-party approval of robot commands.

    Usage:
      gate = MultisigGate()
      gate.add_party(SigningParty("alice", "Alice", PartyType.HUMAN))
      gate.add_party(SigningParty("ai_validator", "Safety AI", PartyType.AI))
      gate.set_policy(MultisigPolicy("default", "Default", 0.7, 2, 1))

      approval_id = await gate.submit("robot-1", "actuations/execute",
                                      {"name": "moveL", "pose": [...]}, risk_score=0.85)
      await gate.sign(approval_id, "alice", Decision.APPROVE, "looks safe")
      await gate.sign(approval_id, "ai_validator", Decision.APPROVE, "validated")
      # → executes automatically when quorum reached
    """

    def __init__(self) -> None:
        self._parties: Dict[str, SigningParty] = {}
        self._policies: Dict[str, MultisigPolicy] = {}
        self._approvals: Dict[str, PendingApproval] = {}
        self._execute_callback: Optional[Callable] = None
        self._default_policy = MultisigPolicy(
            "default", "Default Policy",
            risk_threshold=0.7,
            required_human_approvals=1,
            required_ai_approvals=0,
            timeout_s=300,
        )
        self._policies["default"] = self._default_policy
        asyncio.get_event_loop().call_soon(lambda: asyncio.ensure_future(self._expiry_loop()))

    # -- Configuration ---

    def add_party(self, party: SigningParty) -> None:
        self._parties[party.party_id] = party
        log.info("Added signing party: %s (%s)", party.name, party.party_type.value)

    def set_policy(self, policy: MultisigPolicy) -> None:
        self._policies[policy.policy_id] = policy
        log.info("Set policy: %s (threshold=%.2f, humans=%d, ai=%d)",
                 policy.name, policy.risk_threshold,
                 policy.required_human_approvals, policy.required_ai_approvals)

    def on_execute(self, callback: Callable) -> None:
        """Register callback that receives (approval) when quorum is reached."""
        self._execute_callback = callback

    # -- Core Operations ---

    def _select_policy(self, risk_score: float) -> MultisigPolicy:
        """Select most restrictive applicable policy."""
        applicable = [p for p in self._policies.values() if risk_score >= p.risk_threshold]
        if not applicable:
            return self._default_policy
        return max(applicable, key=lambda p: p.risk_threshold)

    def _compute_digest(self, robot_id: str, method: str, params: Dict) -> str:
        payload = json.dumps({"robot_id": robot_id, "method": method, "params": params},
                             sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    async def submit(self, robot_id: str, method: str, params: Dict,
                     risk_score: float = 0.5) -> str:
        """Submit a request for multisig approval. Returns approval_id."""
        policy = self._select_policy(risk_score)
        approval_id = str(uuid.uuid4())
        now = time.time()
        approval = PendingApproval(
            approval_id=approval_id,
            robot_id=robot_id,
            method=method,
            params=params,
            risk_score=risk_score,
            policy_id=policy.policy_id,
            submitted_at=now,
            expires_at=now + policy.timeout_s,
            digest=self._compute_digest(robot_id, method, params),
        )
        self._approvals[approval_id] = approval
        log.info("Multisig approval requested: %s (%s) risk=%.2f policy=%s",
                 approval_id, method, risk_score, policy.policy_id)
        return approval_id

    async def sign(self, approval_id: str, party_id: str,
                   decision: Decision, comment: str = "") -> ApprovalStatus:
        """Add a signature from a signing party."""
        approval = self._approvals.get(approval_id)
        if approval is None:
            raise ValueError(f"Unknown approval_id: {approval_id}")
        if approval.status != ApprovalStatus.PENDING:
            raise ValueError(f"Approval {approval_id} is already {approval.status.value}")

        party = self._parties.get(party_id)
        if party is None:
            raise ValueError(f"Unknown party: {party_id}")

        if time.time() > approval.expires_at:
            approval.status = ApprovalStatus.EXPIRED
            return ApprovalStatus.EXPIRED

        # Prevent duplicate signatures
        if any(s.party_id == party_id for s in approval.signatures):
            raise ValueError(f"Party {party_id} already signed")

        sig = Signature(
            party_id=party_id,
            party_type=party.party_type,
            decision=decision,
            comment=comment,
        )
        approval.signatures.append(sig)
        log.info("Signature from %s (%s): %s on %s",
                 party.name, party.party_type.value, decision.value, approval_id)

        policy = self._policies.get(approval.policy_id, self._default_policy)

        if policy.is_rejected(approval.signatures):
            approval.status = ApprovalStatus.REJECTED
            log.warning("Approval %s REJECTED", approval_id)
            return ApprovalStatus.REJECTED

        if policy.is_satisfied(approval.signatures):
            approval.status = ApprovalStatus.APPROVED
            await self._execute(approval)
            return ApprovalStatus.EXECUTED

        return ApprovalStatus.PENDING

    async def _execute(self, approval: PendingApproval) -> None:
        approval.status = ApprovalStatus.EXECUTED
        log.info("Executing approved command: %s %s on %s",
                 approval.approval_id, approval.method, approval.robot_id)
        if self._execute_callback:
            try:
                await self._execute_callback(approval)
            except Exception as exc:
                log.error("Execute callback failed: %s", exc)

    async def _expiry_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            now = time.time()
            for approval in list(self._approvals.values()):
                if approval.status == ApprovalStatus.PENDING and now > approval.expires_at:
                    approval.status = ApprovalStatus.EXPIRED
                    log.warning("Approval %s EXPIRED", approval.approval_id)

    def list_approvals(self, status: Optional[ApprovalStatus] = None) -> List[Dict]:
        result = list(self._approvals.values())
        if status:
            result = [a for a in result if a.status == status]
        return [a.to_dict() for a in result]

    def get_approval(self, approval_id: str) -> Optional[Dict]:
        approval = self._approvals.get(approval_id)
        return approval.to_dict() if approval else None

    def list_policies(self) -> List[Dict]:
        return [
            {"policy_id": p.policy_id, "name": p.name,
             "risk_threshold": p.risk_threshold,
             "required_human": p.required_human_approvals,
             "required_ai": p.required_ai_approvals,
             "timeout_s": p.timeout_s}
            for p in self._policies.values()
        ]


# ─────────────────────────────────────────────────────────────────────────────
#  Risk Scorer
# ─────────────────────────────────────────────────────────────────────────────

class RiskScorer:
    """
    Heuristic risk scoring for P-MCP actuation requests.
    Returns a float 0.0 (safe) → 1.0 (extremely dangerous).
    """

    HIGH_RISK_METHODS = {
        "actuations/execute", "safety/estop/release", "actuations/batch",
    }
    HIGH_RISK_ACTUATIONS = {
        "moveL", "moveJ", "walk_to", "navigate_to",
    }
    ESTOP_METHODS = {"safety/estop/engage"}

    def score(self, method: str, params: Dict) -> float:
        if method in self.ESTOP_METHODS:
            return 0.1   # e-stop is safe to call without human approval
        if method not in self.HIGH_RISK_METHODS:
            return 0.0

        actuation_name = params.get("name", "") or params.get("actuation", "")
        if actuation_name in self.HIGH_RISK_ACTUATIONS:
            base = 0.6
        else:
            base = 0.3

        # Increase risk if large motion parameters are present
        pose = params.get("pose") or params.get("target")
        if isinstance(pose, (list, tuple)) and len(pose) >= 3:
            magnitude = sum(abs(float(x)) for x in pose[:3])
            if magnitude > 1.0:
                base = min(1.0, base + 0.2)

        return base
