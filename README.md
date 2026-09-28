# pmcp-safety

Safety-critical modules split out as their own sub-project so that
`pmcp-python` (and other SDKs) can depend on them rather than embed
them.

## Contents and maturity

| Module | Purpose | Backend today |
|---|---|---|
| `safety-loop/` | Runtime safety loop (`safety_loop.py`, `safety_extended.py`) — the on-robot control loop that gates every command | Defaults to `--simulator mock`; Gazebo hookup is flagged as "not fully implemented" in the source |
| `tee-attestator/` | TEE attestation service (`attestator.py`) + quote service (`quote_service.py`) | **Mock only.** Returns `MOCK_QUOTE`; enclave "public keys" are hardcoded byte strings (`b"mock_public_key_001"` and similar). The interface is real; the backend is a placeholder. |
| `compliance/` | ISO 10218 / IEC 62443 compliance harness (`harness.py`) | Working self-checks; produces a `ComplianceReport` |
| `multisig/` | m-of-n signing gate for safety-critical actions | Working local Ed25519 signing (via `cryptography`) |
| `edge/` | Edge hardening middleware — `InputValidator`, `RateLimiter`, `TLSConfig`, `SecureLogger` | Working aiohttp middleware |

## How to use

Each sub-module has its own `__init__.py`. There is no top-level
package, so import by sub-path:

```python
from compliance.harness import ComplianceHarness, ALL_CHECKS
from edge.hardening import EdgeHardeningMiddleware, RateLimiter
from multisig.gate import MultisigGate
```

Add the sub-project root to `PYTHONPATH` (or later, install this
sub-project as a proper package):

```bash
export PYTHONPATH="$PWD/pmcp-safety:$PYTHONPATH"
```

There is no test suite in this sub-project as it stands; behaviour is
exercised indirectly through `pmcp-python/tests/test_compliance.py`
and the runtime safety loop's own smoke script (`safety-loop/src/`).

## Known follow-ups (per `MIGRATION_MAP.md`)

- **`ShadowPreview` / `ShadowStatus` type location.** These currently
  live in `pmcp-python/{pmcp,sdk,v05}/types.py` — three separate copies.
  The intended end-state is a single canonical definition in
  `pmcp-safety`, re-exported from `pmcp-python`, so upstream and
  downstream both see the same type. Not done yet; consolidating the
  three copies inside `pmcp-python` should probably come first.
- **`pmcp_kinematics` soft import.** The migration note asked for a
  soft `try/except` import here. In the current tree `pmcp-safety`
  does not import `pmcp_kinematics` at all; the only cross-repo edge
  is `pmcp-python/v05/pmcp_safety_v5.py:412`, which is already a
  function-local (lazy) import, so this fix is moot for now.

## Honest limitations

- The **TEE attestator ships mock enclave keys** and hardcoded quotes.
  It demonstrates the interface; it does **not** validate a real SGX,
  SEV-SNP, or TDX report. Any production use MUST replace
  `MOCK_ENCLAVES` and `MOCK_QUOTE`.
- The **safety-loop simulator defaults to mock**. Wire a real robot
  or Gazebo instance in before drawing production conclusions.

## License

Apache 2.0 (see [`LICENSE`](LICENSE)).
