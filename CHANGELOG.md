# Changelog — pmcp-safety

All notable changes to the safety sub-project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-09-28

First tagged public release.

### Added

- `SECURITY.md` that leads with the thing a reader most needs to know:
  **the TEE attestator and the safety loop are mock-backed and are not
  security boundaries today.** Anything gated on an attestation result
  or on the safety loop's simulated verdict is currently gated on
  nothing. In-scope items are listed per module, with the multisig
  gate and the network-facing `edge/` middleware called out as the
  parts most worth a careful look.
- `CONTRIBUTING.md` stating **fail-closed as a hard requirement**: a
  new error path may reject an operation, but it may never convert a
  rejection into a pass or swallow an exception into a "safe" verdict.

### Known limitations (documented, not fixed)

- **`tee-attestator/` returns `MOCK_QUOTE`.** Enclave "public keys" are
  hardcoded byte strings such as `b"mock_public_key_001"`. The
  interface is real; the backend is a placeholder. A real SGX / SEV-SNP
  / TDX verification path is the highest-value change available here.
- **`safety-loop/` defaults to `--simulator mock`.** The Gazebo path is
  flagged as not fully implemented in the source.
- **There is no test suite in this repository.** Behaviour is exercised
  only indirectly through `pmcp-python/tests/test_compliance.py` and
  the safety loop's own smoke script. For a repository whose modules
  are a safety loop and a signing gate, that is the obvious gap to
  close.
- **No package metadata or version.** There is nothing to install yet.
- `ShadowPreview` / `ShadowStatus` still exist as three separate copies
  across `pmcp-python/{pmcp,sdk,v05}/types.py`. The intended end-state
  is a single canonical definition here, re-exported from `pmcp-python`.

### Changed

- Split into its own repository so SDKs can depend on these modules
  rather than embed them.

## [0.5.0]

Modules established in the pre-split monorepo: safety loop, TEE
attestator, ISO 10218 / IEC 62443 compliance harness, m-of-n multisig
gate, and edge hardening middleware.
