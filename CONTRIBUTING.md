# Contributing to pmcp-safety

Safety-critical modules split out so the SDKs can depend on them rather
than embed them.

The organization-wide contributor policy lives in
[`physicalcontextprotocol/.github`](https://github.com/physicalcontextprotocol/.github/blob/main/CONTRIBUTING.md).
This file covers what is specific to this repository.

## There is no test suite here yet

That is the first thing worth fixing. There is no `tests/` directory in
this repository; behaviour is currently exercised only indirectly
through `pmcp-python/tests/test_compliance.py` and the safety loop's own
smoke script. For a repository whose modules are named "safety-loop" and
"multisig gate", that gap is the obvious thing to close.

## High-value contributions

- **A real TEE verification path.** `tee-attestator/` returns
  `MOCK_QUOTE` with hardcoded enclave "public keys" such as
  `b"mock_public_key_001"`. Replacing that with actual SGX / SEV-SNP /
  TDX report verification is the single most valuable change available
  here.
- **Wire the safety loop to a real simulator.** It defaults to
  `--simulator mock`; the Gazebo path is flagged as not fully
  implemented in the source.
- **Tests for the multisig gate**, especially a test that an
  under-threshold signature set is rejected.
- **Tests for `edge/`** — it is the network-facing module, so its rate
  limiter and input validator are the parts most worth pinning down.

## Fail-closed is a hard requirement

If you change anything in the safety loop, the attestator, or the
multisig gate, the change must fail **closed**. A new error path may
reject an operation; it may never convert a rejection into a pass, and
it may never swallow an exception into a "safe" verdict. If a review
question comes down to "what happens when this errors?", the correct
answer is "the operation is refused".

## Known follow-up

`ShadowPreview` and `ShadowStatus` currently exist as three separate
copies in `pmcp-python/{pmcp,sdk,v05}/types.py`. The intended end-state
is a single canonical definition here, re-exported from `pmcp-python`.
Consolidating the three copies inside `pmcp-python` would sensibly come
first.

## Releasing

No package metadata yet. There is no version to bump — that gap is
itself worth closing if you are picking something up.
