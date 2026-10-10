# Security policy — pcp-safety

The default policy for this organization lives in
[`pcp-spec/SECURITY.md`](https://github.com/physicalcontextprotocol/pcp-spec/blob/main/SECURITY.md)
and applies here in full. This file records what is specific to the
safety sub-project.

## Reporting

Use **private vulnerability reporting**:
**Security → Report a vulnerability** on this repository, or
[open an org-level advisory](https://github.com/physicalcontextprotocol/security/advisories/new).

Do not open a public issue.

## Read this first

Two modules here are **mock-backed by default** and their README says
so, but it is worth repeating in a security policy:

- `tee-attestator/` returns `MOCK_QUOTE`. The enclave "public keys" are
  hardcoded byte strings such as `b"mock_public_key_001"`. The interface
  is real; the backend is a placeholder.
- `safety-loop/` defaults to `--simulator mock`. The Gazebo path is
  flagged as not fully implemented in the source.

**Do not treat either as a security boundary.** Anything gated on
attestation results or on the safety loop's simulated verdict is, today,
gated on nothing. If you need a real boundary, you must supply a real
SGX / SEV-SNP / TDX verification path and a real robot.

## In scope here

- `multisig/` — a bypass of the m-of-n signing gate, or a signature
  verification that accepts a forged or wrong-key signature.
- `edge/` — a rate limiter, input validator, or TLS config that can be
  trivially defeated by an input the validator is supposed to reject.
  This middleware is the network-facing part of this repository.
- `compliance/` — a self-check that reports PASS on a condition it did
  not actually test.
- A safety-loop or attestator code path that fails *closed* being
  changed to fail *open*, or an error being swallowed into a "safe"
  verdict.
- Leaked secrets or credentials in this repository.

## Out of scope here

- The mock backends themselves. They are documented.
- The `m-of-n` threshold default. Changing it is a configuration
  decision, not a vulnerability.
- Missing coverage. There is no test suite in this repository yet;
  behaviour is exercised indirectly through `pcp-python`.

## Supported

Best-effort. No supported-version table yet.
