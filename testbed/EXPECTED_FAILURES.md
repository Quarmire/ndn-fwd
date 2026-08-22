# Expected Failures — see the frozen ndn-rs ledger

This file was a stale fork of the audit ledger that lives in the sibling
**ndn-rs** repo. The authoritative record — frozen 2026-07-01 when `cargo
nextest` became the single source of truth for in-repo behavior — is
[`ndn-rs/testbed/EXPECTED_FAILURES.md`](https://github.com/Quarmire/ndn-rs/blob/main/testbed/EXPECTED_FAILURES.md).

> **Note (2026-08-21):** this testbed's forwarder image has not been
> re-validated since the fork diverged from the ndn-rs ledger. Re-run the
> interop harness (`testbed/tests/interop/`) against a freshly built image
> before citing any historical PASS/FAIL row for it.
