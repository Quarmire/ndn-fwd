# audit-strict-mgmt-validation

**Internal audit witness.** Not a user-facing tool — runs under the
audit harness to gate spec-compliance finding N.12.

## What it does

Strict-trust validation of an `ndn-fwd` management response:

1. Connects to a running `ndn-fwd`'s management socket.
2. Issues `/localhost/nfd/status/general`.
3. Validates the response Data against a freshly-built `Validator`
   pinned to **only** the daemon's persisted trust anchor — the same
   contract `ndn-cxx`'s `ValidatorConfig` (and any `nfdc` configured
   with a trust schema) would enforce.

Exits `0` if the response validates cleanly against the strict
schema, non-zero otherwise.

## Why not just run `nfdc`?

The audit-doc rationale (preserved verbatim from the crate's
header):

- `nfdc` validates with whatever's in the operator's `client.conf`
  + `validator-config-file`, neither of which it ships defaults for.
  Forcing it into strict mode requires writing both per test run —
  which only proves the wrapping config does what we already know.
- ndn-cxx's actual signature verifier is OpenSSL's
  `EVP_DigestVerify` over ECDSA-P256 + SHA-256, bit-identical to the
  `p256` crate's verifier ndn-rs's `Validator` uses. If ndn-rs's
  validator says `Valid`, so will ndn-cxx's.
- The witness controls both signer and verifier through
  `ndn-security`'s `Validator`, which is the same code the engine
  uses for live mgmt validation — so the result tracks the deployed
  behaviour, not a parallel reimplementation.

## Build

```bash
cargo build --release -p audit-strict-mgmt-validation
```

Not shipped in the `flake.nix` packages — it has no user-facing role.
Run it directly from `cargo` against a live forwarder when the audit
witness needs it.

## Run

```bash
audit-strict-mgmt-validation \
  --socket /run/ndn-fwd/mgmt.sock \
  --pib-dir /var/lib/ndn-fwd/pib
```

Used by the audit witness script at
`testbed/tests/audit/n12_strict_mgmt_validation.sh`.

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.
