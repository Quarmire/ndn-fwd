# enroll-ndncert

NDNCERT 0.3 enrollment client. Drives a full
`NEW → CHALLENGE → cert-fetch` flow against a running CA, prints
the issued certificate, and persists the new key into the PIB.

Used in operator workflows (request a cert) and in CI as the live
interop witness for the NDNCERT issuance path against an
ndn-cxx-based CA.

## Get started

```bash
cargo run --release -p enroll-ndncert -- \
  --face-socket /run/ndn-fwd/mgmt.sock \
  --ca-prefix /test/ndncert/CA \
  --name /test/requester
```

When run without `--pin`, the binary completes the `NEW` step plus
the first CHALLENGE round, prints `WAITING_FOR_PIN` and the request
ID to stderr, then reads one line of stdin as the PIN. This is the
shape the audit witnesses use (the harness reads the CA container
logs for the PIN and pipes it back in).

## Configure

| Flag | Required | Purpose |
|---|---|---|
| `--face-socket` | yes | Forwarder Unix socket to reach the CA over NDN. |
| `--ca-prefix` | yes | The CA's NDN prefix (e.g. `/test/ndncert/CA`). |
| `--name` | yes | The identity name the requester wants a cert for. |
| `--pin` | no | Pre-shared PIN. Omit for interactive PIN entry on stdin. |
| `--pib-dir` | no | Where to persist the new key. Defaults to `$NDN_PIB` or the platform default. |
| `--timeout-ms` | no | Per-Interest timeout. Default `4000`. |

## Build

### Cargo

```bash
cargo build --release -p enroll-ndncert
./target/release/enroll-ndncert --help
```

### Nix

```bash
nix run github:Quarmire/ndn-rs#enroll-ndncert -- --help
nix profile install github:Quarmire/ndn-rs#enroll-ndncert
```

## Run

### Interactive (PIN on stdin)

```bash
enroll-ndncert \
  --face-socket /run/ndn-fwd/mgmt.sock \
  --ca-prefix /test/ndncert/CA \
  --name /test/alice
# stderr → WAITING_FOR_PIN request_id=ABC123
# (operator obtains PIN from the CA out-of-band)
echo "123456" | enroll-ndncert ...
```

### Non-interactive (PIN known up front)

```bash
enroll-ndncert \
  --face-socket /run/ndn-fwd/mgmt.sock \
  --ca-prefix /test/ndncert/CA \
  --name /test/alice \
  --pin 123456
```

### As part of a test harness

The C.13 audit witness runs this binary in two stages: trigger
(no PIN), then read the PIN from the CA container's logs, then
re-invoke with `--pin`. The witness script lives at
`testbed/tests/audit/c13_live_interop.sh`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Cert issued, persisted to the PIB, name printed on stdout. |
| `2` | NEW step failed (CA unreachable or rejected). |
| `3` | CHALLENGE step failed (bad PIN or schema violation). |
| `4` | Cert fetch failed after issuance. |

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.

## Acknowledgements

Implements the NDNCERT 0.3 protocol. The reference CA implementation
is [ndncert-ca-server](https://github.com/named-data/ndncert).
