# did-ndn-driver

[DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver)
driver for the `did:ndn` DID method. Runs as an HTTP server,
resolves `did:ndn:…` identifiers by fetching the corresponding DID
Document over NDN, and returns a W3C-format DID Resolution Result.

The `did:ndn` method itself is specified at
[`docs/specs/did-ndn-spec.md`](../../../docs/specs/did-ndn-spec.md).

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/1.0/identifiers/{did}` | `GET` | Resolve a `did:ndn:…` identifier. Returns a DIF `DidResolutionResult`. |
| `/health` | `GET` | Liveness probe. Returns `"ok"`. |

## Get started

```bash
cargo run --release -p did-ndn-driver
# Listens on 0.0.0.0:8080 by default.

curl http://localhost:8080/1.0/identifiers/did:ndn:v1:%2Fndn%2Falice
```

## Configure

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | TCP port to bind. |
| `BIND` | `0.0.0.0` | Bind address. |
| `RUST_LOG` | (unset) | Tracing filter. `did_ndn_driver=debug` for request-level detail. |

DID resolution uses the local NDN substrate; the driver expects an
`ndn-fwd` reachable via the platform default management socket (or
the path in `$NDN_SOCKET`).

## Build

### Cargo

```bash
cargo build --release -p did-ndn-driver
./target/release/did-ndn-driver
```

### Nix

```bash
nix run github:Quarmire/ndn-rs#did-ndn-driver
nix profile install github:Quarmire/ndn-rs#did-ndn-driver
```

## Run

### Standalone

```bash
PORT=9090 did-ndn-driver
RUST_LOG=did_ndn_driver=debug did-ndn-driver
```

### As a DIF Universal Resolver driver

Add to `uni-resolver-web/src/main/resources/application.yml`:

```yaml
- pattern: "^did:ndn:.+"
  url: "http://did-ndn-driver:8080/1.0/identifiers/"
```

Then submit the entry upstream to the
[DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver).

### Docker / Kubernetes

A small container image is straightforward:

```dockerfile
FROM debian:stable-slim
COPY did-ndn-driver /usr/local/bin/
EXPOSE 8080
CMD ["did-ndn-driver"]
```

Mount the management socket from a sidecar `ndn-fwd` (or run both in
the same container) so the driver can reach the NDN substrate.

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.

## Acknowledgements

Conforms to the W3C
[DID Core 1.0](https://www.w3.org/TR/did-core/) spec and the DIF
Universal Resolver driver HTTP binding.
