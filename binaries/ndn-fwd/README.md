# ndn-fwd

The NDN forwarder daemon. Reads a TOML config, brings up faces,
loads identities, mounts the NFD-compatible management surface, and
runs the engine pipeline.

## Get started

```bash
cargo run --release -p ndn-fwd                          # built-in defaults
cargo run --release -p ndn-fwd -- -c binaries/ndn-fwd/ndn-fwd.default.toml
```

`RUST_LOG=info` for status output; `RUST_LOG=ndn_engine=trace` to
follow the pipeline stage-by-stage.

## Configure

A TOML file. The shipped reference is [`ndn-fwd.default.toml`](./ndn-fwd.default.toml)
(also baked into the Docker image as `/etc/ndn-fwd/config.toml`).

| Section | Purpose |
|---|---|
| `[engine]` | PIT capacity, content-store size, pipeline threads, replay guard. |
| `[[face]]` | One entry per face: UDP, TCP, Unix, WebSocket, multicast, serial, Ethernet. |
| `[management]` | Unix-socket path, NFD-compat verbs, signed-command policy. |
| `[security]` | Trust anchors, validator policy, PIB directory. |
| `[routing.*]` | Static routes, NLSR, DV. |
| `[discovery.*]` | Neighbour discovery + service discovery. |
| `[observability]` | Tracing target filter, log format, OpenTelemetry export. |

The [config reference](https://github.com/Quarmire/ndn-rs/blob/main/docs/wiki/src/operations/config-reference.md)
in the sibling **ndn-rs** repo's wiki walks the option groups.

## Build

### Cargo

```bash
cargo build --release -p ndn-fwd
./target/release/ndn-fwd --help
```

#### Features

The default build ships `spsc-shm`, `websocket`, `serial`, `l2`,
`fec`, and `rate-limit`. Everything else is opt-in at compile time
— since P1 that includes `webtransport` and `quic` (they drag
ACME/rustls and quinn into every build otherwise), alongside
`bluetooth`, `webrtc`, `radio`, `af-xdp`, `cclf`, `smtp`, `console`,
`yubikey-piv`, and `partitioned-fwd`:

```bash
cargo build --release -p ndn-fwd --features webtransport,quic
```

See `[features]` in [`Cargo.toml`](./Cargo.toml) for what each flag
pulls in.

### Docker

`ndn-fwd` depends on ndn-rs, ndn-ext, and ndn-radio-drivers via `../`
path deps, so the build context is the **parent** directory with those
repos checked out as siblings of `ndn-fwd/` (the layout the publish
workflow reproduces — see the [`Dockerfile`](./Dockerfile) header):

```bash
# From the directory containing ndn-fwd/, ndn-rs/, ndn-ext/, ndn-radio-drivers/:
docker build -f ndn-fwd/binaries/ndn-fwd/Dockerfile -t ndn-fwd .

docker pull ghcr.io/quarmire/ndn-fwd:latest             # prebuilt
```

## Run

### Default

```bash
ndn-fwd
```

Listens on UDP and TCP 6363 with stub identity and no persistent
storage.

### Production

```bash
ndn-fwd -c /etc/ndn-fwd/config.toml
```

### Docker — config + mgmt socket exposed

```bash
docker run --rm \
  -p 6363:6363/udp -p 6363:6363/tcp \
  -v /etc/ndn-fwd:/etc/ndn-fwd:ro \
  -v /run/ndn-fwd:/run/ndn-fwd \
  ghcr.io/quarmire/ndn-fwd:latest

ndn-ctl --socket /run/ndn-fwd/ndn-fwd.sock status
```

### Docker — WebSocket-over-TLS

```bash
docker run --rm \
  -p 6363:6363/udp -p 9696:9696/tcp \
  -v /etc/ndn-fwd:/etc/ndn-fwd:ro \
  -v /etc/letsencrypt/live/router.example.org:/etc/ndn-fwd/certs:ro \
  ghcr.io/quarmire/ndn-fwd:latest
```

In the config:

```toml
[[face]]
kind = "web-socket"
bind = "0.0.0.0:9696"
tls_cert = "/etc/ndn-fwd/certs/fullchain.pem"
tls_key  = "/etc/ndn-fwd/certs/privkey.pem"
```

## tokio-console build profile

`binaries/ndn-fwd/.cargo/config.toml` defines a `console` cargo
profile that builds `ndn-fwd` with [tokio-console](https://github.com/tokio-rs/console)
support. To use it:

```bash
cd binaries/ndn-fwd
RUSTFLAGS="--cfg tokio_unstable" \
  cargo build --features console --profile console
RUSTFLAGS="--cfg tokio_unstable" \
  cargo run --features console --profile console

# In another shell (one-time install: `cargo install tokio-console`):
tokio-console                              # default 127.0.0.1:6669
TOKIO_CONSOLE_BIND=0.0.0.0:9999 ...        # override
```

The profile is local to this crate so the rest of the workspace
builds unencumbered.

## License

Licensed under either MIT or Apache-2.0 at your option
(`license = "MIT OR Apache-2.0"` in the workspace manifest).

## Acknowledgements

`ndn-fwd` builds on the NDN architecture developed by the NDN
research team led by Lixia Zhang at UCLA. The management surface
follows the NFD specification.
