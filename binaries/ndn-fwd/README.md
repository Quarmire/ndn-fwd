# ndn-fwd

The NDN forwarder daemon. Reads a TOML config, brings up faces,
loads identities, mounts the NFD-compatible management surface, and
runs the engine pipeline.

## Get started

```bash
cargo run --release -p ndn-fwd                          # built-in defaults
cargo run --release -p ndn-fwd -- -c examples/ndn-fwd.example.toml
```

`RUST_LOG=info` for status output; `RUST_LOG=ndn_engine=trace` to
follow the pipeline stage-by-stage.

## Configure

A TOML file. The shipped reference is [`examples/ndn-fwd.example.toml`](../../../examples/ndn-fwd.example.toml)
— every option with its default in a comment.

| Section | Purpose |
|---|---|
| `[engine]` | PIT capacity, content-store size, pipeline threads, replay guard. |
| `[[face]]` | One entry per face: UDP, TCP, Unix, WebSocket, multicast, serial, Ethernet. |
| `[management]` | Unix-socket path, NFD-compat verbs, signed-command policy. |
| `[security]` | Trust anchors, validator policy, PIB directory. |
| `[routing.*]` | Static routes, NLSR, DV. |
| `[discovery.*]` | Neighbour discovery + service discovery. |
| `[observability]` | Tracing target filter, log format, OpenTelemetry export. |

The wiki's [Config reference](../../../docs/wiki/src/operations/config-reference.md)
walks the option groups.

## Build

### Cargo

```bash
cargo build --release -p ndn-fwd
./target/release/ndn-fwd --help
```

### Nix

```bash
nix build .#ndn-fwd                                     # local checkout
nix run github:Quarmire/ndn-rs                          # remote
nix profile install github:Quarmire/ndn-rs#ndn-fwd      # system install
```

### Docker

```bash
docker build -f binaries/ndn-fwd/Dockerfile -t ndn-fwd .
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

ndn-ctl --socket /run/ndn-fwd/mgmt.sock status
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

### NixOS system service

The workspace [`flake.nix`](../../../flake.nix) exports a
`nixosModules.default` that runs `ndn-fwd` under systemd with a
hardened profile, auto-generated identity, and an optional firewall
rule.

```nix
{
  imports = [ inputs.ndn-rs.nixosModules.default ];
  services.ndn-fwd = {
    enable = true;
    openFirewall = true;
    identity = "/ndn/mysite/router1";
    configFile = ./ndn-fwd.toml;
  };
}
```

See the main [README](../../../README.md#self-host) for the full
flake snippet and module options.

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

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.

## Acknowledgements

`ndn-fwd` builds on the NDN architecture developed by the NDN
research team led by Lixia Zhang at UCLA. The management surface
follows the NFD specification.
