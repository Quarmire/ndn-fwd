# ndn-tools

Operator CLIs for working with an NDN forwarder. One crate, eight
binaries: `ndn-peek`, `ndn-put`, `ndn-ping`, `ndn-sec`, `ndn-ctl`,
`ndn-traffic`, `ndn-iperf`, `ndn-psync-consumer`.

## Get started

```bash
cargo build --release -p ndn-tools
./target/release/ndn-ctl status
./target/release/ndn-peek /ndn/example/data
```

Each binary takes `--help` for its full option set.

## Configure

Every tool talks to the forwarder over its management socket. The
default is `/run/ndn-fwd/mgmt.sock` (override with
`--socket <path>`). `$NDN_SOCKET` sets the default for the current
shell.

`RUST_LOG=info` for status; `RUST_LOG=debug` for protocol-level
detail.

## Build

### Cargo

```bash
cargo build --release -p ndn-tools
# Produces: ndn-peek, ndn-put, ndn-ping, ndn-sec, ndn-ctl, ndn-traffic, ndn-iperf, ndn-psync-consumer
```

### Nix

```bash
nix profile install github:Quarmire/ndn-rs#ndn-tools    # installs all seven
nix run github:Quarmire/ndn-rs#ndn-ctl -- status        # one-shot
```

## Run

### `ndn-ctl` — management

Wraps the NFD-compatible management surface
(`/localhost/nfd/<module>/<verb>`).

```bash
ndn-ctl status                                  # router status snapshot
ndn-ctl rib register /ndn/example --face 1 --cost 10
ndn-ctl faces list
ndn-ctl cs info
ndn-ctl security identity-status
ndn-ctl strategy-choice set /ndn/example /localhost/nfd/strategy/best-route
```

`ndn-ctl --help` lists every verb. The wire shape matches NFD so any
NFD-compatible tooling (e.g. `nfdc`) talks to the same socket.

### `ndn-peek` — fetch one Data

```bash
ndn-peek /ndn/example/data
ndn-peek /ndn/example/file --timeout-ms 4000
ndn-peek /ndn/example/data --hex                # raw wire output
```

### `ndn-put` — publish from stdin

```bash
ndn-put /ndn/example/file --chunk-size 8192 < data.bin
```

Segments the input, signs each chunk with the local KeyChain, and
serves them under the given prefix until interrupted.

### `ndn-ping` — reachability + latency

```bash
ndn-ping /ndn/example --count 10 --interval-ms 100
```

Sends probe Interests every `--interval-ms` and reports per-Interest
round-trip time plus loss rate.

### `ndn-sec` — identity / key / cert management

```bash
ndn-sec keygen /ndn/mysite/router1               # mint Ed25519 identity
ndn-sec certdump /ndn/mysite/router1             # cert in PEM/wire form
ndn-sec --pib-dir /var/lib/ndn-fwd/pib list
ndn-sec anchor add /path/to/anchor.cert
```

The PIB directory defaults to `$NDN_PIB` or the platform default;
override with `--pib-dir <path>`.

### `ndn-traffic` — synthetic load

Embeds a forwarder engine with producer/consumer face pairs and
drives Interest/Data through the full pipeline.

```bash
ndn-traffic --mode echo  --count 10000 --concurrency 4
ndn-traffic --mode sink  --count 1000
ndn-traffic --mode echo  --count 5000 --rate 1000 --size 2048
```

| Flag | Default | Description |
|---|---|---|
| `--mode` | `echo` | `echo` (producer replies) or `sink` (all Nack) |
| `--count` | `10000` | Total Interests to send |
| `--rate` | `0` | Target packets/s (0 = unlimited) |
| `--size` | `1024` | Data payload size in bytes |
| `--prefix` | `/traffic` | Name prefix |
| `--concurrency` | `1` | Parallel consumer flows |

Output: throughput (pps + Mbps), latency percentiles
(min/avg/p50/p95/p99/max), loss rate.

### `ndn-iperf` — sustained throughput

Sliding-window flow control between an in-process producer/consumer
pair.

```bash
ndn-iperf                                       # 10s, 8KB, window 64
ndn-iperf --duration 5 --size 1024 --window 128
```

| Flag | Default | Description |
|---|---|---|
| `--duration` | `10` | Test duration in seconds |
| `--size` | `8192` | Data payload size in bytes |
| `--window` | `64` | Max outstanding Interests |
| `--prefix` | `/iperf` | Name prefix |

Output: total bytes, Mbps, packet counts, RTT statistics.

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.

## Acknowledgements

Verb shape follows the NFD management protocol. `ndn-peek` /
`ndn-put` / `ndn-ping` mirror the corresponding ndn-cxx tools.
