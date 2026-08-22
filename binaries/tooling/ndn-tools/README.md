# ndn-tools

Operator CLIs for working with an NDN forwarder. One crate, twelve
binaries:

| Binary | Purpose |
|---|---|
| `ndn-ctl` | NFD-compatible management commands over the forwarder socket |
| `ndn-peek` | Fetch one Data packet |
| `ndn-put` | Segment, sign, and publish stdin under a prefix |
| `ndn-ping` | Reachability + latency probes |
| `ndn-traceroute` | Forwarder-hop distance via HopLimit ramping |
| `ndn-sec` | Identity / key / cert management (incl. SafeBag export/import) |
| `ndn-traffic` | Synthetic load through an embedded engine |
| `ndn-iperf` | Sustained-throughput benchmark |
| `ndn-psync-consumer` | Observe PSync FullProducer updates through a forwarder |
| `ndn-mgmt-response-verify` | Check a mgmt control response is signed by a trust anchor |
| `ndn-mgmt-notification-fetch` | Fetch one NFD-style mgmt notification Data |
| `ndn-safebag-witness` | Testbed-only SafeBag interop witness vs `ndnsec` |

## Get started

```bash
cargo build --release -p ndn-tools
./target/release/ndn-ctl status
./target/release/ndn-peek /ndn/example/data
```

Each binary takes `--help` for its full option set.

## Configure

Every tool talks to the forwarder over its management socket. The
built-in default is `/run/nfd/nfd.sock` on Unix (override with
`--socket <path>`). `$NDN_SOCK` sets the default for the current
shell; the Docker image's config uses `/run/ndn-fwd/ndn-fwd.sock`.

`RUST_LOG=info` for status; `RUST_LOG=debug` for protocol-level
detail.

## Build

### Cargo

```bash
cargo build --release -p ndn-tools
# Produces all twelve binaries from the table above.
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

### `ndn-traceroute` — hop distance

```bash
ndn-traceroute /ndn/example
```

Ramps the Interest `HopLimit` toward a ping-style responder and
reports the forwarder-hop distance.

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

### Sync + testbed witnesses

The remaining binaries back the `testbed/` harness; each takes
`--help` for its full option set:

- `ndn-psync-consumer` — subscribe to a PSync FullProducer through a
  running forwarder and print observed update prefixes.
- `ndn-mgmt-response-verify` — send one management command and verify
  the control response is key-signed by a configured trust anchor.
- `ndn-mgmt-notification-fetch` — fetch one NFD-style management
  notification Data packet.
- `ndn-safebag-witness` — testbed-only SafeBag interop witness against
  ndn-cxx `ndnsec export`/`import`.

## License

Licensed under either MIT or Apache-2.0 at your option
(`license = "MIT OR Apache-2.0"` in the workspace manifest).

## Acknowledgements

Verb shape follows the NFD management protocol. `ndn-peek` /
`ndn-put` / `ndn-ping` mirror the corresponding ndn-cxx tools.
