# ndn-bench

AppFace channel throughput + latency benchmark. Embeds an engine
with `InProcFace` consumer/producer channels and drives a controlled
Interest/Data exchange loop.

**Scope:** measures the channel overhead between the application and
the engine — not the full pipeline. For end-to-end pipeline
throughput, use [`ndn-traffic`](../ndn-tools/README.md#ndn-traffic--synthetic-load)
or [`ndn-iperf`](../ndn-tools/README.md#ndn-iperf--sustained-throughput).

## Get started

```bash
cargo run --release -p ndn-bench
cargo run --release -p ndn-bench -- --interests 50000 --concurrency 16
```

## Configure

| Flag | Default | Purpose |
|---|---|---|
| `--interests` | `1000` | Total Interests to send. |
| `--concurrency` | `10` | Parallel worker tasks. |
| `--name` | `/bench` | Name prefix. |

## Build

### Cargo

```bash
cargo build --release -p ndn-bench
./target/release/ndn-bench --help
```

### Nix

```bash
nix run github:Quarmire/ndn-rs#ndn-bench -- --interests 10000
```

## Run

Output reports Interests/sec throughput and RTT percentiles (avg,
p50, p95, p99). Sample run:

```text
$ ndn-bench --interests 100000 --concurrency 32
sent=100000  duration=1.78s  rate=56180 interests/s
rtt:  avg=560us  p50=510us  p95=910us  p99=1.6ms
```

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.
