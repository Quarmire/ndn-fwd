# ndn-bench

Throughput and latency benchmarking for the NDN forwarder.

Embeds an engine with `AppFace` channels and drives a controlled
Interest/Data exchange loop, reporting per-packet latency percentiles
and aggregate throughput.

## Usage

```bash
ndn-bench [--interests N] [--concurrency C] [--name PREFIX]
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--interests` | `1000` | Total Interests to send |
| `--concurrency` | `10` | Parallel worker tasks |
| `--name` | `/bench` | Name prefix |

## Output

Reports interests/sec throughput and RTT percentiles (avg, p50, p95, p99).

## Note

This tool currently measures AppFace channel overhead only (the pipeline
is not fully wired). For end-to-end pipeline throughput measurement, use
[`ndn-traffic`](../ndn-tools/README.md#ndn-traffic) or
[`ndn-iperf`](../ndn-tools/README.md#ndn-iperf) instead.
