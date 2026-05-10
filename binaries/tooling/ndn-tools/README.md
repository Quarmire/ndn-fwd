# ndn-tools

NDN command-line tools for testing, debugging, and performance measurement.

## Tools

### ndn-peek

Fetch a single Data packet by name.

```bash
ndn-peek /ndn/example/data --timeout-ms 4000
```

### ndn-put

Publish Data segments from a file.

```bash
ndn-put /ndn/example/file --chunk-size 8192 < data.bin
```

### ndn-ping

Send probe Interests and measure round-trip time.

```bash
ndn-ping /ndn/example --count 10 --interval-ms 100
```

### ndn-traffic

Configurable NDN traffic generator. Embeds a forwarding engine with
producer/consumer AppFace pairs and drives Interest/Data traffic through
the full pipeline.

```bash
# Echo mode (producer responds with Data):
ndn-traffic --mode echo --count 10000 --concurrency 4

# Sink mode (no producer — all Interests Nack):
ndn-traffic --mode sink --count 1000

# Rate-limited:
ndn-traffic --mode echo --count 5000 --rate 1000 --size 2048
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `echo` | `echo` (producer replies) or `sink` (all Nack) |
| `--count` | `10000` | Total Interests to send |
| `--rate` | `0` | Target pps (0 = unlimited) |
| `--size` | `1024` | Data payload size in bytes |
| `--prefix` | `/traffic` | Name prefix |
| `--concurrency` | `1` | Parallel consumer flows |

Output includes throughput (pps, Mbps), latency percentiles
(min/avg/p50/p95/p99/max), and loss rate.

### ndn-iperf

NDN bandwidth measurement tool. Measures sustained throughput between a
producer and consumer through the embedded forwarding engine using
sliding-window flow control.

```bash
# Default: 10s test, 8KB payload, window of 64:
ndn-iperf

# Custom parameters:
ndn-iperf --duration 5 --size 1024 --window 128
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--duration` | `10` | Test duration in seconds |
| `--size` | `8192` | Data payload size in bytes |
| `--window` | `64` | Max outstanding Interests |
| `--prefix` | `/iperf` | Name prefix |

Output includes total bytes transferred, throughput in Mbps, packet
counts, and RTT statistics.

### ndn-sec

Security key and certificate management.

```bash
ndn-sec generate --name /ndn/example/KEY
ndn-sec show --pib-dir ./keys
```

### ndn-ctl

Send management commands to a running forwarder.

```bash
ndn-ctl add-route /ndn/prefix 0 10
ndn-ctl list-faces
ndn-ctl get-stats
```

## Building

```bash
cargo build -p ndn-tools

# Release build for benchmarking:
cargo build -p ndn-tools --release
```
