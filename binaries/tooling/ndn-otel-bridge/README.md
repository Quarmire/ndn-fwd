# ndn-otel-bridge

Sidecar that consumes NDN-native spans from an `ndn-fwd`
observability prefix and forwards them via OTLP/HTTP-protobuf to a
standard OpenTelemetry backend (Jaeger, Tempo, Honeycomb, Datadog,
etc.).

## What it does

```text
ndn-fwd  (observability publisher)
   │
   ▼  Interest <prefix>/recent
bridge.poll() ─── list of (trace_id, span_id)
   │
   ▼  Interest <prefix>/traces/<trace>/spans/<span>
bridge.fetch_span() ─── OTLP Span protobuf bytes
   │
   ▼  batch + POST /v1/traces (OTLP/HTTP-protobuf)
OpenTelemetry collector
```

The wire-level NDN side is the [TraceContext LP TLV](../../../docs/specs/trace-context-lp-tlv.md);
the bridge translates from there into standard OTLP.

## Get started

```bash
cargo run --release -p ndn-otel-bridge -- \
  --socket /run/ndn-fwd/mgmt.sock \
  --otlp-endpoint http://localhost:4318/v1/traces
```

The bridge runs until interrupted.

## Configure

| Flag | Default | Purpose |
|---|---|---|
| `--socket` | `/run/nfd/nfd.sock` | Forwarder management socket. |
| `--ndn-prefix` | `/localhost/nfd/observability` | NDN prefix to poll for span manifests. |
| `--otlp-endpoint` | `http://localhost:4318/v1/traces` | OTLP collector endpoint. |
| `--service-name` | `ndn-rs` | Service name on the exported spans. |
| `--batch-size` | `100` | Max spans per OTLP POST. |
| `--batch-timeout` | `5s` | Max wait before flushing a partial batch. |
| `--poll-interval` | `1s` | How often to poll `<prefix>/recent`. |

Forwarder side: enable `[observability] publish_to_ndn = true` in
`ndn-fwd.toml`.

## Build

### Cargo

```bash
cargo build --release -p ndn-otel-bridge
./target/release/ndn-otel-bridge --help
```

### Nix

```bash
nix run github:Quarmire/ndn-rs#ndn-otel-bridge -- --help
nix profile install github:Quarmire/ndn-rs#ndn-otel-bridge
```

## Run

### Local Jaeger

```bash
docker run -d --name jaeger \
  -p 4318:4318 -p 16686:16686 \
  jaegertracing/all-in-one:latest

ndn-otel-bridge --otlp-endpoint http://localhost:4318/v1/traces
```

Then browse to `http://localhost:16686` for the Jaeger UI.

### Honeycomb / Datadog

```bash
# Honeycomb
ndn-otel-bridge \
  --otlp-endpoint https://api.honeycomb.io/v1/traces \
  --service-name production-router
# Datadog Agent OTLP receiver
ndn-otel-bridge --otlp-endpoint http://localhost:4318/v1/traces
```

(Backend-specific auth headers — `x-honeycomb-team`, `dd-api-key` —
are sent through the OTLP HTTP client's default header configuration;
set them via env vars per your backend's docs.)

## License

Licensed under either [MIT](../../../LICENSE-MIT) or
[Apache-2.0](../../../LICENSE-APACHE) at your option.

## Acknowledgements

Exports OTLP/HTTP per the
[OpenTelemetry Protocol specification](https://opentelemetry.io/docs/specs/otlp/).
The NDN-side trace format is documented at
[`docs/specs/trace-context-lp-tlv.md`](../../../docs/specs/trace-context-lp-tlv.md).
