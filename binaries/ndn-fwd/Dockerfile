# Multi-stage Docker image for the ndn-fwd NDN forwarder.
#
# ndn-fwd depends on ndn-rs + ndn-ext via `../` path deps, so the build needs all
# three repos laid out as siblings. The publish workflow checks them out next to
# each other and builds with that parent directory as the context; this Dockerfile
# reproduces the dev-workspace layout under /workspace so the path deps resolve.
#
# Build (from a directory containing ndn-fwd/, ndn-rs/, ndn-ext/ as siblings):
#   docker build -f ndn-fwd/binaries/ndn-fwd/Dockerfile -t ndn-fwd .
#
# Run with default config:
#   docker run --rm -p 6363:6363/udp -p 6363:6363/tcp ndn-fwd
#
# Run with a custom config file:
#   docker run --rm -p 6363:6363/udp -p 6363:6363/tcp \
#     -v /path/to/ndn-fwd.toml:/etc/ndn-fwd/config.toml:ro \
#     ndn-fwd
#
# Exposes:
#   6363/udp  — NDN UDP face
#   6363/tcp  — NDN TCP face
#   9696/tcp  — WebSocket face (wss:// when websocket-tls feature is enabled)
#
# NOTE: this builds all dependencies from scratch each time. A cargo-chef caching
# layer was removed because it does not compose cleanly with the cross-repo `../`
# path deps; re-introduce it once the sibling layout is confirmed if build time
# becomes a concern.

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM rust:slim AS builder

ARG BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${BUILD_JOBS}

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

# Reproduce the dev-workspace sibling layout: ndn-fwd's Cargo.toml path deps point
# at ../ndn-rs and ../ndn-ext, so all three must sit next to each other.
WORKDIR /workspace
COPY ndn-rs  ndn-rs
COPY ndn-ext ndn-ext
COPY ndn-fwd ndn-fwd

WORKDIR /workspace/ndn-fwd
RUN cargo build --release --bin ndn-fwd -j "${CARGO_BUILD_JOBS}"

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM debian:trixie-slim

# `libdbus-1-3` is required at runtime because workspace feature unification
# (resolver 2 with `--bin ndn-fwd`) can still propagate `ndn-face-native/bluetooth`
# into the build graph via other workspace members, pulling `bluer` and
# `libdbus-sys`.  Symptom without it: ndn-fwd exits at startup with
# `error while loading shared libraries: libdbus-1.so.3`.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    netcat-openbsd \
    libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/ndn-fwd/target/release/ndn-fwd /usr/local/bin/ndn-fwd
COPY ndn-fwd/binaries/ndn-fwd/ndn-fwd.default.toml /etc/ndn-fwd/config.toml

RUN mkdir -p /etc/ndn-fwd/certs /run/ndn-fwd

EXPOSE 6363/udp 6363/tcp 9696/tcp

ENTRYPOINT ["ndn-fwd", "--config", "/etc/ndn-fwd/config.toml"]
