# Multi-stage Docker image for the ndn-fwd NDN forwarder.
#
# Uses cargo-chef for dependency layer caching.  The cacher stage compiles
# all external crates once per Cargo.toml/Cargo.lock change.  A source-only
# change skips dependency recompilation and only rebuilds workspace crates,
# reducing incremental build time from ~10 min to ~2–3 min.
#
# Build (from repo root):
#   docker build -f binaries/ndn-fwd/Dockerfile -t ndn-fwd .
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

# ── Stage 1: chef base ────────────────────────────────────────────────────────
FROM rust:slim AS chef

RUN cargo install cargo-chef --locked

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Stage 2: planner ──────────────────────────────────────────────────────────
# Scans workspace Cargo.toml files and produces recipe.json.  No compilation.
# Runs on every source change but the output only changes when
# Cargo.toml / Cargo.lock changes, so the cacher stage stays cached.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: cacher ───────────────────────────────────────────────────────────
# Compiles external dependencies only.  Cached as long as recipe.json is
# unchanged (i.e. Cargo.toml / Cargo.lock are unchanged).
FROM chef AS cacher
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --bin ndn-fwd --recipe-path recipe.json

# ── Stage 4: builder ──────────────────────────────────────────────────────────
# Compiles workspace crates.  External deps are already compiled in /build/target
# from the cacher stage, so only ndn-rs crates are recompiled here.
FROM chef AS builder
COPY . .
COPY --from=cacher /build/target target
RUN cargo build --release --bin ndn-fwd

# ── Stage 5: runtime image ────────────────────────────────────────────────────
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

COPY --from=builder /build/target/release/ndn-fwd /usr/local/bin/ndn-fwd
COPY binaries/ndn-fwd/ndn-fwd.default.toml /etc/ndn-fwd/config.toml

RUN mkdir -p /etc/ndn-fwd/certs /run/ndn-fwd

EXPOSE 6363/udp 6363/tcp 9696/tcp

ENTRYPOINT ["ndn-fwd", "--config", "/etc/ndn-fwd/config.toml"]
