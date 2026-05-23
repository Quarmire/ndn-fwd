# Multi-stage Docker image for the did-ndn-driver DID method server.
#
# Uses cargo-chef for dependency layer caching.  See binaries/ndn-fwd/Dockerfile
# for a full explanation of the planner → cacher → builder pattern.
#
# Build (from repo root):
#   docker build -f binaries/tooling/did-ndn-driver/Dockerfile -t did-ndn-driver .

# ── Stage 1: chef base ────────────────────────────────────────────────────────
FROM rust:slim AS chef

RUN cargo install cargo-chef --locked

WORKDIR /build

# ── Stage 2: planner ──────────────────────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: cacher ───────────────────────────────────────────────────────────
FROM chef AS cacher
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --bin did-ndn-driver --recipe-path recipe.json

# ── Stage 4: builder ──────────────────────────────────────────────────────────
FROM chef AS builder
COPY . .
COPY --from=cacher /build/target target
RUN cargo build --release --bin did-ndn-driver

# ── Stage 5: runtime image ────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/did-ndn-driver /usr/local/bin/did-ndn-driver

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["did-ndn-driver"]
