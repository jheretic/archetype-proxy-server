# Build context MUST be the archetype-proxy-server repo root:
#   docker build -f deploy/Dockerfile -t archetype-proxy-server .
#
# Two-stage: compile a release binary, then ship it on a slim runtime. The
# build fetches the pinned OpenHTTPA git dep, so the builder needs network.
#
# NOTE: the default build is MOCK-only (no TEE feature flags). The image is for
# SMOKE TESTING multi-replica stickiness; ARCHETYPE_PROXY_INSECURE_DEV=1 is set
# in docker-compose so the (release) no-mock guard does not refuse to start.
# Do NOT ship this image to production as-is.

FROM rust:1.95-bookworm AS builder
WORKDIR /src
# Cache deps: copy manifests first. (Cargo.lock pins the full graph.)
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tests ./tests
# Build the release binary.
RUN cargo build --release --bin archetype-proxy-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/archetype-proxy-server /usr/local/bin/archetype-proxy-server
# Default listen is 127.0.0.1:8443 (loopback). In a container we must bind all
# interfaces so the LB can reach it; docker-compose overrides ARCHETYPE_PROXY_LISTEN.
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/archetype-proxy-server"]
