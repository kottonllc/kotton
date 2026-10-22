# Two-stage build: compile in the official Rust image, run in a minimal
# Debian slim image (~20 MB vs ~1.5 GB).
#
# Build context: workspace root  (required — relay has path deps into core/).
# Build command:
#   docker build -f infra/relay/Dockerfile -t kotton-relay .

# ── Stage 1: build ────────────────────────────────────────────────────────────
# Pin the builder to bookworm so the binary's glibc requirement matches the
# bookworm-slim runtime below. (The floating `rust:1-slim` tag has moved to a
# newer Debian whose glibc 2.38 is absent from bookworm, breaking the runtime.)
ARG BUILDER_BASE=rust:1-slim-bookworm
ARG RUNTIME_BASE=debian:bookworm-slim
ARG ARTIFACTS=builder

FROM ${BUILDER_BASE} AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the full workspace so path deps (kotton-protocol) can be resolved.
COPY . .

# The relay is extracted from the workspace; target it by manifest path.
# --target-dir keeps the binary at /build/target/release/kotton-relay.
# Cache mounts for the same reason as infra/Dockerfile: `COPY . .` above invalidates on
# any change, and without these every build recompiles from cold. The `cp` stays inside
# this RUN because a cache mount is not part of the layer it is mounted into.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release \
    --manifest-path infra/relay/Cargo.toml \
    --target-dir /build/target \
  && mkdir -p /out && cp /build/target/release/kotton-relay /out/

# A relay binary handed in (`just stack::prebuilt`, ARTIFACTS=prebuilt).
FROM ${RUNTIME_BASE} AS prebuilt
COPY infra/prebuilt/ /out/

FROM ${ARTIFACTS} AS artifacts

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM ${RUNTIME_BASE} AS runtime
ARG APT=1
RUN if [ "$APT" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libsqlite3-0 wget \
      && rm -rf /var/lib/apt/lists/*; \
    fi

COPY --from=artifacts /out/kotton-relay /usr/local/bin/kotton-relay

EXPOSE 7700

ENTRYPOINT ["kotton-relay"]
CMD ["--bind", "0.0.0.0:7700"]
