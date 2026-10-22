set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# kotton-relay infrastructure (address exchange + blind circuits; it keeps nothing).
# Standalone — not part of the workspace (lives in infra/relay/).
# Invoked as `just relay::build`, `just relay::deploy`, `just relay::logs`.

# Build the kotton-relay binary, into `out/relay` (or `CARGO_TARGET_DIR`); prints its path.
build:
    cargo xtask build-relay

# Release build of the kotton-relay binary, for a local run; prints its path. Not what a release
# packs: `cargo xtask release-server relay` builds that in a target of its own.
build-release:
    cargo xtask build-relay --release

# Build and start the relay via docker compose (detached).
deploy:
    docker compose -f infra/relay/docker-compose.yml up -d --build

# Stop and remove the relay containers.
down:
    docker compose -f infra/relay/docker-compose.yml down

# Tail relay logs.
logs:
    docker compose -f infra/relay/docker-compose.yml logs -f relay
