set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# Headless profile — core daemons + CLI + the WASM sandbox runner (compute).
# No GPU, no display server, no Python. Use this on CI, VPS, or server/compute nodes.
# Invoked as `just headless::build`, `just headless::run <user>`.

# Build the headless binaries (kotton + kdeviced + kuserd + runner + kinferd).
#
# `kinferd`, `ksyncd` and `kquicd` because the daemon spawns each by name from
# beside its own executable: a sidecar that was never built
# is a supervisor that retries three times, gives up, and logs `No such file or
# directory` — which is what the owner's first desktop run printed on 2026-09-17,
# for `ksyncd`, because this line did not build it.
build:
    cargo build --bin kotton --bin kdeviced --bin kuserd --bin kotton-runner --bin kinferd --bin ksyncd --bin kquicd

# Headless release build.
build-release:
    cargo build --release --bin kotton --bin kdeviced --bin kuserd --bin kotton-runner --bin kinferd --bin ksyncd --bin kquicd

# Run Kotton headless: launch kuserd, then enter the runtime identity-first — type
# your key (it resolves who you are) or create a new identity. You're identified by
# your key, not a username, so there is no name argument. Depends on `build`.
# Usage: just headless::run
run: build
    cargo xtask "run::headless"
