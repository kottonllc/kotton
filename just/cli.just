set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# CLI profile — the kotton CLI binary only. Invoked as `just cli::build`.

# Build the kotton CLI binary.
build:
    cargo build --bin kotton

# Release build of the kotton CLI binary.
build-release:
    cargo build --release --bin kotton
