set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# kuserd daemon recipes — invoked as `just kuserd::build`, `just kuserd::start`, `just kuserd::dev`.

# Build the kuserd user-daemon binary.
build:
    cargo build --bin kuserd

# Start kuserd against your real node (foreground).
# Run `just user::auth <user>` in a second terminal after the daemon is ready.
start:
    cargo run --bin kuserd

# Start an isolated kuserd in .kotton.dev/ (safe to hack on).
# Data goes to .kotton.dev/; socket name is kuserd-dev.
# Before running kotton commands against this instance, set in your shell:
#   export KUSERD_IPC_NAME=kuserd-dev          # Unix
#   $env:KUSERD_IPC_NAME = "kuserd-dev"        # Windows PowerShell
# Run `just nuke` to wipe and start fresh.
[unix]
dev:
    KOTTON_BASE_DIR=.kotton.dev KUSERD_IPC_NAME=kuserd-dev cargo run --bin kuserd

[windows]
dev:
    $env:KOTTON_BASE_DIR=".kotton.dev"; $env:KUSERD_IPC_NAME="kuserd-dev"; cargo run --bin kuserd
