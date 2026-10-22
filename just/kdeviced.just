set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# kdeviced device-daemon recipes — invoked as `just kdeviced::build`, `just kdeviced::start`.
# kdeviced is only needed for multi-user production or kctl operator tooling.
# For single-user development, use `just kuserd::start` instead.

# Build the kdeviced device-daemon binary.
build:
    cargo build --bin kdeviced

# Start kdeviced (device-level orchestration daemon).
start:
    cargo run --bin kdeviced
