set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# App management recipes — invoked as `just app::sideload`, `just app::list`, etc.
# Requires a running daemon (`just kuserd::start`) and an authenticated user (`just user::auth <user>`).

# Register a compiled WASM app directory with the running daemon.
# Reads manifest.toml and the compiled app.wasm from the app directory.
# Usage: just app::sideload ./guest/apps/kotton-shell austin
#
# On Windows while `kotton repl` is running: use the REPL instead to avoid
# the Windows exe lock — type inside the REPL:
#   app sideload ./guest/apps/kotton-shell
[windows]
sideload path user:
    .\target\debug\kotton.exe app sideload {{path}} --user {{user}}

[unix]
sideload path user:
    cargo run --bin kotton -- app sideload {{path}} --user {{user}}

# Remove a sideloaded app by ID.
# Usage: just app::unsideload sh.kotton.shell
unsideload id:
    cargo run --bin kotton -- app unsideload {{id}}

# List all registered apps.
list:
    cargo run --bin kotton -- app list

# Re-hash the installed WASM binary and verify it matches the stored content hash.
# Usage: just app::verify sh.kotton.shell
verify id:
    cargo run --bin kotton -- app verify {{id}}
