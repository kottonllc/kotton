set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# WASM build targets — guest apps + the sandbox runner.
# Invoked as `just wasm::apps`, `just wasm::runner`.

# Compile all WASM guest apps (kotton-shell) to app.wasm.
apps:
    cargo xtask build-apps

# Build the kotton-runner WASM sandbox host binary.
runner:
    cargo build --bin kotton-runner
