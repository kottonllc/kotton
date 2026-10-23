set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# Two-node local harness (Arc A — "send a file to my phone"). Two isolated kuserd
# nodes on ONE machine — "a" = this laptop, "b" = "your phone" — plus a local relay
# so they reach each other by DID with no manual addressing (the same path verified
# in tests/suite/introduction.rs). The relay is configured AT RUNTIME (`relay set`), not
# via an env var — nodes boot relay-less and become reachable live.
#
# A device syncs to its person's drives and never to another device, so the
# `sync` below carries a file from A to B only once the person has a drive both
# reach (a vault enrolled on A before B joins); with none, `sync` says so.
#
# Typical session — FIVE terminals:
#   1) just nodes::relay   # local relay (presence + reachability)
#   2) just nodes::a       # node A daemon ("laptop") — boots relay-less
#   3) just nodes::b       # node B daemon ("phone")  — boots relay-less
#   4) just nodes::repl-a  # on A: onboard, then  `relay set http://127.0.0.1:7700`,
#                          #        then  `invite phone`
#   5) just nodes::repl-b  # on B: onboard (join), then `relay set http://127.0.0.1:7700`
#   then on A:  echo "hi" > /hello.txt  &&  sync     on B:  sync  &&  cat /hello.txt
# `just nodes::nuke` wipes both data dirs to start clean.

# --- Local relay (DID-addressed reachability between the nodes) ---
relay:
    cargo run --manifest-path infra/relay/Cargo.toml -- --bind 127.0.0.1:7700

# --- Node A daemon ("laptop") — boots relay-less; set the relay at runtime ---
[unix]
a:
    KOTTON_BASE_DIR=.kotton.node-a KUSERD_IPC_NAME=kuserd-a KOTTON_PEER_LISTEN_PORT=7401 cargo run --bin kuserd
[windows]
a:
    $env:KOTTON_BASE_DIR=".kotton.node-a"; $env:KUSERD_IPC_NAME="kuserd-a"; $env:KOTTON_PEER_LISTEN_PORT="7401"; cargo run --bin kuserd

# --- Node B daemon ("phone") — boots relay-less; set the relay at runtime ---
[unix]
b:
    KOTTON_BASE_DIR=.kotton.node-b KUSERD_IPC_NAME=kuserd-b KOTTON_PEER_LISTEN_PORT=7402 cargo run --bin kuserd
[windows]
b:
    $env:KOTTON_BASE_DIR=".kotton.node-b"; $env:KUSERD_IPC_NAME="kuserd-b"; $env:KOTTON_PEER_LISTEN_PORT="7402"; cargo run --bin kuserd

# --- Runtime on node A (identity-first: create an identity, then `invite phone`) ---
[unix]
repl-a:
    KOTTON_BASE_DIR=.kotton.node-a KUSERD_IPC_NAME=kuserd-a KOTTON_NODE_LABEL=laptop cargo run --bin kotton -- repl
[windows]
repl-a:
    $env:KOTTON_BASE_DIR=".kotton.node-a"; $env:KUSERD_IPC_NAME="kuserd-a"; $env:KOTTON_NODE_LABEL="laptop"; cargo run --bin kotton -- repl

# --- Runtime on node B (identity-first: choose join, paste the code from A) ---
[unix]
repl-b:
    KOTTON_BASE_DIR=.kotton.node-b KUSERD_IPC_NAME=kuserd-b KOTTON_NODE_LABEL=phone cargo run --bin kotton -- repl
[windows]
repl-b:
    $env:KOTTON_BASE_DIR=".kotton.node-b"; $env:KUSERD_IPC_NAME="kuserd-b"; $env:KOTTON_NODE_LABEL="phone"; cargo run --bin kotton -- repl

# --- Wipe both node data dirs (start clean) ---
[unix]
nuke:
    rm -rf .kotton.node-a .kotton.node-b
[windows]
nuke:
    Remove-Item -Recurse -Force .kotton.node-a, .kotton.node-b -ErrorAction SilentlyContinue
