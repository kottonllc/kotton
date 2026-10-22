set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# Demo recipes -- invoked as `just demo::sync`, etc.

# Two-node encrypted file transfer demo.
#
# Spins up two isolated kuserd processes, exchanges identities, writes a file
# on node A, syncs it to node B over QUIC mTLS, and prints the result.
# State is written to .kotton.demo/; wiped and recreated on each run.
#
# Prerequisites: just headless::build  (builds kuserd + kotton)
sync:
    cargo xtask demo::sync
