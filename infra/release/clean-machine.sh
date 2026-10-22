#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install a release archive on a machine that has never had a toolchain, and make
# an identity there. A measurement, run by hand; `cargo xtask release-test` is the
# in-tree test every archive passes before it is named.
#
#   sh infra/release/clean-machine.sh out/dist/kotton-<rev>-linux-x86_64.tar.gz
#
# The machine is a stock `ubuntu:24.04` image plus RUNTIME below: the shared
# libraries the binaries load, and nothing a build needs. Before anything runs
# it asserts that no cargo, rustc or python is on it and no GTK headers are, then
# runs the steps `docs/use/first-hour.md` gives a friend, with **no network**
# (`--network none`): install.sh, kotton-start, `kotton id create` at a terminal
# (util-linux `script` makes one), `kotton id list`.
#
# The one thing it cannot show is the window: a container has no GPU, and the
# archive's window renders on one (DEC-0076). What it shows is everything short
# of that. TASK-a-friend-cannot-install-kotton-without-a-toolchain.
set -eu

archive=${1:?usage: sh infra/release/clean-machine.sh <archive.tar.gz> [base-image]}
image=${2:-ubuntu:24.04}
archive=$(CDPATH='' cd -- "$(dirname -- "$archive")" && pwd)/$(basename -- "$archive")

# The runtime libraries, by package: what `ldd` needs resolved for every binary
# in bin/, measured 2026-09-25 against this image. `ldd` inside the run below
# fails the measurement if one is missing, and says which.
RUNTIME="libgtk-3-0t64 libxdo3 libayatana-appindicator3-1 libssl3t64 ca-certificates"

tag=kotton-clean-machine
docker build -q -t "$tag" - >/dev/null <<DOCKERFILE
FROM $image
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $RUNTIME && rm -rf /var/lib/apt/lists/*
RUN useradd -m friend
DOCKERFILE

# `seccomp=unconfined` because the daemon keeps its device key in the kernel
# keyring (kotton-secret, `linux-no-secret-service`), and docker's default seccomp
# profile refuses `add_key` and `keyctl`: under it the daemon exits with
# `Platform secure storage failure: PermissionDenied` before it listens. A Linux
# desktop allows those calls; a default container is not the machine a friend has.
# Measured 2026-09-25, and filed:
# TASK-the-daemon-dies-opaquely-where-the-kernel-keyring-is-refused.
docker run --rm --network none --security-opt seccomp=unconfined -u friend -w /home/friend \
    -v "$archive:/tmp/kotton.tar.gz:ro" "$tag" sh -eu -c '
    say() { echo "clean-machine: $*"; }
    for t in cargo rustc rustup python3 python pkg-config cc gcc; do
        if command -v "$t" >/dev/null 2>&1; then say "FAIL — $t is on this machine, so it is not clean"; exit 1; fi
    done
    if [ -e /usr/include/gtk-3.0 ] || [ -e /usr/include/pango-1.0 ]; then say "FAIL — development headers are installed"; exit 1; fi
    say "no cargo, rustc, python, compiler or GTK/pango headers here; no network"

    tar -xzf /tmp/kotton.tar.gz
    cd kotton-*/
    missing=$(for b in bin/*; do ldd "$b" | grep "not found" | sed "s|^|$b: |"; done)
    if [ -n "$missing" ]; then say "FAIL — shared libraries missing:"; echo "$missing"; exit 1; fi
    say "every binary in bin/ resolves its shared libraries"

    sh install.sh
    cd "$HOME"
    rm -rf kotton-*/
    export PATH="$HOME/.local/bin:$PATH"

    RUST_LOG=info kotton-start > daemon.log 2>&1 &
    daemon=$!
    door=$(kotton config paths | sed -n "s/^  socket: *//p")
    for _ in $(seq 1 120); do [ -S "$door" ] && break; sleep 0.5; done
    [ -S "$door" ] || { say "FAIL — the daemon never listened at $door"; tail -30 daemon.log; exit 1; }
    say "kotton-start: the daemon is up"

    # Enter at the passphrase prompt takes the suggested one, as a person may.
    (sleep 3; printf "\n"; sleep 10) | script -qec "kotton id create friend" /dev/null > create.log 2>&1 || {
        say "FAIL — kotton id create"; cat create.log; tail -30 daemon.log; exit 1; }
    grep -q "created" create.log || { say "FAIL — kotton id create did not say it created"; cat create.log; exit 1; }
    kotton id list | grep -q friend || { say "FAIL — kotton id list does not show friend"; exit 1; }
    say "kotton id create friend, from the installed prefix, at a terminal: done"
    cmp -s "$HOME/.local/opt/kotton/share/kotton/shell/app.wasm" "$HOME/.local/share/kotton/system/shell/app.wasm" \
        || { say "FAIL — the daemon did not stage the shell it shipped with"; exit 1; }
    say "the daemon staged the shell it shipped with"
    kill "$daemon" 2>/dev/null || true
    say "PASS"
'
