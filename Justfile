# KOTTON development recipes
# Install: cargo install just  |  Docs: https://github.com/casey/just
# Run `just` (no args) to list everything.

# On Windows, run recipes through PowerShell
set windows-shell := ["powershell", "-NoLogo", "-Command"]

# Load .env so local overrides (OPENSSL_DIR, KOTTON_BASE_DIR, etc.) flow into recipes.
set dotenv-load

# The relay's own target directory: `out/relay`, or `CARGO_TARGET_DIR` when that is exported,
# because the variable wins for every developer convenience build. The relay a release packs
# is not built here: `release-server` builds it in a target of its own (`out/release/relay`).
# The relay is a workspace of its own and cargo reads `build.target-dir` from where it is
# run, not from the manifest it is handed, so a recipe that builds it passes this.
# `cargo xtask build-relay` and `cargo xtask out relay` say the same thing from
# `xtask/src/out.rs`.
relay_target := env_var_or_default("CARGO_TARGET_DIR", "out/relay")

# A daemon reads no relay from its environment: point it at a local
# dev-services relay with `kotton config relay set http://localhost:7700`.
#
# KOTTON_BASE_DIR, KDEVICED_IPC_NAME, and KUSERD_IPC_NAME can be set to isolate a daemon instance
# (e.g. in CI or when running `just daemon-dev`). Do not set these for normal
# development — all dev tooling (daemon, CLI, host) shares the same default
# data directory:
#   Linux:   $XDG_DATA_HOME/kotton  (~/.local/share/kotton if XDG_DATA_HOME unset)
#   macOS:   ~/Library/Application Support/Kotton
#   Windows: %LOCALAPPDATA%\Kotton

# Windows prerequisites -------------------------------------------------------
#
# Required for all builds:
#   scoop install openssl
#
#   SQLCipher (kotton-record) links against system OpenSSL.
#   .cargo/config.toml sets OPENSSL_NO_VENDOR and OPENSSL_DIR automatically so
#   the build works in any shell (bash, PowerShell) without sourcing .env.
#   Perl is no longer required — the vendored OpenSSL build was dropped.
#   You also need MSVC Build Tools (Visual Studio Installer → "Desktop development with C++").
#
# Required for desktop builds only (just desktop::build / just desktop::build-release):
#   scoop install python
#
#   Python 3 is required by the stylo CSS engine, a transitive dep of blitz-shell.
#   It runs a code-generation step at compile time. Not needed for headless/server nodes.
#
# On Linux/macOS: libssl-dev (Debian/Ubuntu) or openssl (Homebrew); python3 is
# usually pre-installed. No manual env vars needed.
# ------------------------------------------------------------------------------

# -- modules ------------------------------------------------------------------
#
# Domain-first: every deployable/profile owns its lifecycle verbs (build / setup /
# start / deploy). Component daemons and management areas are domains too.

# Profiles — full lifecycle per profile:
#   `just headless::build|build-release|run <user>`
#   `just desktop::build|build-release|run <user>`  (requires Python 3)
#   `just cli::build|build-release`
# `run` provisions the identity on first launch (no separate setup step).
mod cli 'just/cli.just'
mod headless 'just/headless.just'
mod desktop 'just/desktop.just'

# WASM build targets: `just wasm::apps` (guest apps), `just wasm::runner` (sandbox runner)
mod wasm 'just/wasm.just'

# kotton-relay infra: `just relay::build`, `just relay::deploy`, `just relay::down`, `just relay::logs`
mod relay 'just/relay.just'
# Real topologies of real images — the scenario harness (infra/scenarios)
mod stack 'just/stack.just'
# A rented host has no recipes: the guides in docs/use/ are the commands, typed on the host.
# What a host runs is `cargo xtask release-server relay|vault`: two archives, no Docker.
mod release 'just/release.just'

# Component daemons: `just <name>::build`, `just <name>::start` (kuserd also `::dev`)
mod kuserd 'just/kuserd.just'
mod kdeviced 'just/kdeviced.just'
mod kuid 'just/kuid.just'

# User management: `just user::add`, `just user::auth`, `just user::list`, `just user::rm`
mod user 'just/user.just'

# App management: `just app::sideload`, `just app::list`, `just app::unsideload`, `just app::verify`
mod app 'just/app.just'

# Code generation: `just gen::docs`, `just gen::docs_check`
mod gen 'just/gen.just'

# Demo recipes: `just demo::sync`
mod demo 'just/demo.just'

# Two-node local harness: `just nodes::a`, `just nodes::b`, `just nodes::repl-a <user>`
mod nodes 'just/nodes.just'

# -- entrypoint ----------------------------------------------------------------

# List all available recipes
default:
    @just --list

# -- primary workflows ---------------------------------------------------------

# Stop all running Kotton processes (kuserd, kdeviced, kuid, kotton, kctl, ksyncd, kquicd, khttpd, kinferd).
[windows]
stop:
    foreach ($name in @("kotton","kctl","kuserd","kdeviced","kuid","ksyncd","kquicd","khttpd","kinferd")) { \
        Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -Force \
    }; Write-Host "[stop] all Kotton processes terminated"

[unix]
stop:
    pkill -f "kuserd|kdeviced|kuid|ksyncd|kquicd|khttpd|kinferd" || true
    echo "[stop] all Kotton processes terminated"

# Open a headless terminal REPL for a user.
# Usage: just terminal austin
terminal user:
    cargo run --bin kotton -- repl {{user}}

# Build everything for development: WASM apps + desktop binaries + sandbox runner.
build-all:
    cargo xtask build-apps
    cargo build --bin kotton --bin kdeviced --bin kuserd --bin kuid --bin kotton-runner --features kuid/kuid-desktop,kuid/kuid-gpu

# -- testing -------------------------------------------------------------------

# Run all tests.
# Two binaries must exist before the integration suite runs, because some tests
# spawn real processes rather than linking a library:
#   * kotton-mock-runner — a workspace member, not a dev-dep (binary-only crates
#     can't be deps), so `cargo test` never builds it.
#   * kuserd — `cargo test` builds test targets and the bins of the package under
#     test, but not a dependency crate's bin, so two_node_transfer's
#     `env!("KUSERD_BIN")` points at a path that doesn't exist yet.
# Both fail as "No such file or directory" at spawn, which reads like a broken
# test rather than a missing prerequisite — hence building them here.
# Mutation unit tests in kuid require the kuid-desktop feature.
#
# `cargo xtask bind-check` is `cargo test` with the promise enforced.
# KOTTON_PAIR_LOCAL_ONLY declares the run same-machine: every inbound socket binds
# loopback and the mDNS multicast advertise is skipped. Both daemons in a two-node
# test share a host and dial 127.0.0.1, so a LAN-facing socket reaches nobody it
# needs to — and opening one makes Windows Defender raise a firewall dialog. That
# dialog is a GUI prompt: a background or CI run sits blocked on it and looks like a
# slow test rather than a stuck one.
#
# That claim was false for four months across two separate sockets, because nothing
# checked it: a gate cannot see a socket by reading source. bind-check sets the
# variable and runs the suite with `tools/bindwatch` interposed on bind(2), so a
# non-loopback bind fails the run and names the test binary that made it. It is
# Linux-only (LD_PRELOAD) and says so on the platforms it cannot observe, rather
# than printing a pass it did not earn.
#
# `kotton_peer::scope` owns the switch and lists what honors it. It used to live in
# the pairing module and cover only the pairing listener, which is why the QUIC peer
# listener — bound by peer_sync, relay_peer_sync and every enroll_threshold_sign
# case — kept raising the dialog anyway.
#
# `scope` is domain-tier, so primitive-tier code cannot consult it. mDNS lives in
# `kotton-net`: its boot path is gated at the domain-tier caller instead
# (`kotton_device::network::instantiate_discovery`), and the `kotton-net` unit tests
# that construct a live ServiceDaemon are `#[ignore]`d — they bind :5353, which no
# env var set here can prevent. `-- --include-ignored` runs them, and bind-check
# will report the socket when it does.
#
# One recipe on every platform: bind-check sets the variable itself, so this no
# longer needs a PowerShell arm to avoid the inline `VAR=value cmd` prefix that
# PowerShell reads as a command name.
test:
    # `kotton` is here because `tests/suite/cli_identity.rs` runs it as a process —
    # the first tests in the repository that do (2026-09-11). It was not in this
    # list, so all four of them failed under `just test` on `main` with the
    # harness's own message ("the `kotton` CLI is not built"), while passing for
    # anyone who ran `cargo test --workspace` by hand. A test added to prove the
    # CLI works, not run by the gate that exists to run it. `kvaultd` is here for
    # `suite/headless.rs`, which installs it with the self-host adapter and starts it as
    # its unit does.
    cargo build --bin kotton --bin kotton-mock-runner --bin kuserd --bin khttpd --bin kotton-runner --bin kinferd --bin kvaultd
    # `confinement` runs real components in the real runner; this builds them.
    cargo xtask build-apps
    # The relay is its own workspace; the relay tests spawn this binary, from `out/relay`.
    cargo xtask build-relay
    cargo xtask bind-check
    # The shipped renderer, not the seam. The window renders on the GPU, so `kuid-gpu` is what
    # `just desktop::build` produces, and a gate that compiles the other build is a gate
    # that has never compiled the binary a person is handed. It also decides whether the
    # refusal is tested at all: `gpu_refusal` in `core/kuid/src/main.rs` is cfg'd on
    # `kuid-gpu`, so under the old feature set those four tests existed and nothing ran
    # them. Needs no GPU — `gpu_verdict` is a function of what an adapter says about
    # itself, and every renderer test here draws into an image with `vello_cpu`.
    cargo xtask bind-check -- -p kuid --features kuid/kuid-desktop,kuid/kuid-gpu
    # And the seam still has to compile. `anyrender_vello_cpu` stays in the
    # tree as a build-time opt-in — it is what `just desktop::shot` builds, on a machine
    # that cannot open a window at all — so it is code the project still owns. `check`
    # rather than `test`: the ruling says this path is unmeasured, and the two feature
    # sets share every test but the type alias under them.
    cargo check -p kuid --features kuid/kuid-desktop --all-targets
    cargo xtask bind-check -- --manifest-path infra/relay/Cargo.toml --target-dir {{relay_target}}

# `cargo test -p kotton-integration-tests` builds none of the binaries the suite runs as
# processes (each is bin-only; see tests/build.rs), so a narrow run needs them built first,
# and the suite's own check (`common::bins`) names any that are not. Names are as `--list`
# prints them: `just test_suite headless::a_second_nameless_mint_typed_at_the_repl_is_refused_by_the_daemon`.
# The relay is built by `cargo xtask build-relay`, the one command for it, into the directory
# the suite's `relay_bin` reads back.
#
# The guest apps' `app.wasm` are the inputs that are not binaries, and `kuserd` embeds all
# three as it compiles, so `cargo xtask build-apps` runs first. A test that needs an input that is not
# built fails naming it; none returns green without running.
#
# Build every input the integration suite needs, then run the suite tests named, exactly.
test_suite +tests:
    cargo xtask build-apps
    cargo build --bin kotton --bin kotton-mock-runner --bin kuserd --bin khttpd --bin kotton-runner --bin kinferd --bin kvaultd
    cargo xtask build-relay
    cargo xtask bind-check -- -p kotton-integration-tests --test suite -- --exact {{tests}}

# Run tests for a specific crate (e.g. `just test_crate kotton-shell`)
test_crate crate:
    cargo xtask bind-check -- -p {{crate}}

# -- hygiene & CI --------------------------------------------------------------

# Kill all running Kotton processes (releases Windows file locks before build/clean).
[unix]
kill:
    -pkill -f "kuserd|kuid|kdeviced|kotton|kinferd" || true

[windows]
kill:
    -Stop-Process -Name kotton,kuid,kuserd,kdeviced,kquicd,ksyncd,khttpd,kinferd -ErrorAction SilentlyContinue

# Wipe a DEVELOPMENT base directory — `just dev`'s `.kotton.dev`, or one you name.
#
# **This is not the product's clean install, and the default is not where a person's
# Kotton lives.** `just headless::run` and `just desktop::run` set no KOTTON_BASE_DIR,
# so they use the platform default (`%LOCALAPPDATA%\Kotton`, `~/Library/Application
# Support/Kotton`, `~/.local/share/kotton`). Running bare `just nuke` after following
# the README therefore deletes a directory you never wrote to and exits 0, which is
# how it read as a clean install while cleaning nothing.
#
# For a real device, use the verb that owns both halves and cannot name the wrong
# directory:
#
#     kotton device reset          # lists what it will delete, refuses
#     kotton device reset --yes
#
# **The keychain half below does not match the directory half, and never did.** It
# clears the unscoped "Kotton" service — the DEFAULT install's — while removing
# whatever directory it was given. A non-default base dir gets its own service,
# "Kotton@<absolute path>" (`OsSecrets::for_base_dir`), which this does not touch.
# So bare `just nuke` deletes a dev directory and the production install's secrets.
# That is left as it is rather than half-fixed here: matching them means resolving
# the scoped name before the directory goes and sweeping a service per platform,
# which is `kotton device reset`'s job and is tested there.
[unix]
nuke base_dir=".kotton.dev":
    -pkill -f "kuserd|kuid|kdeviced|kotton"
    -rm -rf "{{base_dir}}"
    # macOS Keychain: delete every "Kotton" generic-password entry (loop until none).
    -while security delete-generic-password -s Kotton >/dev/null 2>&1; do :; done
    @echo "Nuked {{base_dir}} + the unscoped Kotton keychain entries (macOS). Linux uses the kernel keyring (keyutils) — entries clear on logout, or run 'keyctl clear @s'."
    @echo "NOTE: dev wipe. A real device is 'kotton device reset', which owns both halves."

[windows]
nuke base_dir=".kotton.dev":
    -Stop-Process -Name kotton,kuid,kuserd,kdeviced,kquicd,ksyncd,khttpd,kinferd -ErrorAction SilentlyContinue
    -Remove-Item -Recurse -Force "{{base_dir}}" -ErrorAction SilentlyContinue
    # Windows Credential Manager: delete every stored credential naming Kotton. The
    # match is on the name, so it covers both "Kotton" and "Kotton@<path>".
    -cmdkey /list | Select-String 'Kotton' | ForEach-Object { ($_ -replace '.*Target:\s*','').Trim() } | Where-Object { $_ } | ForEach-Object { cmdkey /delete:$_ | Out-Null }
    Write-Host "Nuked {{base_dir}} + Kotton keychain entries"
    Write-Host "NOTE: this was a dev wipe. A real device is 'kotton device reset'."

# Wipe an isolated data directory for CI (defaults to /tmp/kotton-ci on Unix). Only
# the data dir — CI runs isolated, so it does not touch the shared OS keychain.
[unix]
ci-nuke base_dir="/tmp/kotton-ci":
    -pkill -f kuserd
    -rm -rf "{{base_dir}}"
    @echo "Wiped {{base_dir}}"

[windows]
ci-nuke base_dir="$env:TEMP/kotton-ci":
    -Stop-Process -Name kuserd -ErrorAction SilentlyContinue
    -Remove-Item -Recurse -Force "{{base_dir}}" -ErrorAction SilentlyContinue
    Write-Host "Wiped {{base_dir}}"

# Run clippy and the structural checks: the fast gate, the one every pull request runs
# (`.github/workflows/lint.yml`) and the one to run before you open one. Each check is a
# property of the code or the documents a reader is sent to, and each says what it holds
# when it fails.
lint:
    # First, and about the machine rather than the code: every gate below assumes its tools
    # exist. Fails only on the `lint` tier, so a contributor without the GTK stack is not
    # blocked from fixing a document.
    cargo xtask doctor
    # `--all-targets`, not bare `cargo clippy`: bare clippy builds the lib target only, so
    # everything inside `#[cfg(test)]` and every integration-test binary would go unlinted.
    # `-D warnings`, as the relay below: a new warning fails the gate instead of joining a
    # pile nobody reads. The workspace was swept to none to make this hold (#91).
    cargo clippy --all-targets -- -D warnings
    # infra/relay declares its own `[workspace]`, so the `cargo clippy` above never reaches
    # it. It is held to `-D warnings` the same way.
    cargo clippy --manifest-path infra/relay/Cargo.toml --target-dir {{relay_target}} --all-targets -- -D warnings
    # The principles it inspects (II, III and IV), against the code.
    cargo xtask constitution-check
    cargo xtask tier-check
    cargo xtask blindness-check
    cargo xtask vault-check
    cargo xtask key-reach-check
    # The inference runtime's crate, core/infer, opens nothing. An allow-list rather than a
    # deny-list of networking crates, plus a source grep, because `std::net` needs no
    # dependency at all.
    cargo xtask infer-check
    # Both server units say MemoryDenyWriteExecute=yes; this holds that neither closure links
    # a crate that emits code at run time.
    cargo xtask wx-check
    # Every binary an archive packs links only the system's crates and crates.io; the crates
    # here today that are not the system's are printed as the cuts still owed.
    cargo xtask ship-check
    # One feature set for every test build, so the shared crates are compiled once. When it
    # fails: `cargo xtask workspace-hack`.
    cargo xtask workspace-hack-check
    # `device` may name a user's store, never enumerate or resolve one.
    cargo xtask residency-check
    # A device-config key with a reader and no writer is a switch nothing can flip.
    cargo xtask config-key-check
    # The relay and the vault compose onto one machine.
    cargo xtask port-check
    # Every dependency carries a licence Kotton may ship under, every crate and source file
    # declares its directory's, and LICENSE states the same boundary.
    cargo xtask license-check
    cargo xtask link-check
    # The documents a reader is sent to say what is true, not what happened: no file under
    # docs/, no root *.md, no string literal under xtask/src/ (the lines a gate prints; a
    # named file's test fixtures may hold a timestamp) and no Rust comment under the trees
    # host-word-check reads (but the files the check still lists as not yet swept) names a
    # record or narrates a date; and no file beside them (this Justfile, just/*.just, the
    # workflows, the root manifests) names a record.
    cargo xtask docs-present-check
    # docs/cli/reference.md is generated from the CLI's command tree; checked, never
    # rewritten, so a dirty copy cannot go green.
    cargo xtask-docs docs-check
    # Every `kotton` command README.md gives is one the binary has (held through the reference
    # above), and every script it runs from a checkout is in this tree. A page added later is
    # gated by naming it here: `cargo xtask claim-check <page>…`.
    cargo xtask claim-check
    # What a person reads says *host* for the machine and *instance*, *relay* or *vault* for
    # what runs on it, never *box*: the root *.md (README.md, CONTRIBUTING.md, CLAUDE.md and
    # their kin), the installer, infra's READMEs, the CLI reference, and the string literals
    # of the shell, the CLI, xtask, infra/relay, and every crate under core/, its sources and
    # its tests.
    cargo xtask host-word-check
    # A path named in CLAUDE.md, CONTRIBUTING.md or README.md exists.
    cargo xtask facts-check
    # Every UserRequest variant has a domain, and every assignment names a real variant.
    cargo xtask request-domains
    # The JSON surface of the IPC request enum, pinned. When a wire change is deliberate:
    # `cargo xtask wire-surface`.
    cargo xtask wire-check
    # One acceptor, one request type.
    cargo xtask channel-check
    # No Unix-only path where Windows will also compile it.
    cargo xtask windows-check
    # A declared IPC scope names verbs the channel actually has.
    cargo xtask scope-check
    # `RemoteRequest` is generated from the `Remote` arms of required_trust(), so widening
    # the remote surface is a diff in a generated file.
    cargo xtask remote-request-check
    # No way to accept a request without being told who sent it.
    cargo xtask caller-check
    # A relay's address is compared in one place.
    cargo xtask relay-address-check
    # Every file under tests/tests/suite/ is compiled into the one integration binary.
    cargo xtask suite-check
    # GitHub Actions runs the release workflow on a pushed tag and the lint workflow on a
    # pull request, on Linux, and nothing else.
    cargo xtask actions-check
    # A contribution is certified, not granted: every commit since origin/main carries its
    # author's `Signed-off-by:`, with no exemption, and none is made as an agent.
    # `.github/workflows/signoff.yml` holds the same rule on every pull request; this holds it,
    # plus the shape of an agent's commit, under `just lint`, and a test keeps the two in agreement.
    cargo xtask signoff-check

# What each worktree costs on disk, and what is reclaimable.
worktrees *ARGS:
    cargo xtask worktrees {{ARGS}}

# Delete every build output this checkout holds, which is `out/` and nothing else — the
# workspace target, xtask's, the guest apps', the relay's, the merge gate's, the release builds'
# and the release archives (`.cargo/config.toml`, `xtask/src/out.rs`). The next build is cold.
# A `CARGO_TARGET_DIR` exported to somewhere else is a cache somebody shares and is not this
# checkout's to delete; `cargo clean` there, knowingly.
[unix]
clean:
    rm -rf out

[windows]
clean:
    if (Test-Path out) { Remove-Item -Recurse -Force out }

# Reclaim disk from this checkout's build caches (`out/target`, `out/xtask`, `out/merge`,
# `out/release`'s workspace, relay and guest-app targets). It is safe while a build may
# be live because it takes cargo's own `.cargo-lock` on each profile directory first, so it
# waits for the build rather than racing it; the ten-minute age floor is a second guard, not
# the reason. `--dry-run` prints the plan.
# The rules live in `xtask/src/reclaim.rs`, once, rather than in each agent's shell history.
reclaim *ARGS:
    cargo xtask reclaim {{ARGS}}

# Check that docs build cleanly
rustdoc:
    cargo doc --no-deps

# -- dev services (Docker Compose) -------------------------------------------
#
# Starts the local dev stack: kotton-relay.
# Requires Docker with Compose v2 (`docker compose` not `docker-compose`).
#
# Service addresses:
#   kotton-relay  http://localhost:7700

# Start all dev services in the background
dev_services:
    docker compose up -d --build
    @echo ""
    @echo "Dev services running:"
    @echo "  relay       http://localhost:7700"
    @echo ""
    @echo "Point Kotton at it: kotton config relay set http://localhost:7700"

# Stop and remove all dev service containers (data volumes are preserved)
dev_services_stop:
    docker compose down

# Stop and remove containers AND wipe all persistent volumes
dev_services_clean:
    docker compose down -v

# Follow logs from all dev services
dev_services_logs:
    docker compose logs -f

# Run the relay suites on their own. Each test spawns its own `kotton-relay`
# (`common::relay`), so nothing needs to be running first — these are
# in `just test` too. Set KOTTON_RELAY_ADDR to point them at a relay elsewhere.
e2e_relay:
    cargo xtask build-relay
    cargo test -p kotton-integration-tests -- --nocapture \
      relay_circuit relay_peer_sync relay_presence rendezvous_handles \
      enroll_then_threshold_sign_over_relay
