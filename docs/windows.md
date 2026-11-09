# Kotton on Windows

What a person running Kotton on Windows x86_64 gets, what the gate holds of it on every
pull request, and what it does not. The protocol names Windows on x86_64 as a device at
`v0.1.0` and says each device platform is built and tested in the gate, so that what a
person runs is what the release was held to; this page says how far that is true today.
Windows on arm64 is not built and not promised.

## Building it

`cargo` builds the workspace on Windows as on Linux, through PowerShell. The
[`Justfile`](../Justfile) names what to install first:

- **OpenSSL**, which the encrypted record database links against: `scoop install openssl`,
  then set `OPENSSL_DIR` to where it landed, in a gitignored `.env` that `just` loads, or in
  the shell for a bare `cargo build`. `.cargo/config.toml` forbids a vendored copy
  (`OPENSSL_NO_VENDOR`); it does not know where yours is.
- **MSVC Build Tools**, from the Visual Studio Installer ("Desktop development with C++").

The toolchain is the one `rust-toolchain.toml` names; `rustup` installs it on the first
`cargo`. Kotton's data lives under `%LOCALAPPDATA%\Kotton`, and the daemon's socket is a named
pipe where Linux has a Unix domain socket (`core/ipc`).

## What every pull request holds on Windows

One job on a `windows-latest` runner, [`.github/workflows/windows.yml`](../.github/workflows/windows.yml),
runs on every pull request and is a required check on `main`. It is a build, not a check: a
check stops before codegen and the link, and the link is where a Windows-only symbol, an
import library or the linker fails. The job:

- builds the workspace with warnings refused;
- compiles every test target in the workspace, the integration suite's, xtask's and the
  daemons' included, so each one is held to compile on Windows whether or not it runs there;
- runs every test of the library crates it names, which is the greater part of the tree;
- runs the daemons' own unit tests in-process, with no daemon started.

The run is declared same-machine, so every socket binds loopback and nothing advertises on
the network; no test raises the Windows firewall dialog. The workflow's header says what it
holds and why, by test rather than by crate; it is the authority, and this page does not
restate its list.

## What it does not hold

- **The integration suite** (`tests/`), which starts the daemons and the relay as processes,
  is compiled on Windows and run by no workflow on any platform: it runs under `just test` on
  the contributor's Linux machine, and the pull request records that run's exit. The relay
  itself is a workspace of its own, released for Linux alone, and is not built on Windows;
  `cargo xtask windows-check`, a grep for Unix-only calls that runs in `just lint`, is what
  still reads it, and says so in its module doc.
- **xtask's tests**, the gate's own tooling, written for Linux; no job runs them on either
  platform, and Windows compiles them.
- **kvaultd's integration tests**: three install the built vault and drive it with a shell and
  Linux tools, and one compares its settings reader with systemd's.
- **A release archive.** The release workflow produces no Windows archive today; the
  PowerShell installer kotton-dist will ship has nothing to install until it does
  (kotton #59). A Windows build of the tree has been run by hand and is not a release.
- **Confinement reaching a guest.** The Windows sandbox, an AppContainer with no
  capabilities, an access entry per grant and a job object attached at process creation, is
  written, compiled and measured by `core/proc`'s own probes on every pull request. It is not
  reached by `confine`, which still refuses on Windows: stable Rust gives a `Command` no way to
  carry the attribute list the container rides on. `core/proc/src/provider/sandbox/mod.rs`'s
  platform table and `windows.rs`'s module doc say exactly what is measured and what is not.
  A guest launched on Windows today runs unconfined, and the daemon says so in its log
  (`core/app`'s `on_unsupported`) rather than pretending otherwise.
- **The window.** This repository ships no window: the desktop is built elsewhere, nothing
  here builds it on any platform, and no gate here exercises it.

A thing not held here is a thing a pull request can break without a check going red. When
one of these moves into the gate, this page and the workflow's header move with it.
