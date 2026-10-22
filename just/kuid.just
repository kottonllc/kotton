set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# kuid compositor recipes — invoked as `just kuid::build`, `just kuid::start`.
# Requires a running kuserd (`just kuserd::start`) and an authenticated user (`just user::auth <user>`).

# Build the kuid display-server binary on the shipped renderer (requires Python 3).
#
# vello/wgpu — Metal on macOS, Vulkan on Linux, DX12 on Windows. This is the default:
# the window renders on the GPU, and a machine that offers no
# hardware adapter runs headless rather than opening a window that rasterises in software.
build:
    cargo build --bin kuid --features kuid/kuid-desktop,kuid/kuid-gpu

# Build kuid on the CPU seam — `vello_cpu` over softbuffer, no wgpu linked at all.
#
# **Named on purpose, and nothing in the product reaches it.** It is kept as a
# build-time seam rather than a fallback: at 1440x900 a CPU frame costs ~19ms, of which
# ~18ms is rasterisation, and a window that rasterises in software is the first
# impression the ruling declines to ship. `just desktop::shot` is the one recipe that
# builds it, as that ruling's documented contributor opt-in.
build-cpu:
    cargo build --bin kuid --features kuid/kuid-desktop

# Why the GPU default was once "not yet", kept because the reasoning is still read.
#
# **Verified drawing 2026-08-28** on native Windows/DX12 — the first frame this
# path produced anywhere. The default did not move that day, and the reason was
# not caution: a build-time feature cannot fall back. A `kuid-gpu` binary on a
# machine with no adapter failed at startup, which describes CI, this project's
# own dev container, and every headless node.
#
# **That failure is now a decision instead of a crash**, which is what let the default
# move: kuid asks wgpu for an adapter before it builds anything, and on a software
# adapter or none it prints one line naming `just headless::run` and exits cleanly
# (`refuse_without_a_gpu`, core/kuid/src/main.rs). Such a machine is a headless
# machine, so a runtime CPU fallback is not the answer, and choosing the renderer at
# run time is not needed.
#
# Native Windows was excluded here on the grounds that wgpu-hal 29 and
# gpu-allocator 0.28 could not agree on a `windows` crate version, with a note
# saying to use WSL. **That is no longer true**: it was rechecked by compiling instead of by reading a
# version number and found the pair clean; `check-all-platforms` below has been
# building exactly that combination ever since. The note outlived its blocker by
# two days and sent a Windows user to a CPU rasteriser in the meantime.
# Re-verified 2026-08-28: `--features kuid/kuid-desktop,kuid/kuid-gpu
# --target x86_64-pc-windows-msvc` checks clean.
#
# `build-gpu` is kept as an alias of `build`, because the name is in commit messages and
# in two records; they now produce the same binary.
build-gpu: build

# Cross-check every renderer/platform pair kuid claims to support.
#
# The watch condition for the Windows GPU build used to be "has gpu-allocator
# published a new version" — a proxy, checked three times over two months, always
# reading 0.28.0 and concluding "still blocked" while the build had in fact been
# fine for some time. A build blocker's watch condition is a build. This is it,
# and it takes under two minutes.
#
# Needs the targets: rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin
check-all-platforms:
    cargo check -p kuid --features kuid/kuid-desktop --target x86_64-unknown-linux-gnu
    cargo check -p kuid --features kuid/kuid-desktop,kuid/kuid-gpu --target x86_64-unknown-linux-gnu
    cargo check -p kuid --features kuid/kuid-desktop --target aarch64-apple-darwin
    cargo check -p kuid --features kuid/kuid-desktop,kuid/kuid-gpu --target aarch64-apple-darwin
    cargo check -p kuid --features kuid/kuid-desktop --target x86_64-pc-windows-msvc
    cargo check -p kuid --features kuid/kuid-desktop,kuid/kuid-gpu --target x86_64-pc-windows-msvc

# Start the kuid display-server compositor, on the shipped renderer.
#
# The bootstrap token this comment used to name is gone: kuserd hands kuid one end of a
# pipe pair at spawn, and possession of that is the whole credential (2026-08-27).
start:
    cargo run -p kuid --features kuid/kuid-desktop,kuid/kuid-gpu
