set windows-shell := ["powershell", "-NoLogo", "-Command"]
set working-directory := ".."

# Desktop profile — everything in headless + the kuid display-server sidecar.
# Requires Python 3 on the PATH: the `stylo` CSS engine (a blitz-shell transitive dep)
# generates code at build time.  Windows: `scoop install python`; macOS/Linux: usually present.
# Invoked as `just desktop::build`, `just desktop::run <user>`.

# Build the desktop binaries (headless + the kuid compositor + runner) AND the WASM
# guest apps (the shell). Requires Python 3.
#
# `render` picks kuid's renderer, and **the default is `gpu`**: the window
# renders on the GPU, and a machine that offers no hardware adapter runs headless rather
# than opening a window that rasterises in software. It is a build-time feature, not a
# runtime flag, which is why it is a recipe parameter: the binary either has wgpu linked
# or it does not.
#
# `cpu` builds the other seam, which nothing in the product reaches and nothing measures.
# It exists for a contributor whose machine cannot open a window at all, and
# `desktop::shot` below is the one recipe that passes it — see the note there.
#
#   just desktop::build          the shipped compositor
#   just desktop::build cpu      the CPU seam, named on purpose
#
# A `gpu` build on a machine with no GPU **does not fall back**: it prints one line
# naming `just headless::run` and exits without opening a window, and the daemon stops
# supervising it. That is the ruling working, not a failure.
build render="gpu":
    cargo xtask build-apps
    cargo build --bin kotton --bin kdeviced --bin kuserd --bin kotton-runner --bin kinferd --bin ksyncd --bin kquicd --bin kuid --features {{ if render == "cpu" { "kuid/kuid-desktop" } else { "kuid/kuid-desktop,kuid/kuid-gpu" } }}

# Desktop release build (requires Python 3). The shipped renderer — this
# recipe builds what a person would be handed, so it is the one place where a CPU
# rasteriser would ship by accident.
build-release:
    cargo build --release --bin kotton --bin kdeviced --bin kuserd --bin kotton-runner --bin kinferd --bin ksyncd --bin kquicd --bin kuid --features kuid/kuid-desktop,kuid/kuid-gpu

# Run Kotton with the kuid display server (GUI). Depends on `build`. Requires Python.
#
# **The user is optional, and the window owns onboarding**.
#
#   just desktop::run           no identity yet — the window's welcome flow creates one,
#                               called `owner`.
#   just desktop::run austin    the existing identity `austin`, unlocked on the window's
#                               lock screen (or the chooser, with several registered).
#
# **The terminal never asks for a credential on either line.** It used to on the second:
# the recipe authenticated in the terminal while the window showed a screen offering the
# same act — two doors to one thing, and answering either left the other waiting. That step
# is deleted, not skipped; the window is the one door.
#
# A username *selects*; it never creates. To have an identity under a name of your
# choosing, create it first:
#
#   cargo run --bin kotton -- id create <name>
#
# **Every run stages the freshly built shell into `<base>/system/shell/`**, with a name and
# without one, because there is one body of the shell and every path runs it — the welcome,
# the lock screen, and the relaunch as a user. A named user does not have a shell of their
# own to run instead: an identity is still born with the shell and the editor registered to
# it (`bundled_apps()`), but for the app it *designates* as its shell that row carries the
# designation and this staging carries the body. So a rebuild reaches the logged-in desk.
run user="" render="gpu": (build render)
    cargo xtask "run::desktop" {{user}}

# A picture of the window, on a machine that cannot show one (Linux).
#
# **This is a contributor's opt-in, not a shipped path.** The window renders on the
# GPU, and one thing was left open — "what a contributor without a GPU does …
# the answer may be a documented opt-in rather than an amendment". This is that opt-in.
# Nothing in the product knows it exists; the GPU is still where the window is meant to
# render, and `just desktop::run` is still how a person opens one.
#
# What it does: starts `Xvfb` on a free display, runs `desktop::run` against it on the
# CPU renderer with no user, waits for the window, and writes a PNG of it to a path it
# prints. It stops kuserd, kuid and the framebuffer on the way out, including when it
# fails — so `just kill` afterwards is belt and braces, not a step.
#
#   just desktop::shot                       → .kotton.shot/desktop.png
#   just desktop::shot /tmp/window.png       → somewhere else
#
# With no user named, the window onboards, so the picture is the welcome
# screen. It is a picture, not a session: there is no window manager on the framebuffer,
# so nothing has keyboard focus and nothing can be typed into.
#
# `cargo xtask doctor --tier desktop` has a row for each of the two packages this needs
# (`xvfb`, `scrot`), and reports them met on a machine that already has a display.
#
# **`cpu` is passed here on purpose, and is the only recipe that passes it.** Every other
# recipe defaults to the GPU renderer; this one is that rule's
# documented contributor opt-in, and the machines it is for — a container, a build machine, an
# agent's checkout — have no adapter, so a `gpu` build would refuse to open the window
# there is no point photographing. Do not "fix" this line by removing the argument.
[linux]
shot out="" render="cpu": (build render)
    cargo xtask "run::shot" "{{out}}"

# Boot a machine that nobody has ever logged into, and watch it draw.
#
# A bare `just desktop::run` also onboards in the window, on *this* machine's data.
# This one wipes `.kotton.firstrun/` first, which is the whole difference: a fresh
# machine rather than this machine with nobody logged in. Ctrl-C to stop.
# Re-running wipes again, so first run stays first. Lives in xtask so it runs
# the same on every platform; see `docs/use/your-own-pc.md`.
first-run render="gpu": (build render)
    cargo xtask "run::first-run"

# Start this device fresh: `kotton device reset`, through cargo, for when the
# binary is not on your path. Says what it would delete and refuses without
# `--yes`: `just desktop::reset --yes`.
#
# Stops every Kotton process first. The verb refuses under a live daemon, and a
# daemon is usually live here: on Unix, Ctrl-C on `run` ends xtask before it can
# stop the kuserd it started, so the first reset after a run met exactly that
# refusal (2026-09-17). A reset is the one command where stopping everything
# first is always what the person means.
reset *args:
    just kill
    cargo run --bin kotton -- device reset {{args}}

# The composite-cost benchmark, on the renderer this machine actually has.
#
# The compositor's published frame costs carry the CPU column and **owe the GPU one**: the
# container that measured it has no adapter, so a `kuid-gpu` run there would measure
# lavapipe rasterising on the CPU through a graphics API. This recipe is that run, for
# whoever has a GPU. It prints which renderer it measured in its first line.
#
#   just desktop::bench-composite        the shipped renderer (GPU)
#   just desktop::bench-composite cpu    the CPU seam, to reproduce the published column
#
# Release, because the published numbers are release and a debug rasteriser is a
# different order of magnitude. The three lines it prints are the numbers;
# a pull request that changes the compositor's cost says them in its description.
bench-composite render="gpu":
    cargo test --release -p kuid --features {{ if render == "cpu" { "kuid/kuid-desktop" } else { "kuid/kuid-desktop,kuid/kuid-gpu" } }} composite_cost -- --ignored --nocapture
