// SPDX-License-Identifier: AGPL-3.0-or-later
//! `doctor`: what this checkout needs, checked, in one place.
//!
//! ## Why
//!
//! `CONTRIBUTING.md` says `just lint` and `just test` must both pass, and that running them
//! *"is not optional."* Measured against a fresh container on 2026-08-25, neither can run:
//! `just` is not installed and nothing says to install it, `just test` fails on three system
//! libraries, `wasm32-wasip2` is absent, and a missing `rg` makes `measure-check` pass while
//! verifying nothing.
//!
//! Those facts were written down — in `ADVISORY.md`, whose own rule is that entries are
//! **deleted when they stop being true**. A permanent prerequisite kept in a file designed to
//! forget is a prerequisite on its way to being lost, and until then it is prose that nothing
//! reads. **A prerequisite nobody checks fails at the worst possible moment: in someone
//! else's first hour.**
//!
//! ## Tiers, because not everyone needs everything
//!
//! Blocking a documentation fix on the GTK stack is how a contributor decides the project is
//! not worth the afternoon. So each requirement names the *smallest* thing it gates:
//!
//! | tier | what it unblocks |
//! |---|---|
//! | [`Tier::Lint`] | `just lint` — the gate every branch must pass |
//! | [`Tier::Test`] | `just test` — the suite |
//! | [`Tier::Build`] | `cargo xtask release` — the desktop's archive |
//! | [`Tier::Desktop`] | `just desktop::run` — the window |
//! | [`Tier::Server`] | `cargo xtask release-server` — a host's two archives |
//!
//! The first four are a ladder: `doctor` always *reports* all four and only *fails* on the
//! one asked for, so you can see the whole picture without being blocked by the part you do
//! not need yet. The build rung is what separates *building* the window from *running* it:
//! the GTK stack is linked by a build and asked of no display, so `desktop` lists it and a
//! runner with no window manager, no GPU and no framebuffer can still be held to it.
//!
//! **`build` and `server` are each also asked for alone**, and reported with nothing else
//! when they are. Building the desktop's archive needs `clang`, `pkg-config`, OpenSSL and the
//! `wasm32-wasip2` target, which sit on the lint and test rungs, and needs none of `just`,
//! `rg`, `git` or the settings parser that those rungs also ask for; so a row names the other
//! tiers that read it (`Need::also`) and the lone report draws on them, rather than
//! restating the rows or asking a release runner for tools it never runs. The release
//! workflow installs what `doctor --tier build` names and then runs it.
//!
//! **`server` is beside the ladder, not on it**, and is reported only when it is asked for.
//! Building a host's release needs none of the desktop's GTK and none of the suite's wasm
//! target, and a contributor fixing a doc needs no musl toolchain — printing each tier's
//! paste block to the other is how a report stops being believed. The rows are what
//! `xtask/src/release_server.rs` builds with, and the words each fix uses are the words
//! `docs/use/build-a-release.md` uses (`the_server_fixes_are_the_guides_words`): the owner
//! once met a missing musl target that the old single runbook named in its step 5 and
//! not in the block at its top, and prose only some readers reach is not a
//! prerequisite list — the guide opens with it now. The build tier's rows are held to that
//! same guide, and to `docs/use/linux.md` as well, since the window's contributor installs
//! them from there.
//!
//! ## The rule this exists to hold
//!
//! **A check that cannot determine an answer must fail, not pass.** `measure-check` printed
//! *"`rg` could not search for `UserRequest`; treating as resolved"* — 250 times, exiting
//! zero, verifying nothing. Its reasoning was sound at the symbol level (*"reporting a stale
//! link because a tool is unavailable teaches the reader to ignore this check"*), and the
//! resolution is not to invert it there but to refuse **once, at the top**: a gate may assume
//! its tools exist exactly because `doctor` ran first.

use std::process::Command;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tier {
    Lint,
    Test,
    Build,
    Desktop,
    Server,
}

impl Tier {
    fn label(self) -> &'static str {
        match self {
            Tier::Lint => "lint",
            Tier::Test => "test",
            Tier::Build => "build",
            Tier::Desktop => "desktop",
            Tier::Server => "server",
        }
    }
    fn parse(s: &str) -> Option<Tier> {
        match s {
            "lint" => Some(Tier::Lint),
            "test" => Some(Tier::Test),
            "build" => Some(Tier::Build),
            "desktop" => Some(Tier::Desktop),
            "server" => Some(Tier::Server),
            _ => None,
        }
    }
    /// The tiers a report for this one shows: the ladder for a rung of it, and the server
    /// and build tiers alone for themselves (see the module's note on why neither report
    /// carries the rest of the ladder).
    fn shown(self) -> &'static [Tier] {
        match self {
            Tier::Server => &[Tier::Server],
            Tier::Build => &[Tier::Build],
            _ => &[Tier::Lint, Tier::Test, Tier::Build, Tier::Desktop],
        }
    }
    /// Whether a report for `self` lists `need`, drawn under `tier` — the tier the report
    /// is showing. A row is listed under its own tier, and under each tier it names in
    /// `also` when that tier is the one asked for alone (`Build`): the part of the lint and
    /// test rungs the archive's build reads, without `just`, `rg` or `git`.
    fn lists(self, need: &Need, tier: Tier) -> bool {
        need.tier == tier || (self.shown() == [tier] && need.also.contains(&tier))
    }
}

/// How to find out whether a requirement is met.
enum Probe {
    /// A binary that answers `--version` on `PATH`.
    Bin(&'static str),
    /// A binary that exists on `PATH`, found without running it — for a tool that
    /// opens the display before it answers anything, so `--version` on a shell with
    /// no display reports "not installed" for a tool that is (`xprop`, 2026-09-17).
    OnPath(&'static str),
    /// A rustup target, from `rustup target list --installed`.
    Target(&'static str),
    /// A C library, from `pkg-config --exists`.
    PkgConfig(&'static str),
    /// A shared library with no pkg-config file, from `ldconfig -p`.
    ///
    /// `libxdo` is the reason this exists. It ships **no `.pc` file**, so
    /// `pkg-config --exists libxdo` fails whether or not the library is installed — this
    /// reported it missing on a machine where `dpkg` said `ii` and `kuid` had just linked
    /// against it. A probe that cannot succeed is worse than no probe: it sends someone to
    /// install a thing they already have.
    ///
    /// It answers whether a library can be *loaded*, since `ldconfig` lists the versioned
    /// name. That is the right question for a run-time library; for one the build links,
    /// ask the linker with [`Probe::Links`] — `libxdo` moved there (#135).
    Lib(&'static str),
    /// A C library the **linker** can find as `-l<name>`, asked of the linker itself:
    /// `cc` links an empty `main` against it.
    ///
    /// This is the build's own question. `cargo` ends in `cc … -lxdo`, which resolves the
    /// unversioned `libxdo.so` that only the `-dev` package installs; the run-time package
    /// installs `libxdo.so.3` and nothing the linker will take. [`Probe::Lib`] reads
    /// `ldconfig -p`, which lists the versioned name and so answers "can it be loaded", a
    /// different question: it passed on a machine that had the run-time library and no
    /// headers, and the build then failed on `-lxdo` (#135). Asking `cc` also honours
    /// whatever `LIBRARY_PATH` and multiarch directories this machine's compiler searches,
    /// which a list of paths here would only approximate. It is for a library with no
    /// `.pc` file ([`Probe::PkgConfig`] is the better question where there is one) that
    /// the build links; a library only loaded at run time keeps [`Probe::Lib`].
    Links(&'static str),
    /// A binary that is only needed where there is **no** display server, found on
    /// `PATH` — met, not missing, on a machine that has one.
    ///
    /// The virtual framebuffer and the screenshot tool are `just desktop::shot`'s, and
    /// that recipe is `DEC-0076`'s documented opt-in for a contributor whose machine
    /// cannot open a window at all. Asked flatly, they would report MISSING on every
    /// ordinary Linux desktop and send a person to install two packages their window
    /// does not use — which is the failure the `only:` field exists to prevent, one
    /// axis over: not "wrong platform" but "wrong machine on the right platform". The
    /// point of this file is to be believed.
    ///
    /// A display is the whole condition: with `DISPLAY` or `WAYLAND_DISPLAY` set there
    /// is already a server to draw into, so there is nothing to stand up. This is the
    /// same idiom [`Probe::WindowManager`] uses to skip where it cannot apply.
    WhenNoDisplay(&'static str),
    /// A window manager owns `$DISPLAY`.
    ///
    /// Not an installed thing — a *running* one, and the only requirement here
    /// that is. It earns its place because of how it fails: X11 with no window
    /// manager assigns keyboard focus to nobody, so kuid's window receives no key
    /// events at all. The pointer still works, every menu and dock item still
    /// responds to a click, and a screenshot looks perfect. You simply cannot
    /// type, and nothing anywhere says why.
    ///
    /// winit cannot paper over it: its `focus_window` sends `_NET_ACTIVE_WINDOW`
    /// to the root window, which is a request *to a window manager*. With none
    /// running there is nobody to answer, so a client cannot focus itself.
    /// Measured 2026-08-26, after an afternoon spent looking for the bug in the
    /// input path.
    ///
    /// Skipped where it cannot apply: no `$DISPLAY` means no X session to check,
    /// and macOS and Windows do not use one.
    WindowManager,
    /// A **hardware** Vulkan device, from `vulkaninfo --summary`.
    ///
    /// `DEC-0076`: the window renders on the GPU, and a machine that offers no hardware
    /// adapter gets no window at all — a checkout runs `just headless::run`, and an
    /// installed archive runs `kotton --help` at a terminal against the daemon already
    /// running, which is what kuid's own refusal says. That is the one
    /// requirement on this list whose absence is not a missing package, and it earns its
    /// row the way the window-manager row does: by how it fails without one. A machine
    /// that has a GPU, cannot reach it, and says so nowhere cost three separate stretches
    /// of confusion in one day on the owner's WSL2 machine — the slow window, then a panic,
    /// then an afternoon of backend archaeology — and every one of them would have been a
    /// line in this report
    /// (`TASK-the-shipped-window-renders-on-the-gpu-or-does-not-open`).
    ///
    /// **It reports `unknown` rather than `missing` when `vulkaninfo` is absent**, on the
    /// same rule as [`Probe::WindowManager`]: the tool is how the question is asked, not
    /// the thing being asked about, so its absence means *nobody asked*.
    ///
    /// Linux only, and the two platforms it skips are skipped for different reasons.
    /// macOS renders through Metal, which every Mac wgpu supports has, so there is
    /// nothing to ask. Windows renders through DX12, which `vulkaninfo` does not answer
    /// for and which this checkout ships no tool to ask about at all — a row that always
    /// said `unknown` there would make `doctor --tier desktop` exit non-zero on every
    /// Windows machine, which is the "cannot tell reads as fine" failure inverted into a
    /// report nobody believes. A Windows machine with no usable adapter learns it from
    /// kuid's own refusal at startup, which says `Run \`kotton --help\` at a terminal`.
    HardwareGpu,
    /// This machine is running the named `target_os`. For the one requirement that is not
    /// a package: the server release is built on Linux, and nobody has built it anywhere
    /// else.
    Os(&'static str),
    /// `libsystemd-shared-*.so`, systemd's own settings parser, in the directories the
    /// settings differential looks in — found by that test's own finder
    /// (`release_server::systemds_parser`), so this row and the test cannot disagree about
    /// one machine. No `.pc` file and, on Debian, no `ldconfig` entry: it lives under
    /// `…/systemd/`, outside the loader's path.
    SystemdsLibrary,
}

/// Whether `vulkaninfo --summary`'s output names a device that is not a software one.
///
/// `None` where the question was not answered at all: no `deviceType` line means
/// `vulkaninfo` printed something this does not understand, and guessing from that is
/// how a probe comes to report `missing` on a machine that is fine.
///
/// A free function so the parse is tested against real output rather than against a
/// machine — including the output that made this row worth having, which came off a machine
/// with an RTX 4070 Ti in it:
///
/// ```text
/// GPU0: deviceType = PHYSICAL_DEVICE_TYPE_CPU   deviceName = llvmpipe
/// ```
fn vulkan_has_hardware(summary: &str) -> Option<bool> {
    let mut saw_a_device = false;
    let mut hardware = false;
    for line in summary.lines() {
        let Some((_, kind)) = line.split_once("deviceType") else {
            continue;
        };
        // `deviceName` also contains the string on one-line summaries, so take the value
        // after the `=` rather than the rest of the line.
        let Some((_, kind)) = kind.split_once('=') else {
            continue;
        };
        saw_a_device = true;
        // Everything but `PHYSICAL_DEVICE_TYPE_CPU` is hardware, for the reason
        // `gpu_verdict` in kuid accepts everything but `DeviceType::Cpu`: a software
        // rasteriser says so about itself, and a rule that refuses what it cannot name
        // turns away the device that has not shipped yet.
        if !kind.trim_start().starts_with("PHYSICAL_DEVICE_TYPE_CPU") {
            hardware = true;
        }
    }
    saw_a_device.then_some(hardware)
}

/// How a requirement is installed — by installer, not by command line — so the report
/// can merge everything one installer owes into a single line a person pastes once.
/// Ten `fix:` lines under ten rows was the report the owner called a mess; one
/// `apt-get` naming four packages is what they asked for instead (2026-09-17).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Fix {
    /// `cargo install <crate>`
    Cargo(&'static str),
    /// `rustup target add <target>`
    Rustup(&'static str),
    /// `apt-get install -y <package …>`
    Apt(&'static str),
    /// `brew install <formula>`
    Brew(&'static str),
    /// `scoop install <app>`
    Scoop(&'static str),
    /// `winget install <id>`
    Winget(&'static str),
    /// `xcode-select --install`
    Xcode,
    /// A command line printed as it is, on a line of its own — for the thing that
    /// has to be *run* after it is installed.
    Shell(&'static str),
}

pub(crate) struct Need {
    pub(crate) what: &'static str,
    probe: Probe,
    pub(crate) tier: Tier,
    /// The `target_os` values this applies to. Empty means every platform.
    ///
    /// Without it every requirement was checked everywhere, and the whole desktop
    /// tier is Linux-specific: `pkg-config --exists gtk+-3.0` fails on a Mac that
    /// renders through Cocoa, `ldconfig` does not exist there at all so
    /// `Probe::Lib` answers unknown about a library that was never needed, and an
    /// `apt-get` line is not advice on any of it. Telling a macOS contributor to
    /// install four things their build does not use is worse than saying nothing,
    /// because the point of this file is to be believed.
    pub(crate) only: &'static [&'static str],
    /// Other tiers that ask for this same row, for a report on one of them **alone**
    /// (`doctor --tier build`). The row stays in its own tier, so the ladder lists it once;
    /// a tier that is shown by itself cannot reach the rungs below it without also asking for
    /// `just` and `rg`, so it names the rows it reads instead of restating them.
    pub(crate) also: &'static [Tier],
    /// What breaks without it — stated as the failure, not as the requirement, because the
    /// failure is what a reader will have already seen when they come here. One sentence:
    /// it is printed under the requirement's name and wrapped to the terminal, and a
    /// paragraph there is what made the report unreadable (2026-09-17).
    breaks: &'static str,
    /// How it is installed, by `target_os`. `""` applies to every platform not
    /// named; a platform may appear more than once when the fix is two steps. Only
    /// the current platform's entries are ever used: an `apt-get` beside a `cargo
    /// install` on Windows was noise that read as a choice.
    pub(crate) fix: &'static [(&'static str, Fix)],
}

/// Everything this checkout needs, and the smallest thing each one gates.
pub(crate) const NEEDS: &[Need] = &[
    Need {
        what: "just",
        probe: Probe::Bin("just"),
        tier: Tier::Lint,
        only: &[],
        also: &[],
        breaks: "`just lint` and `just test` cannot be invoked at all",
        // The platform's own package manager where its page sets the machine up with one:
        // `docs/use/macos.md` brews `just` and `docs/use/windows.md` scoops it, and a
        // `cargo install` there is a second route to a tool the page already installed.
        fix: &[
            ("macos", Fix::Brew("just")),
            ("windows", Fix::Scoop("just")),
            ("", Fix::Cargo("just")),
        ],
    },
    Need {
        what: "rg (ripgrep)",
        probe: Probe::Bin("rg"),
        tier: Tier::Lint,
        only: &[],
        also: &[],
        breaks: "windows-check cannot search the tree",
        fix: &[
            ("macos", Fix::Brew("ripgrep")),
            ("windows", Fix::Scoop("ripgrep")),
            ("", Fix::Cargo("ripgrep")),
        ],
    },
    // The four below are what `cargo clippy --all-targets` on the workspace links on Linux
    // with no window feature on: `tools/css-support` is a member with no feature gate, and
    // its CSS engine reaches fontconfig; the encrypted database's bundled SQLCipher links
    // the system OpenSSL (`OPENSSL_NO_VENDOR`, `.cargo/config.toml`); both are found by
    // pkg-config and built by a C compiler. The lint workflow installs what this tier
    // names and nothing else, so a library the gate links that is not here fails every
    // pull request on a bare runner before any check runs.
    Need {
        what: "pkg-config",
        probe: Probe::Bin("pkg-config"),
        tier: Tier::Lint,
        only: &["linux"],
        also: &[Tier::Build],
        breaks: "no sys crate's build script finds its library",
        fix: &[("linux", Fix::Apt("pkg-config"))],
    },
    Need {
        what: "cc (a C compiler)",
        probe: Probe::Bin("cc"),
        tier: Tier::Lint,
        only: &["linux"],
        also: &[Tier::Build],
        breaks: "every crate that compiles C fails; clippy stops",
        fix: &[("linux", Fix::Apt("build-essential"))],
    },
    Need {
        what: "fontconfig",
        probe: Probe::PkgConfig("fontconfig"),
        tier: Tier::Lint,
        only: &["linux"],
        also: &[Tier::Build],
        breaks: "fontconfig-sys's build script fails; clippy stops at it",
        fix: &[("linux", Fix::Apt("libfontconfig-dev"))],
    },
    Need {
        what: "openssl",
        probe: Probe::PkgConfig("openssl"),
        tier: Tier::Lint,
        only: &["linux"],
        also: &[Tier::Build],
        breaks: "the encrypted database cannot link OpenSSL",
        fix: &[("linux", Fix::Apt("libssl-dev"))],
    },
    Need {
        what: "git",
        probe: Probe::Bin("git"),
        tier: Tier::Lint,
        only: &[],
        also: &[],
        breaks: "signoff-check, merge, and every check's repo root",
        fix: &[
            ("linux", Fix::Apt("git")),
            ("macos", Fix::Xcode),
            ("windows", Fix::Winget("Git.Git")),
        ],
    },
    Need {
        what: "wasm32-wasip2 target",
        probe: Probe::Target("wasm32-wasip2"),
        tier: Tier::Test,
        only: &[],
        also: &[Tier::Build],
        breaks: "nothing under guest/ compiles",
        fix: &[("", Fix::Rustup("wasm32-wasip2"))],
    },
    Need {
        // The **wasm** half, not the native one: `ring`'s build script uses cc-rs, which
        // reaches for clang on wasm targets because neither gcc nor MSVC can emit wasm at
        // all. Learned 2026-09-11 in `infra/Dockerfile`, whose comment says *every machine
        // that had built this before happened to have clang already* — and then written
        // only there, so the same error was met on Windows on 2026-09-17, six days later.
        // A row here is the lesson reaching the tool that could have said it.
        what: "clang",
        probe: Probe::Bin("clang"),
        tier: Tier::Test,
        only: &[],
        also: &[Tier::Build],
        breaks: "ring's build script fails, so nothing under guest/ builds",
        fix: &[
            ("linux", Fix::Apt("clang")),
            ("macos", Fix::Xcode),
            // `scoop`, not `winget`, because `docs/use/windows.md` sets up this machine
            // with scoop and names `llvm` in the same line as openssl, python, just and
            // ripgrep. The first version of this row said `winget install LLVM.LLVM` — in
            // the same commit that added `llvm` to that scoop line. One dependency, one
            // commit, two package managers.
            ("windows", Fix::Scoop("llvm")),
        ],
    },
    Need {
        what: "python3",
        probe: Probe::Bin("python3"),
        // Lint, not Test: the workspace clippy runs stylo's build script through
        // `tools/css-support`, so the gate needs it before any test does.
        tier: Tier::Lint,
        only: &[],
        also: &[Tier::Build],
        breaks: "the stylo CSS build script fails; clippy stops at it",
        fix: &[
            ("linux", Fix::Apt("python3")),
            // The command line tools bring `python3`, and `docs/use/macos.md` installs them
            // first for the C toolchain. This said `brew install python` until 2026-09-29,
            // which the page never says.
            ("macos", Fix::Xcode),
            ("windows", Fix::Scoop("python")),
        ],
    },
    Need {
        // `just test` on Linux: the settings differential (`infra/relay` and `kvaultd`'s
        // tests, both Linux-only) fails without systemd's own parser unless the machine declares
        // `KOTTON_NO_SYSTEMD_PARSER`. The server tier asks for the same library for the
        // release gate. `python3`, the other half, is the row above
        // (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`).
        what: "libsystemd-shared (the settings differential's parser)",
        probe: Probe::SystemdsLibrary,
        tier: Tier::Test,
        only: &["linux"],
        also: &[],
        breaks: "the settings differential fails, naming the missing library",
        fix: &[("linux", Fix::Apt("libsystemd-shared"))],
    },
    // The build tier: the system libraries `cargo xtask release` links beyond the lint and test
    // rungs (the rows above with `also: &[Tier::Build]` are the rest of what it reads). Nothing
    // here is about running the window; that is the desktop tier, which lists these too, since
    // a window has to be built before it opens.
    Need {
        what: "gtk+-3.0",
        probe: Probe::PkgConfig("gtk+-3.0"),
        tier: Tier::Build,
        only: &["linux"],
        also: &[],
        breaks: "the desktop archive does not build: kuid needs gtk",
        fix: &[("linux", Fix::Apt("libgtk-3-dev"))],
    },
    Need {
        what: "pango",
        probe: Probe::PkgConfig("pango"),
        tier: Tier::Build,
        only: &["linux"],
        also: &[],
        breaks: "pango-sys's build script fails, before the gtk error",
        fix: &[("linux", Fix::Apt("libpango1.0-dev"))],
    },
    Need {
        what: "libxdo",
        probe: Probe::Links("xdo"),
        tier: Tier::Build,
        only: &["linux"],
        also: &[],
        breaks: "kuid fails to link on -lxdo, after pango",
        fix: &[("linux", Fix::Apt("libxdo-dev"))],
    },
    Need {
        what: "libxkbcommon-x11",
        probe: Probe::Lib("libxkbcommon-x11"),
        tier: Tier::Desktop,
        only: &["linux"],
        also: &[],
        breaks: "kuid panics at startup and kuserd restarts it in a loop",
        fix: &[("linux", Fix::Apt("libxkbcommon-x11-0"))],
    },
    Need {
        // The tool the next row asks the display with. Its own row because without
        // it the next row cannot answer, and "cannot answer" used to print as
        // "missing" with a window manager as the cure — on WSL2, which has one.
        what: "xprop (x11-utils)",
        probe: Probe::OnPath("xprop"),
        tier: Tier::Desktop,
        only: &["linux"],
        also: &[],
        breaks: "doctor cannot tell whether a window manager is running",
        fix: &[("linux", Fix::Apt("x11-utils"))],
    },
    Need {
        what: "a window manager",
        probe: Probe::WindowManager,
        tier: Tier::Desktop,
        only: &["linux"],
        also: &[],
        breaks: "the window opens but cannot be typed into (no key focus)",
        // Install, then run it. Any window manager will do; this is the smallest.
        fix: &[
            ("linux", Fix::Apt("matchbox-window-manager")),
            (
                "linux",
                Fix::Shell("matchbox-window-manager -use_titlebar no &"),
            ),
        ],
    },
    Need {
        // Loaded at run time by `tray-icon`, not linked, so the build cannot miss it.
        // kuid catches the panic and runs without a tray, but the panic's text is the
        // first thing in the log of a first run, and it reads as a crash.
        what: "libayatana-appindicator3",
        probe: Probe::Lib("libayatana-appindicator3"),
        tier: Tier::Desktop,
        only: &["linux"],
        also: &[],
        breaks: "no system tray, and a panic in kuid's log at every start",
        fix: &[("linux", Fix::Apt("libayatana-appindicator3-1"))],
    },
    Need {
        // The tool, on its own row, exactly as `xprop` sits above the window-manager row
        // it asks for: the package that answers the question is installable and the thing
        // it asks about is not, so they are two requirements and only one of them has a
        // cure a package manager can apply.
        what: "vulkaninfo (vulkan-tools)",
        probe: Probe::OnPath("vulkaninfo"),
        tier: Tier::Desktop,
        only: &["linux"],
        also: &[],
        breaks: "doctor cannot tell whether this machine has a GPU to render on",
        fix: &[("linux", Fix::Apt("vulkan-tools"))],
    },
    Need {
        what: "a GPU the window can render on",
        probe: Probe::HardwareGpu,
        tier: Tier::Desktop,
        only: &["linux"],
        also: &[],
        breaks: "no window opens at all; the window renders only on a GPU",
        // Empty on purpose. No package installs a GPU, and the cure for one that is
        // present but unreachable is a driver — the owner's WSL2 machine wanted a Windows
        // driver reinstall, which is not a line this file can print for a machine it has
        // never seen. Naming `vulkan-tools` here would be worse than nothing: this row
        // only reports `missing` when `vulkaninfo` already ran, so the paste block would
        // tell a person to install the tool that just answered them.
        fix: &[],
    },
    // The last two rows are `just desktop::shot`'s, and they are the only rows here that
    // a machine with a display does not need — see `Probe::WhenNoDisplay`. A contributor
    // whose container has no X or Wayland server has no window at all, and `DEC-0076`
    // anticipated exactly that: "the answer may be a documented opt-in rather than an
    // amendment." These name the packages that opt-in needs.
    Need {
        what: "Xvfb — a virtual framebuffer",
        probe: Probe::WhenNoDisplay("Xvfb"),
        tier: Tier::Desktop,
        only: &["linux"],
        also: &[],
        breaks: "`just desktop::shot` has no display to open a window on",
        fix: &[("linux", Fix::Apt("xvfb"))],
    },
    Need {
        what: "scrot — a picture of the window",
        probe: Probe::WhenNoDisplay("scrot"),
        tier: Tier::Desktop,
        only: &["linux"],
        also: &[],
        breaks: "`just desktop::shot` draws the window and cannot save it",
        fix: &[("linux", Fix::Apt("scrot"))],
    },
    // The server tier: what `cargo xtask release-server relay|vault` builds with
    // (`release_server.rs`, measured 2026-09-26 on Ubuntu 24.04). Both servers are built for
    // `x86_64-unknown-linux-musl` and static. `git`, `tar` and `sha256sum` are used too, and
    // have no row: a clean checkout of `main` already has all three.
    Need {
        what: "Linux (or WSL2) to build on",
        probe: Probe::Os("linux"),
        tier: Tier::Server,
        only: &[],
        also: &[],
        breaks: "no one has built the release off Linux; it wants a cross-linker",
        // No package makes a Mac Linux. `docs/use/build-a-release.md` says what is
        // unmeasured, and this row is only a refusal to say `ok` about it.
        fix: &[],
    },
    Need {
        what: "x86_64-unknown-linux-musl target",
        probe: Probe::Target("x86_64-unknown-linux-musl"),
        tier: Tier::Server,
        only: &["linux"],
        also: &[],
        breaks: "cargo cannot build either server for the target a host runs",
        fix: &[("linux", Fix::Rustup("x86_64-unknown-linux-musl"))],
    },
    Need {
        what: "musl-gcc (musl-tools)",
        probe: Probe::OnPath("musl-gcc"),
        tier: Tier::Server,
        only: &["linux"],
        also: &[],
        breaks: "ring, aws-lc-sys and the vault's OpenSSL have no C compiler",
        fix: &[("linux", Fix::Apt("musl-tools"))],
    },
    Need {
        // The host half: every build script is compiled for this machine, not for musl.
        what: "cc (build-essential)",
        probe: Probe::Bin("cc"),
        tier: Tier::Server,
        only: &["linux"],
        also: &[],
        breaks: "no build script compiles; the build stops before either server",
        fix: &[("linux", Fix::Apt("build-essential"))],
    },
    Need {
        what: "make (build-essential)",
        probe: Probe::Bin("make"),
        tier: Tier::Server,
        only: &["linux"],
        also: &[],
        breaks: "the vault's OpenSSL, built from source on musl, does not build",
        fix: &[("linux", Fix::Apt("build-essential"))],
    },
    Need {
        what: "perl",
        probe: Probe::Bin("perl"),
        tier: Tier::Server,
        only: &["linux"],
        also: &[],
        breaks: "OpenSSL's Configure is perl; the vault does not build",
        fix: &[("linux", Fix::Apt("perl"))],
    },
    // The release gate's own: `release-server` runs the settings differential against
    // systemd's parser and refuses a machine where it cannot reach it, so no archive is cut on
    // the form of that test that compared nothing
    // (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`).
    Need {
        what: "libsystemd-shared (systemd's own settings parser)",
        probe: Probe::SystemdsLibrary,
        tier: Tier::Server,
        only: &["linux"],
        also: &[],
        breaks: "release-server refuses; the differential has no parser",
        fix: &[("linux", Fix::Apt("libsystemd-shared"))],
    },
    Need {
        what: "python3 (the settings differential calls the parser with it)",
        probe: Probe::Bin("python3"),
        tier: Tier::Server,
        only: &["linux"],
        also: &[],
        breaks: "release-server refuses; the differential cannot call the parser",
        fix: &[("linux", Fix::Apt("python3"))],
    },
];

/// What a probe found.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Verdict {
    Met,
    Missing,
    /// The probe could not ask, and says what stopped it. Counts as not ready — this
    /// file exists to stop "cannot tell" from reading as "fine" — but prescribes
    /// nothing, because the cure for "cannot tell" is whatever stopped the asking,
    /// and that is named here rather than guessed at.
    Unknown(String),
}

/// Whether a requirement is met. A probe whose tool is absent answers `Missing`
/// where the tool *is* the requirement, and `Unknown` where the tool is only how
/// the requirement is asked about.
fn check(probe: &Probe) -> Verdict {
    fn verdict(met: bool) -> Verdict {
        if met {
            Verdict::Met
        } else {
            Verdict::Missing
        }
    }
    match probe {
        Probe::Bin(b) => verdict(
            Command::new(b)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success()),
        ),
        Probe::OnPath(b) => verdict(on_path(b)),
        Probe::WhenNoDisplay(b) => {
            if std::env::var_os("DISPLAY").is_some()
                || std::env::var_os("WAYLAND_DISPLAY").is_some()
            {
                return Verdict::Met;
            }
            verdict(on_path(b))
        }
        Probe::Target(t) => verdict(
            Command::new("rustup")
                .args(["target", "list", "--installed"])
                .output()
                .is_ok_and(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .any(|l| l.trim() == *t)
                }),
        ),
        Probe::PkgConfig(lib) => match pkg_config_exists("pkg-config", lib) {
            Some(exists) => verdict(exists),
            None => Verdict::Unknown(
                "pkg-config could not be run, so the library cannot be asked about".into(),
            ),
        },
        Probe::Lib(lib) => match ldconfig_lists(LDCONFIG, lib) {
            Some(listed) => verdict(listed),
            None => Verdict::Unknown(
                "ldconfig could not be run, so the library cannot be asked about".into(),
            ),
        },
        Probe::Links(lib) => match links_against("cc", lib) {
            Some(linked) => verdict(linked),
            None => Verdict::Unknown("cc could not be run, so the linker cannot be asked".into()),
        },
        Probe::WindowManager => {
            if !cfg!(target_os = "linux") || std::env::var_os("DISPLAY").is_none() {
                return Verdict::Met;
            }
            if !on_path("xprop") {
                return Verdict::Unknown(
                    "xprop is not installed, so the display cannot be asked".into(),
                );
            }
            // EWMH's own two-step, and it is not pedantry: a window manager that
            // dies without cleaning up leaves `_NET_SUPPORTING_WM_CHECK` on the
            // root window pointing at a window that no longer exists. Checking
            // only the root property reports a live WM on a display that has none
            // — measured, on the display this check was written against.
            //
            // So follow the pointer: the named window must still exist and still
            // carry the property. If the WM is gone, `xprop -id` fails with
            // BadWindow and prints nothing that matches.
            let root = Command::new("xprop")
                .args(["-root", "-notype", "_NET_SUPPORTING_WM_CHECK"])
                .output();
            let Ok(root) = root else {
                return Verdict::Unknown("xprop could not be run".into());
            };
            if !root.status.success() {
                // `unable to open display` — the display is named and not reachable
                // from this shell. Not "no window manager": nothing was asked.
                let display = std::env::var("DISPLAY").unwrap_or_default();
                return Verdict::Unknown(format!(
                    "DISPLAY={display} is set but cannot be opened from this shell"
                ));
            }
            let text = String::from_utf8_lossy(&root.stdout);
            let Some(id) = text.split("# ").nth(1).map(|s| s.trim().to_owned()) else {
                return Verdict::Missing;
            };
            verdict(
                Command::new("xprop")
                    .args(["-id", &id, "_NET_SUPPORTING_WM_CHECK"])
                    .output()
                    .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("window id #")),
            )
        }
        Probe::HardwareGpu => {
            if !on_path("vulkaninfo") {
                return Verdict::Unknown(
                    "vulkaninfo is not installed, so this machine cannot be asked whether it \
                     has a GPU"
                        .into(),
                );
            }
            let Ok(out) = Command::new("vulkaninfo").arg("--summary").output() else {
                return Verdict::Unknown("vulkaninfo could not be run".into());
            };
            // vulkaninfo writes its loader warnings to stderr and its summary to stdout,
            // and exits non-zero on some of those warnings while still printing a usable
            // summary — the owner's WSL2 machine does exactly that, skipping one ICD and
            // listing llvmpipe. So the status is not consulted; the output is.
            let text = String::from_utf8_lossy(&out.stdout);
            match vulkan_has_hardware(&text) {
                Some(hardware) => verdict(hardware),
                None => Verdict::Unknown(
                    "vulkaninfo ran and named no device, so nothing was established".into(),
                ),
            }
        }
        Probe::Os(os) => verdict(std::env::consts::OS == *os),
        Probe::SystemdsLibrary => {
            use crate::release_server::systemds_parser::{library_in, LIBRARY_DIRS};
            let dirs: Vec<&std::path::Path> = LIBRARY_DIRS.iter().map(std::path::Path::new).collect();
            verdict(library_in(&dirs).is_some())
        }
    }
}

/// Whether `pkg_config` knows a package named `lib`.
///
/// `None` where the question was not asked: the tool could not be run. `pkg-config` is how
/// the library is asked about, not the thing being asked about (it has its own row), so
/// its absence means *nobody asked*, and answering "missing" would send someone to install
/// a library they may already have — the rule [`check`] states. The tool's name is a
/// parameter so that is tested directly.
fn pkg_config_exists(pkg_config: &str, lib: &str) -> Option<bool> {
    Command::new(pkg_config)
        .args(["--exists", lib])
        .status()
        .ok()
        .map(|status| status.success())
}

/// Where `ldconfig` is looked for, in order: the bare name, then `/sbin/ldconfig`, which is
/// where Debian keeps it and which a non-root user's `PATH` often leaves out.
const LDCONFIG: &[&str] = &["ldconfig", "/sbin/ldconfig"];

/// Whether the first of `ldconfig_tools` that can be run, as `-p`, lists a shared library
/// named `lib`.
///
/// A tool that cannot be *spawned* hands the question to the next; one that runs and fails
/// is the answer, and the next is not asked. `None` where none could be run, or the one that
/// ran failed (a container with no `ld.so.cache` prints nothing and exits non-zero), for the
/// reason [`pkg_config_exists`] gives: it is how the library is asked about, and where it
/// does not exist (macOS, Windows, a container without it) or cannot answer, nobody asked.
fn ldconfig_lists(ldconfig_tools: &[&str], lib: &str) -> Option<bool> {
    let out = ldconfig_tools
        .iter()
        .find_map(|tool| Command::new(tool).arg("-p").output().ok())?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).contains(&format!("{lib}.")))
}

/// Whether `compiler` links an empty program against `-l<lib>` — what the build does, so
/// it cannot disagree with the build about one machine.
///
/// `None` where the question was not asked: the compiler could not be run, or the
/// directory its output goes in could not be made. `cc` is how the library is asked about,
/// not the thing being asked about (it has its own row), so its absence means *nobody
/// asked*, and answering "missing" would send someone to install a library they may
/// already have — the rule [`check`] states for every probe whose tool is only the means.
///
/// The output goes into a directory of its own, made with `create_dir` under the temp
/// directory (which fails rather than reuse a name someone else made) and removed on every
/// path out. Never `/dev/null`: a linker run as root replaces its output path, and that
/// path is not ours to replace. A pid-named file in the shared temp directory would be a
/// name another user can plant.
fn links_against(compiler: &str, lib: &str) -> Option<bool> {
    use std::io::Write;
    use std::process::Stdio;
    let dir = (0..16).find_map(|n| {
        let dir =
            std::env::temp_dir().join(format!("kotton-doctor-link-{}-{n}", std::process::id()));
        std::fs::create_dir(&dir).ok().map(|()| dir)
    })?;
    let linked = (|| {
        let mut child = Command::new(compiler)
            .args(["-x", "c", "-", "-o"])
            .arg(dir.join("probe"))
            .arg(format!("-l{lib}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        if let Some(mut stdin) = child.stdin.take() {
            // A write that fails means the compiler already exited; its status is the answer.
            let _ = stdin.write_all(b"int main(void) { return 0; }\n");
        }
        child.wait().ok().map(|status| status.success())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    linked
}

/// Every fix for a requirement on this platform: the entries naming it, or the
/// entries naming no platform. Empty where nothing here knows how to install it.
pub(crate) fn fixes_for(need: &Need, os: &str) -> Vec<Fix> {
    let named: Vec<Fix> = need
        .fix
        .iter()
        .filter(|(o, _)| *o == os)
        .map(|(_, f)| *f)
        .collect();
    if !named.is_empty() {
        return named;
    }
    need.fix
        .iter()
        .filter(|(o, _)| o.is_empty())
        .map(|(_, f)| *f)
        .collect()
}

/// The fixes for a set of requirements, merged by installer into the fewest lines: one
/// `cargo install` naming every crate, one `apt-get` naming every package, and so on,
/// in the order a person would run them. Shell lines stay verbatim and last, because
/// they run things the lines above installed.
fn render_fixes(fixes: &[Fix], sudo: bool) -> Vec<String> {
    fn push(list: &mut Vec<&'static str>, item: &'static str) {
        for word in item.split_whitespace() {
            if !list.contains(&word) {
                list.push(word);
            }
        }
    }
    let (mut cargo, mut rustup, mut apt, mut brew, mut scoop, mut winget) = (
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let mut xcode = false;
    let mut shell: Vec<&'static str> = Vec::new();
    for f in fixes {
        match f {
            Fix::Cargo(c) => push(&mut cargo, c),
            Fix::Rustup(t) => push(&mut rustup, t),
            Fix::Apt(p) => push(&mut apt, p),
            Fix::Brew(p) => push(&mut brew, p),
            Fix::Scoop(p) => push(&mut scoop, p),
            Fix::Winget(p) => push(&mut winget, p),
            Fix::Xcode => xcode = true,
            Fix::Shell(line) => {
                if !shell.contains(line) {
                    shell.push(line);
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut line = |prefix: &str, items: &[&str]| {
        if !items.is_empty() {
            out.push(format!("{prefix} {}", items.join(" ")));
        }
    };
    line("cargo install", &cargo);
    line("rustup target add", &rustup);
    if sudo {
        line("sudo apt-get update && sudo apt-get install -y", &apt);
    } else {
        line("apt-get update && apt-get install -y", &apt);
    }
    line("brew install", &brew);
    line("scoop install", &scoop);
    line("winget install", &winget);
    if xcode {
        out.push("xcode-select --install".to_owned());
    }
    out.extend(shell.iter().map(|l| (*l).to_owned()));
    out
}

/// Whether `bin` is on `PATH`, by looking — never by running it. On Windows the
/// name is tried with `.exe` too.
fn on_path(bin: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let plain = dir.join(bin);
        plain.is_file() || (cfg!(windows) && dir.join(format!("{bin}.exe")).is_file())
    })
}

/// Whether the system installer needs `sudo` in front of it: a Unix user who is not
/// root. Measured against a container that runs as root, the block said `apt-get`
/// bare, and on the owner's WSL2 that is `Permission denied` on the lock file.
fn needs_sudo() -> bool {
    if cfg!(windows) {
        return false;
    }
    Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() != "0")
}

/// A command line that would run past `width`, broken at spaces into shell
/// continuation lines — each ending in ` \`, each indented — so it still pastes as
/// one command. A line that fits is returned as it is.
fn continue_at(cmd: &str, width: usize, indent: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::from(indent);
    let cont = format!("{indent}    ");
    for word in cmd.split_whitespace() {
        let at_start = cur.trim().is_empty();
        if !at_start && cur.len() + 1 + word.len() + 2 > width {
            cur.push_str(" \\");
            lines.push(std::mem::replace(&mut cur, cont.clone()));
        }
        if !cur.trim().is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    lines.push(cur);
    lines
}

/// The report never exceeds this many columns. A default Windows console is 80
/// and a reason that wraps there reads as noise; every string in [`NEEDS`] is held
/// to fit by `every_line_fits_the_report`, so nothing here is wrapped by the
/// printer; the closing line alone breaks before its ask when the counts would
/// carry it past the edge.
const MAX_WIDTH: usize = 78;
/// The status word is padded to the widest one (`missing`) so every name starts
/// in the same column whatever precedes it.
const STATUS_WIDTH: usize = 7;
/// The label column in the detail block: `without it` and `fix`, padded alike.
const LABEL_WIDTH: usize = 11;
/// What is left for a reason or a fix line after its indent and label.
const TEXT_WIDTH: usize = MAX_WIDTH - 2 - LABEL_WIDTH - 1;

// Every reason fits its line, checked when this file compiles. A fix may be more than
// one line and `str::lines` is not const, so the test `every_line_fits_the_report`
// holds those and the names; this holds the one that changes most.
const _: () = {
    let mut i = 0;
    while i < NEEDS.len() {
        assert!(
            NEEDS[i].breaks.len() <= TEXT_WIDTH,
            "a `breaks:` sentence in doctor::NEEDS is longer than the report allows"
        );
        i += 1;
    }
};

pub fn run(args: &[String]) {
    use colored::Colorize;
    use std::io::IsTerminal;

    // Colour is for a person at a terminal. Piped, the same text and nothing else —
    // the rule the shell's renderer states for every command.
    if !std::io::stdout().is_terminal() {
        colored::control::set_override(false);
    }

    let want = args
        .iter()
        .position(|a| a == "--tier")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| Tier::parse(s))
        .unwrap_or(Tier::Lint);
    let os = std::env::consts::OS;

    // Two passes over one list: the first draws the picture, the second says what to do.
    // Interleaving the two — reason and fix under every missing row — is what made the
    // report hard to scan, because the rows stopped lining up the moment one was missing.
    let mut missing: Vec<(&Need, Tier, Verdict)> = Vec::new();

    println!(
        "{} what `{}` needs on {os}",
        "doctor —".bold(),
        want.label()
    );
    for &tier in want.shown() {
        println!();
        println!(
            "{:<width$}  {}",
            tier.label().bold(),
            gate_of(tier).dimmed(),
            width = STATUS_WIDTH + 2
        );
        let group: Vec<&Need> = NEEDS
            .iter()
            .filter(|n| want.lists(n, tier))
            .filter(|n| n.only.is_empty() || n.only.contains(&os))
            .collect();
        if group.is_empty() {
            // The header stays: a tier that vanishes reads as "doctor forgot it", and a
            // summary naming a tier the report never showed is what a reader met on
            // Windows, where every desktop requirement is Linux's.
            println!(
                "  {:<width$}  {}",
                "ok".green(),
                format!("nothing more is needed on {os}").dimmed(),
                width = STATUS_WIDTH
            );
            continue;
        }
        for n in group {
            let v = check(&n.probe);
            let word = match &v {
                Verdict::Met => "ok".green(),
                Verdict::Missing => "missing".red().bold(),
                Verdict::Unknown(_) => "unknown".yellow().bold(),
            };
            println!("  {:<width$}  {}", word, n.what, width = STATUS_WIDTH);
            if v != Verdict::Met {
                missing.push((n, tier, v));
            }
        }
    }
    println!();

    if missing.is_empty() {
        println!(
            "{} everything `{}` needs is here.",
            "doctor: OK —".green().bold(),
            want.label()
        );
        return;
    }

    let (here, later): (Vec<&Need>, Vec<&Need>) = missing
        .iter()
        // An unknown has no fix to merge: its cure is the tool that would have
        // answered, and that tool has a row and a fix of its own.
        .filter(|(_, _, v)| !matches!(v, Verdict::Unknown(_)))
        .fold((Vec::new(), Vec::new()), |(mut h, mut l), (n, t, _)| {
            if *t <= want {
                h.push(*n)
            } else {
                l.push(*n)
            }
            (h, l)
        });
    for (n, tier, v) in &missing {
        let note = if *tier <= want {
            ""
        } else {
            "  (a higher tier; not blocking you)"
        };
        println!("{}{}", n.what.bold(), note.dimmed());
        match v {
            Verdict::Unknown(why) => println!("  cannot tell: {why}"),
            _ => println!("  {}", n.breaks),
        }
    }
    println!();

    // One block a person pastes, merged by installer, for the tier they asked about;
    // a second, smaller, for what a higher tier would also want.
    let sudo = needs_sudo();
    let block = |heading: &str, needs: &[&Need]| {
        let fixes: Vec<Fix> = needs.iter().flat_map(|n| fixes_for(n, os)).collect();
        let lines = render_fixes(&fixes, sudo);
        if lines.is_empty() {
            return;
        }
        println!("{}", heading.bold());
        for cmd in lines {
            for l in continue_at(&cmd, MAX_WIDTH, "  ") {
                println!("{l}");
            }
        }
        println!();
    };
    if !here.is_empty() {
        block(&format!("To be ready for `{}`, run:", want.label()), &here);
    }
    if !later.is_empty() {
        block("And for the tiers above it:", &later);
    }

    // Counted apart: a `missing` is a thing to install, an `unknown` is a tool that could
    // not be run, and a line that calls both "missing" sends someone to install what is there.
    let count = |blocking: bool, verdict: fn(&Verdict) -> bool| {
        missing
            .iter()
            .filter(|(_, t, v)| (*t <= want) == blocking && verdict(v))
            .count()
    };
    let is_missing = |v: &Verdict| matches!(v, Verdict::Missing);
    let is_unknown = |v: &Verdict| matches!(v, Verdict::Unknown(_));
    let (absent, unasked) = (count(true, is_missing), count(true, is_unknown));
    if absent + unasked == 0 {
        println!(
            "{} for `{}`. {} for a higher tier, listed above.",
            "doctor: OK".green().bold(),
            want.label(),
            tally(count(false, is_missing), count(false, is_unknown))
        );
        return;
    }
    // A gate that runs without its tools reports OK and verifies nothing; that is the
    // whole reason this exits non-zero rather than advising — an `unknown` included.
    eprintln!("{}", not_ready(want, absent, unasked));
    std::process::exit(1);
}

/// The last line when the asked-for tier is not met. Its own function so the width
/// test can render it for the longest tier name and a two-digit count.
fn not_ready(tier: Tier, missing: usize, unknown: usize) -> String {
    use colored::Colorize;
    let said = format!(
        "`{}` is not ready: {}.",
        tier.label(),
        tally(missing, unknown)
    );
    // An unknown has no fix block (its cure is the tool that would have answered), so
    // with nothing missing there is nothing to paste.
    let ask = if missing == 0 {
        "Rerun once the tool named above can be run."
    } else {
        "Paste the block above, then rerun."
    };
    // Both counts for the longest tier name do not fit one line with the ask; the ask
    // then goes on a line of its own rather than past the edge.
    let join = if "doctor: ".len() + said.len() + 1 + ask.len() <= MAX_WIDTH {
        " "
    } else {
        "\n"
    };
    format!("{} {said}{join}{ask}", "doctor:".red().bold())
}

/// "2 missing", "3 unknown" or "2 missing, 3 unknown": a count that is zero is not said.
fn tally(missing: usize, unknown: usize) -> String {
    match (missing, unknown) {
        (m, 0) => format!("{m} missing"),
        (0, u) => format!("{u} unknown"),
        (m, u) => format!("{m} missing, {u} unknown"),
    }
}

fn gate_of(t: Tier) -> &'static str {
    match t {
        Tier::Lint => "just lint — the gate every branch must pass",
        Tier::Test => "just test — the suite",
        Tier::Build => "cargo xtask release — the desktop's archive",
        Tier::Desktop => "just desktop::run — the window",
        Tier::Server => "cargo xtask release-server — a host's two archives",
    }
}

#[cfg(test)]
mod tests {
    use super::{Tier, NEEDS};

    /// Every requirement names the platforms it applies to, and the desktop tier is
    /// Linux-only in its current form.
    ///
    /// The second half is the load-bearing one: `Probe::PkgConfig` and `Probe::Lib`
    /// answer *unknown* where their tool does not exist, so an ungated Linux
    /// requirement on a Mac is a "cannot tell" row that counts as not ready, for a
    /// library the build never uses. This test is what stops the next requirement
    /// being added without a platform.
    #[test]
    fn every_desktop_requirement_names_its_platform() {
        for need in NEEDS {
            if matches!(need.tier, Tier::Desktop | Tier::Build) {
                assert!(
                    !need.only.is_empty(),
                    "`{}` is a desktop requirement with no platform — it will report \
                     MISSING on macOS and Windows, where it is not needed at all",
                    need.what
                );
            }
        }
    }

    /// The output that made this row worth having, verbatim from the owner's WSL2 machine
    /// on 2026-09-17: one device, and it is software, on a machine with an RTX 4070 Ti.
    #[test]
    fn a_summary_naming_only_llvmpipe_is_not_a_gpu() {
        let summary = "\
Vulkan Instance Version: 1.3.204

Devices:
========
GPU0:
\tapiVersion         = 1.3.255
\tdriverVersion      = 0.0.1
\tvendorID           = 0x10005
\tdeviceID           = 0x0000
\tdeviceType         = PHYSICAL_DEVICE_TYPE_CPU
\tdeviceName         = llvmpipe (LLVM 15.0.7, 256 bits)
\tdriverID           = DRIVER_ID_MESA_LLVMPIPE
";
        assert_eq!(super::vulkan_has_hardware(summary), Some(false));
    }

    /// One hardware device among software ones is still a machine that can render.
    #[test]
    fn a_summary_naming_a_discrete_device_is_a_gpu() {
        let summary = "\
GPU0:
\tdeviceType         = PHYSICAL_DEVICE_TYPE_DISCRETE_GPU
\tdeviceName         = NVIDIA GeForce RTX 4070 Ti
GPU1:
\tdeviceType         = PHYSICAL_DEVICE_TYPE_CPU
\tdeviceName         = llvmpipe (LLVM 15.0.7, 256 bits)
";
        assert_eq!(super::vulkan_has_hardware(summary), Some(true));
    }

    /// Output with no device in it establishes nothing, and must not read as `missing`.
    ///
    /// This is the same rule the `xprop` row follows: the tool is how the question is
    /// asked, and a question that was not answered is not a no.
    #[test]
    fn a_summary_with_no_device_line_says_nothing_either_way() {
        assert_eq!(super::vulkan_has_hardware(""), None);
        assert_eq!(
            super::vulkan_has_hardware("ERROR: [Loader Message] Failed to CreateInstance\n"),
            None
        );
    }

    /// A platform list may only name real `target_os` values.
    ///
    /// A typo here fails open, not closed: `only: &["macos "]` matches nothing, the
    /// requirement is silently skipped everywhere, and the gate stops gating.
    /// The fixes used are this platform's, or the fallback, or none — never another
    /// platform's, and a platform that needs two steps gets both.
    #[test]
    fn a_fix_is_for_the_platform_it_prints_on() {
        use super::{fixes_for, Fix};
        let git = NEEDS.iter().find(|n| n.what == "git").unwrap();
        assert_eq!(fixes_for(git, "windows"), vec![Fix::Winget("Git.Git")]);
        assert_eq!(fixes_for(git, "freebsd"), vec![]);
        let just = NEEDS.iter().find(|n| n.what == "just").unwrap();
        assert_eq!(fixes_for(just, "windows"), vec![Fix::Scoop("just")]);
        // A platform with no entry of its own gets the fallback, and only the fallback.
        assert_eq!(fixes_for(just, "freebsd"), vec![Fix::Cargo("just")]);
        // Pinned because it was wrong once: `docs/use/windows.md` sets this machine up
        // with scoop, and a fix line naming a second package manager sends a person to
        // install one they do not have.
        let clang = NEEDS.iter().find(|n| n.what == "clang").unwrap();
        assert_eq!(fixes_for(clang, "windows"), vec![Fix::Scoop("llvm")]);
        assert_eq!(fixes_for(clang, "linux"), vec![Fix::Apt("clang")]);
        let wm = NEEDS.iter().find(|n| n.what == "a window manager").unwrap();
        assert_eq!(fixes_for(wm, "linux").len(), 2);
        assert_eq!(fixes_for(wm, "macos"), vec![]);
    }

    /// The linker probe asks the compiler and trusts its answer both ways: libc is always
    /// there to link, and a name nothing installs is not. (The case this exists for, a
    /// run-time `libxdo.so.3` with no `libxdo.so`, is the second one from the linker's
    /// side: it finds no `-lxdo` either.) Unix only: Windows has no `cc`.
    #[cfg(unix)]
    #[test]
    fn links_against_asks_the_linker() {
        assert_eq!(super::links_against("cc", "c"), Some(true));
        assert_eq!(
            super::links_against("cc", "kotton-no-such-library-2026"),
            Some(false)
        );
    }

    /// A compiler that cannot be run is "nobody asked", not "not installed": the probe
    /// takes the compiler's name so this is tested directly, with one nothing installs,
    /// and `check` turns the `None` into `Unknown` (it has no other arm for it).
    #[test]
    fn links_against_without_a_compiler_does_not_answer() {
        assert_eq!(
            super::links_against("kotton-no-such-compiler-2026", "c"),
            None
        );
    }

    /// `pkg-config` is how a library is asked about, not the library: one that cannot be
    /// run is "nobody asked", not "not installed", so the probe takes the tool's name and
    /// `check` turns the `None` into `Unknown`, as for the compiler above.
    #[test]
    fn pkg_config_without_pkg_config_does_not_answer() {
        assert_eq!(
            super::pkg_config_exists("kotton-no-such-pkg-config-2026", "openssl"),
            None
        );
    }

    /// The same for `ldconfig`, which does not exist at all on macOS and Windows.
    #[test]
    fn ldconfig_without_ldconfig_does_not_answer() {
        assert_eq!(
            super::ldconfig_lists(&["kotton-no-such-ldconfig-2026"], "libc"),
            None
        );
    }

    /// A tool that cannot be spawned hands the question to the next one (`/sbin/ldconfig`
    /// after the bare name); one that runs and exits non-zero is the answer, and the next
    /// is not asked. `true` and `false` stand in for an `ldconfig` that lists nothing and
    /// one that fails.
    #[cfg(unix)]
    #[test]
    fn ldconfig_falls_through_only_when_it_cannot_be_run() {
        assert_eq!(
            super::ldconfig_lists(&["kotton-no-such-ldconfig-2026", "true"], "libc"),
            Some(false)
        );
        assert_eq!(super::ldconfig_lists(&["false", "true"], "libc"), None);
        assert_eq!(
            super::ldconfig_lists(
                &["kotton-no-such-ldconfig-2026", "kotton-no-such-either-2026"],
                "libc"
            ),
            None
        );
        assert_eq!(super::LDCONFIG.last(), Some(&"/sbin/ldconfig"));
    }

    /// **The closing line counts what is missing apart from what could not be asked.**
    /// A tool that could not be run is not a package to install, and the summary that
    /// called every row that is not `ok` "missing" overstated by exactly those.
    #[test]
    fn the_summary_counts_unknown_rows_apart_from_missing_ones() {
        colored::control::set_override(false);
        let line = |m, u| super::not_ready(Tier::Build, m, u);
        assert_eq!(
            line(2, 0),
            "doctor: `build` is not ready: 2 missing. Paste the block above, then rerun."
        );
        assert_eq!(
            line(0, 3),
            "doctor: `build` is not ready: 3 unknown.\n\
             Rerun once the tool named above can be run."
        );
        assert_eq!(
            line(5, 5),
            "doctor: `build` is not ready: 5 missing, 5 unknown.\n\
             Paste the block above, then rerun."
        );
        assert_eq!(super::tally(0, 0), "0 missing");
        assert_eq!(super::tally(1, 2), "1 missing, 2 unknown");
    }

    /// `on_path` looks and does not run: the shell that runs these tests is on PATH,
    /// and a name nothing installs is not.
    #[test]
    fn on_path_finds_a_binary_without_running_it() {
        let shell = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(super::on_path(shell));
        assert!(!super::on_path("kotton-no-such-binary-2026"));
    }

    /// Fixes merge by installer into one line each, deduplicated, with shell lines
    /// verbatim and last.
    #[test]
    fn fixes_merge_into_one_line_per_installer() {
        use super::{render_fixes, Fix};
        let fixes = [
            Fix::Apt("libgtk-3-dev"),
            Fix::Cargo("just"),
            Fix::Apt("libpango1.0-dev"),
            Fix::Shell("matchbox-window-manager &"),
            Fix::Apt("libgtk-3-dev"),
            Fix::Cargo("ripgrep"),
        ];
        let lines = render_fixes(&fixes, false);
        assert_eq!(
            lines,
            vec![
                "cargo install just ripgrep",
                "apt-get update && apt-get install -y libgtk-3-dev libpango1.0-dev",
                "matchbox-window-manager &",
            ]
        );
        assert!(render_fixes(&[], false).is_empty());
        // A user who is not root is told `sudo`, on the system installer only.
        assert_eq!(
            render_fixes(&fixes, true)[1],
            "sudo apt-get update && sudo apt-get install -y libgtk-3-dev libpango1.0-dev"
        );
        assert_eq!(render_fixes(&fixes, true)[0], "cargo install just ripgrep");
    }

    /// A long command becomes continuation lines that each fit and still paste as one.
    #[test]
    fn a_long_command_continues_within_the_width() {
        let cmd = "apt-get update && apt-get install -y libgtk-3-dev libpango1.0-dev \
                   libxkbcommon-x11-0 libxdo-dev matchbox-window-manager x11-utils";
        let lines = super::continue_at(cmd, 40, "  ");
        assert!(lines.len() > 1);
        for (i, l) in lines.iter().enumerate() {
            assert!(l.len() <= 40, "too long: {l:?}");
            if i + 1 < lines.len() {
                assert!(l.ends_with(" \\"), "no continuation: {l:?}");
            }
        }
        let joined: String = lines
            .iter()
            .map(|l| l.trim_end_matches('\\').trim())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(joined, cmd.split_whitespace().collect::<Vec<_>>().join(" "));
        assert_eq!(super::continue_at("short", 40, "  "), vec!["  short"]);
    }

    /// Every line the report can print fits in [`MAX_WIDTH`] columns, so it never
    /// wraps in a default console. This is the whole cap: the printer does not wrap,
    /// so a string that fails here is a line that would run past the edge.
    #[test]
    fn every_line_fits_the_report() {
        colored::control::set_override(false);
        for (missing, unknown) in [(10, 10), (0, 10), (10, 0)] {
            for last in super::not_ready(Tier::Desktop, missing, unknown).lines() {
                assert!(
                    last.chars().count() <= super::MAX_WIDTH,
                    "the last line is too long: {last:?}"
                );
            }
        }
        for need in NEEDS {
            assert!(
                need.what.len() + 2 + super::STATUS_WIDTH + 2 <= super::MAX_WIDTH,
                "`{}`: the name is too long for a row",
                need.what
            );
            assert!(
                need.breaks.len() <= super::TEXT_WIDTH,
                "`{}`: the reason is {} chars; the cap is {}: {:?}",
                need.what,
                need.breaks.len(),
                super::TEXT_WIDTH,
                need.breaks
            );
            for (os, fix) in need.fix {
                if let super::Fix::Shell(line) = fix {
                    assert!(
                        line.len() + 2 <= super::MAX_WIDTH,
                        "`{}` on {os:?}: a shell line is {} chars: {line:?}",
                        need.what,
                        line.len()
                    );
                }
            }
        }
        for tier in [
            Tier::Lint,
            Tier::Test,
            Tier::Build,
            Tier::Desktop,
            Tier::Server,
        ] {
            let header = super::STATUS_WIDTH + 2 + 2 + super::gate_of(tier).len();
            assert!(
                header <= super::MAX_WIDTH,
                "the {} header is too long",
                tier.label()
            );
        }
    }

    /// **The server tier is reported alone, and the ladder never shows it.** A person
    /// building a host's release is not told to install GTK, and a contributor asking about
    /// `desktop` is not handed a musl toolchain to paste.
    #[test]
    fn the_server_tier_is_reported_alone_and_the_ladder_never_shows_it() {
        assert_eq!(Tier::parse("server"), Some(Tier::Server));
        assert_eq!(Tier::Server.shown(), &[Tier::Server]);
        for rung in [Tier::Lint, Tier::Test, Tier::Desktop] {
            assert!(!rung.shown().contains(&Tier::Server), "{}", rung.label());
            assert_eq!(
                rung.shown(),
                &[Tier::Lint, Tier::Test, Tier::Build, Tier::Desktop]
            );
        }
    }

    /// The rows a report for `want` lists, in the order it lists them: each shown tier's
    /// group, as `run` draws it.
    fn listed(want: Tier) -> Vec<&'static super::Need> {
        want.shown()
            .iter()
            .flat_map(|&t| NEEDS.iter().filter(move |n| want.lists(n, t)))
            .filter(|n| n.only.is_empty() || n.only.contains(&"linux"))
            .collect()
    }

    /// **The build tier is a rung of the window's ladder and also asked for alone**, so the
    /// release runner can be held to what the archive builds with without being held to a
    /// window manager. Alone it shows only itself; on the ladder it is one rung, between the
    /// suite's and the window's.
    #[test]
    fn the_build_tier_is_a_rung_and_is_reported_alone() {
        assert_eq!(Tier::parse("build"), Some(Tier::Build));
        assert_eq!(Tier::Build.shown(), &[Tier::Build]);
        assert!(Tier::Test < Tier::Build && Tier::Build < Tier::Desktop);
        for rung in [Tier::Lint, Tier::Test, Tier::Desktop] {
            assert!(rung.shown().contains(&Tier::Build), "{}", rung.label());
        }
        assert!(!Tier::Server.shown().contains(&Tier::Build));
        // On the ladder no row is listed twice, though the build tier names rows the lint and
        // test rungs own.
        let ladder = listed(Tier::Desktop);
        for (i, n) in ladder.iter().enumerate() {
            assert!(
                !ladder[i + 1..].iter().any(|m| std::ptr::eq(*m, *n)),
                "`{}` is listed twice in the desktop report",
                n.what
            );
        }
    }

    /// **The build tier asks for what the archive is built with and nothing about running
    /// the window**: no window manager, no GPU, no framebuffer, none of the tools that ask
    /// the display — and none of what only the lint and test rungs want (`just`, `rg`, `git`,
    /// systemd's parser). Everything it does list, the desktop report lists too.
    #[test]
    fn the_build_tier_asks_for_nothing_about_running_the_window() {
        use super::Probe;
        let build = listed(Tier::Build);
        for n in &build {
            assert!(
                !matches!(
                    n.probe,
                    Probe::WindowManager | Probe::HardwareGpu | Probe::WhenNoDisplay(_)
                ),
                "`{}` is about running the window",
                n.what
            );
            assert_ne!(n.tier, Tier::Desktop, "`{}` is the window's own row", n.what);
            assert!(
                listed(Tier::Desktop).iter().any(|m| std::ptr::eq(*m, *n)),
                "the desktop report does not list `{}`, which a build needs",
                n.what
            );
        }
        for absent in ["xprop", "vulkaninfo", "Xvfb", "scrot", "just", "rg", "git"] {
            assert!(
                !build.iter().any(|n| matches!(
                    n.probe,
                    Probe::Bin(b) | Probe::OnPath(b) | Probe::WhenNoDisplay(b) if b == absent
                )),
                "the build tier asks for `{absent}`"
            );
        }
        assert!(
            !build.iter().any(|n| matches!(n.probe, Probe::SystemdsLibrary)),
            "the build tier asks for systemd's parser, which only the suite and the servers read"
        );
    }

    /// **The build tier names every library and tool `cargo xtask release` reads on
    /// Linux**: the C toolchain and `pkg-config`, the OpenSSL sqlcipher links (a row both
    /// the lint workflow and the build need), fontconfig, GTK, pango and libxdo, `python3`
    /// for stylo, and `clang` and the wasm target for the bundled apps.
    #[test]
    fn the_build_tier_names_what_the_release_reads() {
        use super::{fixes_for, Fix, Probe};
        let build = listed(Tier::Build);
        for pkg in [
            "pkg-config",
            "build-essential",
            "libfontconfig-dev",
            "libssl-dev",
            "clang",
            "python3",
            "libgtk-3-dev",
            "libpango1.0-dev",
            "libxdo-dev",
        ] {
            assert!(
                build.iter().any(|n| fixes_for(n, "linux") == vec![Fix::Apt(pkg)]),
                "the build tier has no row that installs `{pkg}`"
            );
        }
        assert!(
            build
                .iter()
                .any(|n| matches!(n.probe, Probe::Target("wasm32-wasip2"))),
            "the build tier has no row for the wasm target"
        );
    }

    /// **The release workflow installs what the build tier names and runs the tier**, in
    /// place of a list of its own: the apt packages it installs are the tier's, exactly, the
    /// rustup target is the tier's, and `doctor --tier build` is the step's last command.
    #[test]
    fn the_release_workflow_installs_what_the_build_tier_names() {
        use super::{fixes_for, Fix};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join(".github/workflows/release.yml"))
            .expect(".github/workflows/release.yml exists");
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let at = lines
            .iter()
            .position(|l| *l == "cargo xtask doctor --tier build")
            .expect("the release workflow runs `doctor --tier build` as a command of its own");
        let apt = lines[..at]
            .iter()
            .rev()
            .find_map(|l| l.strip_prefix("sudo apt-get install -y "))
            .expect("the step installs with apt-get before it runs doctor");
        let mut installed: Vec<&str> = apt.split_whitespace().collect();
        let mut named: Vec<&str> = listed(Tier::Build)
            .iter()
            .flat_map(|n| fixes_for(n, "linux"))
            .filter_map(|f| match f {
                Fix::Apt(p) => Some(p),
                _ => None,
            })
            .flat_map(str::split_whitespace)
            .collect();
        installed.sort_unstable();
        named.sort_unstable();
        named.dedup();
        assert_eq!(installed, named, "release.yml's apt line is not the build tier's");
        assert!(
            lines[..at].contains(&"rustup target add wasm32-wasip2"),
            "the step does not add the wasm target the tier names"
        );
    }

    /// **The server tier asks for what `release-server` builds with**: the target it names,
    /// the C compiler `ring`, `aws-lc-sys` and OpenSSL build under on that target, the two
    /// tools OpenSSL's own build runs, and systemd's parser, which its gate requires.
    #[test]
    fn the_server_tier_asks_for_what_release_server_builds_with() {
        use super::{fixes_for, Fix, Probe};
        let server: Vec<_> = NEEDS.iter().filter(|n| n.tier == Tier::Server).collect();
        let target = server
            .iter()
            .find_map(|n| match n.probe {
                Probe::Target(t) => Some(t),
                _ => None,
            })
            .expect("the server tier checks a rustup target");
        assert_eq!(target, crate::release_server::TARGET);
        for bin in ["musl-gcc", "cc", "make", "perl"] {
            assert!(
                server.iter().any(|n| matches!(n.probe, Probe::Bin(b) | Probe::OnPath(b) if b == bin)),
                "the server tier has no row for `{bin}`"
            );
        }
        // And systemd's own settings parser, which the release gate requires
        // (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`).
        let parser = server.iter().find(|n| matches!(n.probe, Probe::SystemdsLibrary)).expect("the server tier names libsystemd-shared");
        let test = NEEDS.iter().find(|n| n.tier == Tier::Test && matches!(n.probe, Probe::SystemdsLibrary)).expect("the test tier names libsystemd-shared");
        assert_eq!(fixes_for(test, "linux"), vec![Fix::Apt("libsystemd-shared")]);
        assert_eq!(fixes_for(parser, "linux"), vec![Fix::Apt("libsystemd-shared")]);
        assert!(server.iter().any(|n| matches!(n.probe, Probe::Bin("python3"))), "the server tier has no row for `python3`");
        let musl = server.iter().find(|n| n.what.starts_with("musl-gcc")).unwrap();
        assert_eq!(fixes_for(musl, "linux"), vec![Fix::Apt("musl-tools")]);
        // Off Linux the one row shown is the one no package fixes.
        let off: Vec<_> = server.iter().filter(|n| n.only.is_empty()).collect();
        assert_eq!(off.len(), 1);
        assert!(matches!(off[0].probe, Probe::Os("linux")));
        assert!(fixes_for(off[0], "macos").is_empty());
    }

    #[test]
    fn platform_names_are_real() {
        const KNOWN: &[&str] = &["linux", "macos", "windows", "freebsd", "openbsd", "netbsd"];
        for need in NEEDS {
            for os in need.only {
                assert!(
                    KNOWN.contains(os),
                    "`{}` names an unknown target_os {os:?}",
                    need.what
                );
            }
        }
    }
}
