// SPDX-License-Identifier: AGPL-3.0-or-later
//! `run::shot` — the desktop window drawn under a virtual framebuffer, written out as a PNG.
//!
//! ## What this is, and what it is not
//!
//! `DEC-0076` left one thing open under *Not decided here*: **"what a contributor without
//! a GPU does … the answer may be a documented opt-in rather than an amendment."** This is
//! that opt-in. Nothing here ships, nothing in the product knows this file exists, and the
//! GPU stays the path a person runs on. It is a contributor's tool for looking at the
//! window on a machine that cannot show one.
//!
//! The renderer was never the obstacle: the CPU path (`anyrender_vello_cpu`) is still the
//! default build, which is the seam `DEC-0076` deliberately kept. The obstacle is that a
//! container has no X or Wayland server, so `kuserd`'s `display_available` is false, no
//! compositor is spawned, and no window opens at all. `Xvfb` is one apt package, and a
//! frame written to a file is something an agent can read.
//!
//! ## Why the picture is taken from X and not from kuid
//!
//! kuid can already encode a PNG — `encode_png` in `core/kuid/src/main.rs`, with a `png`
//! dev-dependency and a test that writes a frame. That path paints a blitz document
//! through `anyrender_vello_cpu` **in process**: it is a picture of what the renderer
//! would draw from one document, not of the composited window. It proves nothing about
//! winit opening a window, about the layers composited into it, or about the geometry the
//! person would see, and it lives behind `#[cfg(test)]`.
//!
//! Taking the frame from the X server instead makes the picture *the thing on the screen*,
//! and costs kuid nothing. The alternative — a screenshot verb on the display server —
//! would be a new capability on the process that holds every surface, confined and
//! reasoned about forever after, added so that a contributor could see a welcome screen.
//! The cheaper tool is outside the product, which is where a contributor's tool belongs.
//!
//! ## What it does
//!
//! 1. starts `Xvfb` on a free display,
//! 2. runs the same `run::desktop` that `just desktop::run` runs, with `DISPLAY` pointing
//!    at it and no user — so the window onboards (`DEC-0077`) and the frame is the welcome
//!    screen, which is a picture, not a session,
//! 3. waits for a real X window to appear under the root, lets it settle, and writes a PNG
//!    of it with `scrot`,
//! 4. stops kuserd, kuid and the framebuffer on every path out, including the failures.
//!
//! There is no window manager here, so nothing has keyboard focus (`doctor`'s
//! `a window manager` row says why). That is fine for a picture and useless for a session.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Where the picture goes when nothing names a path. Under `/.kotton.*/`, which
/// `.gitignore` already covers.
const DEFAULT_OUT: &str = ".kotton.shot/desktop.png";
/// The framebuffer's screen. 24-bit because the compositor asks for a 24-bit visual and a
/// shallower screen leaves it nothing to match.
const DEFAULT_SCREEN: &str = "1280x800x24";
/// How long the whole run may take before it is a failure, in seconds. The first draw is
/// behind a daemon start, a compositor start and a wasm shell launch.
const DEFAULT_SECONDS: u64 = 180;
/// How long to let the window paint after X says it exists, in seconds. A window exists
/// before it has drawn, and a screenshot taken at creation is a picture of nothing.
const DEFAULT_SETTLE: u64 = 6;

/// One window as `xwininfo -root -tree` reports it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Win {
    pub id: String,
    pub name: String,
    pub w: u32,
    pub h: u32,
    pub x: i32,
    pub y: i32,
}

impl Win {
    fn geometry(&self) -> String {
        format!("{}x{}+{}+{}", self.w, self.h, self.x, self.y)
    }
}

/// Every window `xwininfo -root -tree` lists under the root, in the order printed.
///
/// A line looks like this, and the shape is stable across the X.Org tools:
///
/// ```text
///      0x200001 "Kotton": ("kotton" "Kotton")  1280x800+0+0  +0+0
/// ```
///
/// Parsed rather than matched on a title, because the title is the *surface's* — it comes
/// from the guest app through `kuserd`, and a check here that named it would be this file
/// deciding what the shell may call itself.
pub(crate) fn parse_tree(out: &str) -> Vec<Win> {
    let mut wins = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        // The root's own two lines name it, and it is the thing everything else is under.
        if !t.starts_with("0x") || t.contains("(the root window)") {
            continue;
        }
        let Some(id) = t.split_whitespace().next() else {
            continue;
        };
        let Some((w, h, x, y)) = t.split_whitespace().find_map(parse_geometry) else {
            continue;
        };
        let name = t
            .split_once('"')
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(n, _)| n.to_owned())
            .unwrap_or_default();
        wins.push(Win {
            id: id.to_owned(),
            name,
            w,
            h,
            x,
            y,
        });
    }
    wins
}

/// `1280x800+0+0`, and `1x1+-1+-1` for a window placed off the top left corner —
/// `xwininfo` always separates with `+` and signs the number, so splitting on `+` is the
/// whole grammar. Anything else, including the bare `+0+0` absolute position that follows
/// it on the same line, is not a geometry.
fn parse_geometry(tok: &str) -> Option<(u32, u32, i32, i32)> {
    let mut parts = tok.split('+');
    let (w, h) = parts.next()?.split_once('x')?;
    let x = parts.next()?;
    let y = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((
        w.parse().ok()?,
        h.parse().ok()?,
        x.parse().ok()?,
        y.parse().ok()?,
    ))
}

/// The smallest thing this will call a desktop, per side.
///
/// **This is not tidiness, it is the race.** winit opens a 10×10 helper window named
/// `kuid` on the display *before* the compositor opens the real one, and it is a window by
/// every test that matters to X: it is mapped, it has a geometry, and it is the largest
/// thing in the tree for as long as it is the only thing. Measured 2026-09-19: a run whose
/// poll landed in that gap photographed it — 10×10, 85 bytes, and the file said it was the
/// desktop. Waiting for the biggest window is not enough; there has to be a size below
/// which a window is not a desktop at all.
///
/// Absolute rather than a fraction of the screen, so that `--screen` cannot move it: a
/// window on a 4K framebuffer is no less a desktop for covering a tenth of it.
const MIN_DESKTOP: u32 = 200;

/// The window to photograph: the largest one the root has that could be a desktop. With no
/// window manager there are no frames, docks or panels — the compositor's `Background` is
/// the only OS window the tree should hold, and everything else composites into it
/// (RFC-0087). "Largest" is still the rule rather than "the only one", because of the
/// helper windows above and because a tray or a tooltip may open more.
pub(crate) fn largest(wins: Vec<Win>) -> Option<Win> {
    wins.into_iter()
        .filter(|w| w.w >= MIN_DESKTOP && w.h >= MIN_DESKTOP)
        .max_by_key(|w| u64::from(w.w) * u64::from(w.h))
}

/// A PNG's declared size, read from IHDR — the first chunk, by the format's own rule.
/// Twenty-four bytes of header rather than a decoder: this reports what was written, it
/// does not look at it.
pub(crate) fn png_size(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 24 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let num = |at: usize| {
        let four: [u8; 4] = bytes[at..at + 4].try_into().expect("four bytes");
        u32::from_be_bytes(four)
    };
    Some((num(16), num(20)))
}

/// The first display number from `from` that no X server holds.
///
/// `taken` answers for one number so the search is testable without an X server; in the
/// run it is the lock file X itself writes, which is the only thing that can answer for a
/// server started by another process.
pub(crate) fn free_display(from: u32, tries: u32, taken: impl Fn(u32) -> bool) -> Option<u32> {
    (from..from + tries).find(|n| !taken(*n))
}

fn display_taken(n: u32) -> bool {
    Path::new(&format!("/tmp/.X{n}-lock")).exists()
        || Path::new(&format!("/tmp/.X11-unix/X{n}")).exists()
}

/// Whether `bin` is on `PATH`. `doctor` owns the same question for its own report; this
/// asks it again rather than importing the report, because the answer here decides whether
/// to refuse, not what to print.
fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            let p = dir.join(bin);
            p.is_file() || (cfg!(windows) && dir.join(format!("{bin}.exe")).is_file())
        })
    })
}

/// Everything started, so everything can be stopped on every path out — including the
/// failures. A framebuffer left running holds a display number, and a kuserd left running
/// holds the socket the next run polls for.
///
/// **Nothing below this line may call `std::process::exit`**: it skips `Drop`, and the
/// whole point of this type is that it runs. Failures come back as an `Err`, and the exit
/// happens in [`run`] after the processes are gone.
struct Running {
    xvfb: Option<std::process::Child>,
    desktop: Option<std::process::Child>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut c) = self.desktop.take() {
            crate::kill_pid(c.id());
            let _ = c.wait();
        }
        // `run::desktop` spawns kuserd, which spawns kuid and the sidecars; killing the
        // xtask that started them does not take them with it. This is `just kill`'s list,
        // called here so a failure path cleans up as well as a success does.
        for name in ["kuserd", "kuid", "kdeviced", "ksyncd", "kquicd", "kinferd"] {
            crate::kill_by_name(name);
        }
        if let Some(mut c) = self.xvfb.take() {
            crate::kill_pid(c.id());
            let _ = c.wait();
        }
    }
}

/// Print the end of the daemon's log, which is where the reason lives when no window
/// appears. Silent if there is no log: that is itself visible above, where `run::desktop`
/// prints the path it opened.
fn tail_daemon_log(lines: usize) {
    let path = crate::staging_base(std::env::var("KOTTON_BASE_DIR").ok().as_deref())
        .join("logs")
        .join("kuserd.log");
    if let Ok(text) = std::fs::read_to_string(&path) {
        eprintln!("[shot] the end of {}:", path.display());
        let all: Vec<&str> = text.lines().collect();
        for l in all.iter().rev().take(lines).rev() {
            eprintln!("  {l}");
        }
    }
}

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

pub fn run(workspace_root: &Path, args: &[String]) {
    if !cfg!(target_os = "linux") {
        eprintln!(
            "[shot] this stands up an X server to draw into, so it is Linux only. On a \
             machine with a display, `just desktop::run` already shows you the window."
        );
        std::process::exit(1);
    }

    let out = PathBuf::from(
        args.iter()
            .find(|a| !a.starts_with("--"))
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_OUT),
    );
    let screen = arg(args, "--screen").unwrap_or(DEFAULT_SCREEN).to_owned();
    let seconds = arg(args, "--seconds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SECONDS);
    let settle = arg(args, "--settle")
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SETTLE);

    // Refuse rather than fail halfway: a run that starts a framebuffer, boots a daemon and
    // then finds it has no way to write a PNG has spent three minutes to say what could
    // have been said first. `doctor --tier desktop` has a row and an apt line for each.
    for (bin, what) in [
        ("Xvfb", "the virtual framebuffer"),
        ("scrot", "the screenshot"),
        ("xwininfo", "finding the window"),
        ("xdpyinfo", "waiting for the framebuffer"),
    ] {
        if !on_path(bin) {
            eprintln!("[shot] `{bin}` is not installed, and it is {what}.");
            eprintln!("       {}", crate::doctor::refuse(bin));
            std::process::exit(1);
        }
    }

    if let Some(dir) = out.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("[shot] cannot create {}: {e}", dir.display());
            std::process::exit(1);
        }
    }

    let Some(n) = free_display(99, 20, display_taken) else {
        eprintln!("[shot] displays :99 to :118 are all in use; nothing to start a framebuffer on");
        std::process::exit(1);
    };
    let display = format!(":{n}");

    println!("[shot] Xvfb on {display}, screen {screen}");
    let xvfb = Command::new("Xvfb")
        .args([&display, "-screen", "0", &screen, "-nolisten", "tcp"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let xvfb = match xvfb {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[shot] could not start Xvfb: {e}");
            std::process::exit(1);
        }
    };

    let mut running = Running {
        xvfb: Some(xvfb),
        desktop: None,
    };
    let outcome = take(
        &mut running,
        workspace_root,
        &display,
        &out,
        Duration::from_secs(seconds),
        Duration::from_secs(settle),
    );
    println!("[shot] stopping the desktop and the framebuffer");
    drop(running);
    if let Err(why) = outcome {
        eprintln!("[shot] {why}");
        std::process::exit(1);
    }
}

/// Start the desktop on `display`, wait for its window, and write the picture. Every
/// failure is an `Err` and never an exit — see [`Running`].
fn take(
    running: &mut Running,
    workspace_root: &Path,
    display: &str,
    out: &Path,
    limit: Duration,
    settle: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + limit;

    if !wait_for(Duration::from_secs(15), || {
        Command::new("xdpyinfo")
            .args(["-display", display])
            .output()
            .is_ok_and(|o| o.status.success())
    }) {
        return Err(format!(
            "the framebuffer did not answer on {display} within 15 s"
        ));
    }

    // The same command `just desktop::run` runs, and deliberately not a second
    // implementation of it: this is `run::desktop` in this very binary, with `DISPLAY`
    // pointing at the framebuffer and no user named, so the window onboards (`DEC-0077`).
    // The binaries are already built — the recipe depends on `desktop::build`, exactly as
    // `desktop::run` does.
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this executable: {e}"))?;
    println!("[shot] running `run::desktop` against {display} with no user");
    let child = Command::new(&exe)
        .arg("run::desktop")
        .current_dir(workspace_root)
        .env("DISPLAY", display)
        // winit prefers Wayland where both are named, and the framebuffer is an X server.
        // `run::desktop` only drops `WAYLAND_DISPLAY` when it sees both; here the server
        // this run started must win outright.
        .env_remove("WAYLAND_DISPLAY")
        .spawn()
        .map_err(|e| format!("could not start the desktop: {e}"))?;
    running.desktop = Some(child);

    println!("[shot] waiting for a window on {display}…");
    let mut found: Option<Win> = None;
    while Instant::now() < deadline && found.is_none() {
        if let Some(c) = running.desktop.as_mut() {
            if let Ok(Some(status)) = c.try_wait() {
                tail_daemon_log(40);
                return Err(format!(
                    "the desktop run exited before a window opened ({status})"
                ));
            }
        }
        found = Command::new("xwininfo")
            .args(["-display", display, "-root", "-tree"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| largest(parse_tree(&String::from_utf8_lossy(&o.stdout))));
        if found.is_none() {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    let Some(win) = found else {
        tail_daemon_log(40);
        return Err(format!(
            "no window opened on {display} within {} s. The window is what this run is a \
             picture of, so this is a failure and not a blank frame.",
            limit.as_secs()
        ));
    };
    println!(
        "[shot] window {} {:?} at {}",
        win.id,
        win.name,
        win.geometry()
    );

    // A window exists as soon as it is mapped, and has drawn nothing. The compositor's
    // first frame and the shell's first paint are both behind that.
    println!("[shot] letting it paint for {} s…", settle.as_secs());
    std::thread::sleep(settle);

    // The window's rectangle off the screen, not the window id: `scrot -u` photographs
    // whatever has focus, and with no window manager here nothing does. The shell asks
    // for 1200×800 on a 1280×800 screen, so a full-screen grab carries an 80-pixel strip
    // of bare root beside the thing the picture is of.
    //
    // Falls back to the whole screen when the crop is refused — a window placed partly
    // off the screen is a real case, and a picture with a margin is worth more than a
    // failure at the last step.
    let shoot = |area: Option<String>| -> std::io::Result<std::process::ExitStatus> {
        let mut cmd = Command::new("scrot");
        cmd.args(["--overwrite", "--display", display]);
        if let Some(a) = area {
            cmd.args(["--autoselect", &a]);
        }
        cmd.arg(out).status()
    };
    let area =
        (win.x >= 0 && win.y >= 0).then(|| format!("{},{},{},{}", win.x, win.y, win.w, win.h));
    let cropped = area.is_some();
    let mut status = shoot(area).map_err(|e| format!("could not run scrot: {e}"))?;
    if cropped && !status.success() {
        println!("[shot] scrot would not crop to the window; taking the whole screen");
        status = shoot(None).map_err(|e| format!("could not run scrot: {e}"))?;
    }
    if !status.success() {
        return Err(format!("scrot failed ({status})"));
    }

    let bytes = std::fs::read(out).map_err(|e| format!("cannot read {}: {e}", out.display()))?;
    let abs = std::fs::canonicalize(out).unwrap_or_else(|_| out.to_path_buf());
    let Some((w, h)) = png_size(&bytes) else {
        return Err(format!("{} is not a PNG this can read", abs.display()));
    };
    println!(
        "[shot] wrote {} — {w}x{h}, {} bytes",
        abs.display(),
        bytes.len()
    );
    // Not a verdict — this does not decode the image. A uniform frame compresses to a few
    // kilobytes whatever its size, so a small file is the one cheap signal that the window
    // opened and drew nothing, and it is worth saying to someone about to attach the file
    // to a report.
    if bytes.len() < 8 * 1024 {
        println!(
            "[shot] that is very small for this screen — a frame this compressible is \
             usually one flat colour. Look at it before you trust it."
        );
    }
    Ok(())
}

/// Poll `ready` four times a second until it answers true or `limit` passes.
fn wait_for(limit: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    ready()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `xwininfo -root -tree` on a framebuffer running the desktop, copied verbatim from
    /// the display this was written against on 2026-09-19. Pinned as a fixture because the
    /// parser's only job is to read what this tool actually prints.
    ///
    /// One character of it is not from that capture: the desktop window's name, which read
    /// `Kotton Shell` until `DEC-0080`'s ruling of 2026-09-19 made the default desktop app's
    /// display name `Kotton`. The title is the `Background` surface's, which is
    /// `manifest.app.name`, so it follows the rename — and a fixture that did not would be
    /// asserting the parser reads a string nothing produces.
    const TREE: &str = r#"xwininfo: Window id: 0x21f (the root window) (has no name)

  Root window id: 0x21f (the root window) (has no name)
  Parent window id: 0x0 (none)
     2 children:
     0x200002 "Kotton": ("kuid" "kuid")  1200x800+0+0  +0+0
     0x400001 "kuid": ("kuid" "Kuid")  10x10+10+10  +10+10
"#;

    #[test]
    fn the_window_tree_is_read_off_xwininfo() {
        let wins = parse_tree(TREE);
        assert_eq!(
            wins.len(),
            2,
            "both children, and neither of the root's lines"
        );
        assert_eq!(wins[0].id, "0x200002");
        assert_eq!(wins[0].name, "Kotton");
        assert_eq!((wins[0].w, wins[0].h), (1200, 800));
        assert_eq!((wins[0].x, wins[0].y), (0, 0));
        assert_eq!(wins[1].name, "kuid");
        assert_eq!((wins[1].x, wins[1].y), (10, 10));
    }

    /// A window placed off the top left corner is a place, not a parse failure —
    /// `xwininfo` signs the number and keeps the `+` separator.
    #[test]
    fn a_negative_offset_is_a_position() {
        let tree = "     0x200003 (has no name): ()  4x4+-1+-2  +-1+-2\n";
        let wins = parse_tree(tree);
        assert_eq!((wins[0].x, wins[0].y), (-1, -2));
        assert_eq!(
            wins[0].name, "",
            "an unnamed window has no name, not a panic"
        );
    }

    /// **The race this exists for.** winit opens its own 10×10 helper window, named
    /// `kuid`, and for a moment it is the only window on the display. A run that took the
    /// largest window while that was true wrote a 10×10 PNG and called it the desktop
    /// (measured 2026-09-19). Nothing that small is a desktop.
    #[test]
    fn a_winit_helper_window_is_never_the_desktop() {
        let win = largest(parse_tree(TREE)).expect("a window");
        assert_eq!(win.id, "0x200002");
        assert_eq!(win.geometry(), "1200x800+0+0");

        let helper_only = "     0x400001 \"kuid\": (\"kuid\" \"Kuid\")  10x10+10+10  +10+10\n";
        assert_eq!(parse_tree(helper_only).len(), 1, "it is a window");
        assert!(
            largest(parse_tree(helper_only)).is_none(),
            "and it is not a desktop — the run must keep waiting for the real one"
        );
    }

    /// An empty tree is not a window of size zero — it is nothing to photograph, and the
    /// run must keep waiting rather than shoot the bare root.
    #[test]
    fn an_empty_tree_has_no_window() {
        let empty = "xwininfo: Window id: 0x40 (the root window) (has no name)\n\n     \
                     0 children.\n";
        assert!(parse_tree(empty).is_empty());
        assert!(largest(parse_tree(empty)).is_none());
    }

    #[test]
    fn a_png_reports_the_size_in_its_header() {
        let mut png = Vec::from(*b"\x89PNG\r\n\x1a\n");
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&1280u32.to_be_bytes());
        png.extend_from_slice(&800u32.to_be_bytes());
        png.extend_from_slice(&[8, 2, 0, 0, 0]);
        assert_eq!(png_size(&png), Some((1280, 800)));
        assert_eq!(png_size(b"not a png at all, truly not"), None);
        assert_eq!(
            png_size(&png[..20]),
            None,
            "a truncated header is not a size"
        );
    }

    /// The first free number, and `None` rather than a wrong answer when every number in
    /// the range is held — starting a second server on a display that has one is how two
    /// runs photograph each other.
    #[test]
    fn a_display_number_is_the_first_one_free() {
        assert_eq!(free_display(99, 20, |_| false), Some(99));
        assert_eq!(free_display(99, 20, |n| n < 101), Some(101));
        assert_eq!(free_display(99, 20, |_| true), None);
    }
}
