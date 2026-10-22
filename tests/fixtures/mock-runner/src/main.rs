// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mock `kotton-runner` binary used by integration tests.
//!
//! Reads JSON frames from stdin and writes [`RunnerOutput`] JSON lines to
//! stdout, then flushes. Behaviour is controlled by `MOCK_RUNNER_MODE`:
//!
//! | Mode      | Behaviour                                              |
//! |-----------|--------------------------------------------------------|
//! | (default) | Responds based on the op type (see below)              |
//! | `error`   | Always writes `RunnerOutput::Error`                    |
//! | `exit`    | Exits immediately without writing any output           |
//! | `probe-socket` | Tries to open a TCP socket, then exits 2 (it could, even if nothing answered), 3 (refused) or 4 (something else) — never 0, which is what a binary that does not know this mode exits with. Reads nothing and writes nothing. |
//! | `report-socket` | Reads its launch frame like any launch, tries a TCP socket, and paints the verdict — `{"socket":"opened"}`, `"refused"` or `"other: …"` — as the launch's patch. One-shot and long-lived. |
//! | `two-surfaces`  | Asks for one more surface, then paints both     |
//! | `surface-storm` | Asks for surfaces until the daemon says no      |
//! | `surface-then-fail` | Asks for one more surface, then fails init  |
//! | `window-list` | Asks for the window list, asks for window 1 back, paints the list |
//! | `window-nudge` | Launches like the default; on each message, asks for the window list and paints the message it was sent beside the list it was then told |
//! | `window-nudge-reaches` | As `window-nudge`, and also answers each message by asking to launch `sh.kotton.editor` and to raise its own surface |
//! | `panels`       | Asks for a top panel, a bottom panel and a window, then gives the window back |
//! | `report-input` | Paints what the launch frame gave it: mount, designation, approvals, launch args |
//!
//! The last two exist for RFC-0087 stage 2 and are long-lived only: asking for a
//! surface is a **blocked host call** — the runner writes a
//! `RunnerOutput::HostCall` and waits for the daemon's `RunnerOp::HostReply` —
//! and one-shot mode reads stdin to EOF before answering, so there is no channel
//! for a reply to arrive on. That is a property of the real runner too, and the
//! real runner says so rather than hanging.
//!
//! Default per-op responses:
//! - `Launch`    → `Launched { patches: [] }`
//! - `Message`   → `MessageHandled { patches: [<counter as raw-json patch>] }`
//! - `Terminate` → `MessageHandled { patches: [] }` then exits cleanly
//!
//! A monotonically-increasing per-process counter is included in
//! `MessageHandled` responses so tests can verify subprocess reuse.
//!
//! Flags:
//!   `--long-lived`   reads frames in a loop (init frame + message frames);
//!                    exits cleanly on EOF.

use kotton_wire::runner::{
    RunnerHostCall, RunnerHostReply, RunnerSurfaceVerb, SurfacePatch,
};
use kotton_wire::{RunnerInput, RunnerMessage, RunnerOp, RunnerOutput, SurfaceHandle, SurfaceRole};
use std::io::{self, BufRead, Write};

/// The surface this mock paints on.
///
/// **The mock is not the real runner**: it never loads a component, never calls
/// `on-launch`, and has no resource table, so it has no `surface` resource to
/// read a handle off. What it has is the handle the daemon minted and put on the
/// launch op, which `main` remembers — and, for a frame that carries none, one
/// minted here so the output is still a well-formed `SurfacePatch` rather than a
/// patch addressed to nothing. A real guest cannot do that second thing and does
/// not need to (RFC-0087).
/// The handle a launch op carries, or a fresh one for an op that carries none.
fn surface_of(op: &RunnerOp) -> kotton_wire::SurfaceHandle {
    match op {
        RunnerOp::Launch { surface, .. } => *surface,
        _ => kotton_wire::SurfaceHandle::mint(),
    }
}

fn respond(
    op: &RunnerOp,
    mode: &str,
    counter: u32,
    surface: kotton_wire::SurfaceHandle,
) -> Option<RunnerOutput> {
    match mode {
        "exit" => {
            std::process::exit(0);
        }
        "error" => Some(RunnerOutput::Error {
            message: "mock error".to_string(),
        }),
        // **Whether the process the daemon spawned may open a socket**, said
        // back on the one channel a launch has. `probe-socket` answers the same
        // question with an exit code and reads nothing, which suits a test that
        // spawns the process itself; this one is for a test that goes through
        // `app_launch`, where the daemon writes a frame first and reads one back,
        // so the probe has to take the frame and answer it like a runner would.
        "report-socket" if matches!(op, RunnerOp::Launch { .. }) => {
            let report = serde_json::json!({ "socket": try_a_socket() });
            let mut patch = vec![0x00u8];
            patch.extend_from_slice(report.to_string().as_bytes());
            Some(RunnerOutput::Launched {
                patches: vec![SurfacePatch { surface, patch }],
                launches: vec![],
                raises: vec![],
            })
        }
        _ => Some(match op {
            RunnerOp::Launch { .. } => RunnerOutput::Launched {
                patches: vec![],
                launches: vec![],
                raises: vec![],
            },
            RunnerOp::Message { .. } => {
                // Encode counter as a raw JSON patch (format version 0x00).
                let json = format!("\"counter:{counter}\"");
                let mut patch = vec![0x00u8];
                patch.extend_from_slice(json.as_bytes());
                RunnerOutput::MessageHandled {
                    // A patch names its surface (RFC-0087 stage 2). See `respond`.
                    patches: vec![SurfacePatch { surface, patch }],
                    launches: vec![],
                    raises: vec![],
                }
            }
            RunnerOp::Input { .. } => RunnerOutput::InputHandled {
                patches: vec![],
                launches: vec![],
                raises: vec![],
            },
            RunnerOp::Terminate => RunnerOutput::MessageHandled {
                patches: vec![],
                launches: vec![],
                raises: vec![],
            },
            RunnerOp::SurfaceError { .. } => RunnerOutput::SurfaceErrorHandled,
            // Extension ops (RFC-0049). The mock stands in for an *app* runner;
            // a fetch cycle here is a no-op that wrote nothing, and a host
            // reply arriving with no fetch in flight is a protocol error rather
            // than something to absorb silently.
            RunnerOp::Fetch { .. } => RunnerOutput::Fetched { wrote: vec![] },
            RunnerOp::HostReply { .. } => RunnerOutput::Error {
                message: "host reply with no fetch in flight".to_string(),
            },
        }),
    }
}

/// Ask the daemon for one more surface, and read its answer.
///
/// The blocked-call shape RFC-0087 stage 2 puts `create-surface` on: a frame out,
/// a reply in, on the same wire the ops arrive on. `Ok(None)` is the daemon
/// refusing — the per-instance cap — which is an answer and not an error.
fn ask_for_a_surface(
    out: &mut impl Write,
    lines: &mut impl Iterator<Item = io::Result<String>>,
) -> Result<Option<SurfaceHandle>, String> {
    write_response(
        out,
        RunnerOutput::HostCall {
            call: RunnerHostCall::Surface {
                verb: RunnerSurfaceVerb::Create {
                    role: SurfaceRole::Window,
                    edge: None,
                    width: 640,
                    height: 480,
                },
            },
        },
    );
    let Some(Ok(line)) = lines.next() else {
        return Err("no reply to a surface call".to_string());
    };
    match serde_json::from_str::<RunnerMessage>(line.trim()).map(|m| m.op) {
        Ok(RunnerOp::HostReply {
            reply: RunnerHostReply::SurfaceCreated { handle },
        }) => Ok(Some(handle)),
        Ok(RunnerOp::HostReply {
            reply: RunnerHostReply::SurfaceFailed { .. },
        }) => Ok(None),
        other => Err(format!("unexpected reply to a surface call: {other:?}")),
    }
}

/// Ask the daemon for one pinned surface, on a named screen edge.
///
/// The designated app's half of RFC-0087 stage 3c. The edge is an **anchor**: the guest says
/// which side it belongs to and the host decides the span, the offset and the band it
/// reserves. `Ok(None)` is the daemon refusing, which is an answer and not an error.
fn ask_for_a_panel(
    out: &mut impl Write,
    lines: &mut impl Iterator<Item = io::Result<String>>,
    edge: kotton_wire::PanelEdge,
    height: u32,
) -> Result<Option<SurfaceHandle>, String> {
    write_response(
        out,
        RunnerOutput::HostCall {
            call: RunnerHostCall::Surface {
                verb: RunnerSurfaceVerb::Create {
                    role: SurfaceRole::Panel,
                    edge: Some(edge),
                    width: 4096,
                    height,
                },
            },
        },
    );
    let Some(Ok(line)) = lines.next() else {
        return Err("no reply to a panel call".to_string());
    };
    match serde_json::from_str::<RunnerMessage>(line.trim()).map(|m| m.op) {
        Ok(RunnerOp::HostReply {
            reply: RunnerHostReply::SurfaceCreated { handle },
        }) => Ok(Some(handle)),
        Ok(RunnerOp::HostReply {
            reply: RunnerHostReply::SurfaceFailed { .. },
        }) => Ok(None),
        other => Err(format!("unexpected reply to a panel call: {other:?}")),
    }
}

/// Give a surface back, and read whether the daemon took it.
///
/// `surface.close` was a stub until RFC-0087 stage 3c — it logged and answered `ok` — so a
/// guest that gave a window back was still charged for it against the per-instance cap.
fn give_a_surface_back(
    out: &mut impl Write,
    lines: &mut impl Iterator<Item = io::Result<String>>,
    surface: SurfaceHandle,
) -> Result<bool, String> {
    write_response(
        out,
        RunnerOutput::HostCall {
            call: RunnerHostCall::Surface {
                verb: RunnerSurfaceVerb::Close { surface },
            },
        },
    );
    let Some(Ok(line)) = lines.next() else {
        return Err("no reply to a close call".to_string());
    };
    match serde_json::from_str::<RunnerMessage>(line.trim()).map(|m| m.op) {
        Ok(RunnerOp::HostReply {
            reply: RunnerHostReply::SurfaceReleased,
        }) => Ok(true),
        Ok(RunnerOp::HostReply {
            reply: RunnerHostReply::SurfaceFailed { .. },
        }) => Ok(false),
        other => Err(format!("unexpected reply to a close call: {other:?}")),
    }
}

/// Ask the daemon for the window list, and for the first window in it back.
///
/// The designated app's half of RFC-0087 stage 3b, on the same blocked-call wire
/// `create-surface` uses. What comes back is painted as a patch, so a test can read
/// what the guest was actually told rather than what the host meant to say.
fn ask_about_the_windows(
    out: &mut impl Write,
    lines: &mut impl Iterator<Item = io::Result<String>>,
) -> Result<String, String> {
    write_response(
        out,
        RunnerOutput::HostCall {
            call: RunnerHostCall::Surface {
                verb: RunnerSurfaceVerb::ListWindows,
            },
        },
    );
    let Some(Ok(line)) = lines.next() else {
        return Err("no reply to a window-list call".to_string());
    };
    let windows = match serde_json::from_str::<RunnerMessage>(line.trim()).map(|m| m.op) {
        Ok(RunnerOp::HostReply {
            reply: RunnerHostReply::SurfaceWindows { windows },
        }) => windows,
        other => return Err(format!("unexpected reply to a window-list call: {other:?}")),
    };

    // Ask for the first one back, and for one that does not exist — a designated app
    // holding an id it was never given must be told no, not handed somebody's window.
    let mut asks = windows.first().map(|w| w.id).into_iter().collect::<Vec<_>>();
    asks.push(9_999);
    let mut refused = Vec::new();
    for id in asks {
        write_response(
            out,
            RunnerOutput::HostCall {
                call: RunnerHostCall::Surface {
                    verb: RunnerSurfaceVerb::RaiseWindow { window: id },
                },
            },
        );
        let Some(Ok(line)) = lines.next() else {
            return Err("no reply to a raise-window call".to_string());
        };
        match serde_json::from_str::<RunnerMessage>(line.trim()).map(|m| m.op) {
            Ok(RunnerOp::HostReply {
                reply: RunnerHostReply::SurfaceRaised,
            }) => {}
            Ok(RunnerOp::HostReply {
                reply: RunnerHostReply::SurfaceFailed { .. },
            }) => refused.push(id),
            other => return Err(format!("unexpected reply to a raise-window call: {other:?}")),
        }
    }

    serde_json::to_string(&serde_json::json!({
        "windows": windows,
        "refused": refused,
    }))
    .map_err(|e| e.to_string())
}

/// Ask the daemon for the window list and nothing else.
fn list_the_windows(
    out: &mut impl Write,
    lines: &mut impl Iterator<Item = io::Result<String>>,
) -> Result<Vec<kotton_wire::WindowView>, String> {
    write_response(
        out,
        RunnerOutput::HostCall {
            call: RunnerHostCall::Surface {
                verb: RunnerSurfaceVerb::ListWindows,
            },
        },
    );
    let Some(Ok(line)) = lines.next() else {
        return Err("no reply to a window-list call".to_string());
    };
    match serde_json::from_str::<RunnerMessage>(line.trim()).map(|m| m.op) {
        Ok(RunnerOp::HostReply {
            reply: RunnerHostReply::SurfaceWindows { windows },
        }) => Ok(windows),
        other => Err(format!("unexpected reply to a window-list call: {other:?}")),
    }
}

/// One patch per surface, each naming its own, so a test can see where each went.
fn paint_each(surfaces: &[SurfaceHandle]) -> Vec<SurfacePatch> {
    surfaces
        .iter()
        .enumerate()
        .map(|(i, &surface)| {
            let json = format!("\"surface:{i}\"");
            let mut patch = vec![0x00u8];
            patch.extend_from_slice(json.as_bytes());
            SurfacePatch { surface, patch }
        })
        .collect()
}

/// Ask the kernel for a TCP socket, and say what it answered.
///
/// `"opened"` when `socket(2)` succeeded — a refused *connection* included,
/// because that is a socket the kernel made and carried a SYN for; `"refused"`
/// when the kernel would not make one; anything else verbatim. Port 9 is
/// discard and nothing listens on it here. Shared by `probe-socket` and
/// `report-socket`, which differ only in how they say the answer.
fn try_a_socket() -> String {
    match std::net::TcpStream::connect("127.0.0.1:9") {
        Ok(_) => "opened".to_string(),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => "opened".to_string(),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => "refused".to_string(),
        Err(e) => format!("other: {e} ({:?})", e.kind()),
    }
}

fn write_response(out: &mut impl Write, response: RunnerOutput) {
    let json = serde_json::to_string(&response).expect("serialize RunnerOutput");
    writeln!(out, "{json}").expect("write response");
    out.flush().expect("flush");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let long_lived = args.contains(&"--long-lived".to_string());
    let mode = std::env::var("MOCK_RUNNER_MODE").unwrap_or_default();

    // Before any frame is read, because the question this answers is what a
    // runner process may do *while the guest inside it is doing nothing at
    // all* — the phrasing of
    // `TASK-the-wasm-runner-is-confined-only-by-wasmtime`'s Done-when. A guest
    // has not been loaded, let alone run: what is being measured is the
    // process the daemon spawned, before WASM enters into it.
    if mode == "probe-socket" {
        // Port 9 is discard and nothing listens on it here. The refusal being
        // looked for happens at `socket(2)`, before an address is used.
        //
        // Not 0 for "it could": 0 is also what a mock runner built before this
        // mode existed exits with, reading an empty stdin, and a stale binary
        // must read as a broken probe rather than as an open socket.
        //
        // A refused *connection* is an opened socket: `socket(2)` succeeded and
        // the kernel carried a SYN to a port nobody listens on. Measured on the
        // landing, 2026-09-23, with the confinement deleted: the probe reported
        // `ConnectionRefused`, which this used to file under "something else",
        // so an unconfined runner failed the test as a broken probe rather than
        // as the open socket it was.
        let code = match try_a_socket().as_str() {
            "opened" => 2,
            "refused" => 3,
            other => {
                eprintln!("probe-socket: {other}");
                4
            }
        };
        std::process::exit(code);
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    let mut counter = 0u32;

    if !long_lived {
        // ── One-shot mode ────────────────────────────────────────────────────
        // Read one RunnerInput line, write one RunnerOutput line, exit.
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).expect("read_line") == 0 {
            return; // EOF before any input — exit cleanly
        }
        if mode == "exit" {
            std::process::exit(0);
        }
        if mode == "hang" {
            // Simulate a runaway guest that never returns. The daemon's deadline
            // must kill us (audit H7). Sleep well past any test deadline.
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
        let op = serde_json::from_str::<RunnerInput>(line.trim())
            .map(|r| r.op)
            .unwrap_or(RunnerOp::Launch {
                launch_args: vec![],
                // A frame this mock could not parse. The handle is minted here
                // so the fallback is a *valid* launch rather than a launch with
                // no surface: the mock never draws, so which surface it is does
                // not matter, and a surface-less launch is not a thing the
                // protocol can express (RFC-0087).
                surface: kotton_wire::SurfaceHandle::mint(),
            });
        counter += 1;
        if let Some(resp) = respond(&op, &mode, counter, surface_of(&op)) {
            write_response(&mut out, resp);
        }
    } else {
        // ── Long-lived mode ──────────────────────────────────────────────────
        // First line is a full RunnerInput; subsequent lines are RunnerMessage.
        // Exit cleanly on EOF.
        let mut lines = stdin.lock().lines();

        // Init frame.
        let Some(Ok(init_line)) = lines.next() else {
            return;
        };
        if mode == "exit" {
            std::process::exit(0);
        }
        let op = serde_json::from_str::<RunnerInput>(&init_line)
            .map(|r| r.op)
            .unwrap_or(RunnerOp::Launch {
                launch_args: vec![],
                // A frame this mock could not parse. The handle is minted here
                // so the fallback is a *valid* launch rather than a launch with
                // no surface: the mock never draws, so which surface it is does
                // not matter, and a surface-less launch is not a thing the
                // protocol can express (RFC-0087).
                surface: kotton_wire::SurfaceHandle::mint(),
            });
        // The handle the daemon minted for this instance, remembered so the
        // message frames below can name it — they carry none of their own.
        let surface = surface_of(&op);
        counter += 1;
        // RFC-0087 stage 2: ask for more surfaces before answering the launch.
        // Written here rather than in `respond` because a host call is an
        // exchange — a frame out and a reply in — and `respond` holds neither
        // half of the wire.
        if matches!(op, RunnerOp::Launch { .. }) && mode == "window-list" {
            match ask_about_the_windows(&mut out, &mut lines) {
                Ok(report) => {
                    let mut patch = vec![0x00u8];
                    patch.extend_from_slice(report.as_bytes());
                    write_response(
                        &mut out,
                        RunnerOutput::Launched {
                            patches: vec![SurfacePatch { surface, patch }],
                            launches: vec![],
                            raises: vec![],
                        },
                    );
                }
                Err(message) => write_response(&mut out, RunnerOutput::Error { message }),
            }
            return;
        }
        // RFC-0087 stage 3c: the shape the designated app actually takes — a strip on each
        // screen edge, a window, and the window given back when the person is done with it.
        if matches!(op, RunnerOp::Launch { .. }) && mode == "panels" {
            let mut report = serde_json::Map::new();
            let steps = [
                ("top", kotton_wire::PanelEdge::Top, 40u32),
                ("bottom", kotton_wire::PanelEdge::Bottom, 64u32),
            ];
            for (name, edge, height) in steps {
                match ask_for_a_panel(&mut out, &mut lines, edge, height) {
                    Ok(Some(_)) => {
                        report.insert(name.to_string(), serde_json::Value::Bool(true));
                    }
                    Ok(None) => {
                        report.insert(name.to_string(), serde_json::Value::Bool(false));
                    }
                    Err(message) => {
                        write_response(&mut out, RunnerOutput::Error { message });
                        return;
                    }
                }
            }
            let window = match ask_for_a_surface(&mut out, &mut lines) {
                Ok(Some(handle)) => handle,
                Ok(None) => {
                    write_response(
                        &mut out,
                        RunnerOutput::Error {
                            message: "mock: the daemon refused a window".to_string(),
                        },
                    );
                    return;
                }
                Err(message) => {
                    write_response(&mut out, RunnerOutput::Error { message });
                    return;
                }
            };
            match give_a_surface_back(&mut out, &mut lines, window) {
                Ok(took) => {
                    report.insert("closed".to_string(), serde_json::Value::Bool(took));
                }
                Err(message) => {
                    write_response(&mut out, RunnerOutput::Error { message });
                    return;
                }
            }
            // Giving the same one back twice must be refused: it is not held any more.
            match give_a_surface_back(&mut out, &mut lines, window) {
                Ok(took) => {
                    report.insert("closed_twice".to_string(), serde_json::Value::Bool(took));
                }
                Err(message) => {
                    write_response(&mut out, RunnerOutput::Error { message });
                    return;
                }
            }
            let json = serde_json::to_string(&serde_json::Value::Object(report))
                .expect("serialize the panel report");
            let mut patch = vec![0x00u8];
            patch.extend_from_slice(json.as_bytes());
            write_response(
                &mut out,
                RunnerOutput::Launched {
                    patches: vec![SurfacePatch { surface, patch }],
                    launches: vec![],
                    raises: vec![],
                },
            );
            return;
        }
        if matches!(op, RunnerOp::Launch { .. })
            && (mode == "two-surfaces" || mode == "surface-storm" || mode == "surface-then-fail")
        {
            let mut held = vec![surface];
            // Far past any plausible cap, so `surface-storm` finds it rather than
            // assuming a number. The other two modes ask exactly once.
            let asks = if mode == "surface-storm" { 64 } else { 1 };
            for _ in 0..asks {
                match ask_for_a_surface(&mut out, &mut lines) {
                    Ok(Some(handle)) => held.push(handle),
                    // The cap. Stop asking and paint what we hold — a guest told
                    // "no more" has been answered, not broken.
                    Ok(None) => break,
                    Err(message) => {
                        write_response(&mut out, RunnerOutput::Error { message });
                        return;
                    }
                }
            }
            if mode == "surface-then-fail" {
                // A launch that got a surface and *then* failed. The daemon has
                // opened two by now — the one it minted for this instance and
                // the one this asked for — and both have to come back down.
                write_response(
                    &mut out,
                    RunnerOutput::Error {
                        message: "mock: asked for a surface, then failed".to_string(),
                    },
                );
                return;
            }
            write_response(
                &mut out,
                RunnerOutput::Launched {
                    patches: paint_each(&held),
                    launches: vec![],
                    raises: vec![],
                },
            );
            return;
        }
        // **What the daemon handed this instance, said back.**
        //
        // The one thing about a launch that no other frame reveals: the mount,
        // the designation and the launch arguments are decided by the host, sent
        // once in the init frame, and never mentioned again. A test that wants
        // to know whether the shell a person is looking at was given their data
        // has nowhere else to read it from — `UserResponse::AppLaunched` carries
        // patches, so the patch is the channel.
        //
        // It stays in the loop afterwards rather than returning, so the instance
        // is alive when the daemon stores it, exactly as a default-mode launch is.
        if mode == "report-input" && matches!(op, RunnerOp::Launch { .. }) {
            let launch_args = match &op {
                RunnerOp::Launch { launch_args, .. } => launch_args.clone(),
                _ => vec![],
            };
            let input: Option<RunnerInput> = serde_json::from_str(&init_line).ok();
            let report = serde_json::json!({
                "user_vfs_path": input.as_ref().and_then(|i| i.user_vfs_path.clone()),
                "occupant": input.as_ref().map(|i| i.occupant),
                "approved": input.as_ref().map(|i| i.approved.len()),
                "launch_args": launch_args,
            });
            let mut patch = vec![0x00u8];
            patch.extend_from_slice(report.to_string().as_bytes());
            write_response(
                &mut out,
                RunnerOutput::Launched {
                    patches: vec![SurfacePatch { surface, patch }],
                    launches: vec![],
                    raises: vec![],
                },
            );
        } else if let Some(resp) = respond(&op, &mode, counter, surface) {
            write_response(&mut out, resp);
        }

        // Subsequent message frames. `while let` rather than `for`, so a mode that
        // answers a message with a host call can still read the reply off `lines`.
        while let Some(result) = lines.next() {
            let line = match result {
                Ok(l) => l,
                Err(_) => break,
            };
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            if mode == "exit" {
                std::process::exit(0);
            }
            let op = serde_json::from_str::<RunnerMessage>(&line)
                .map(|m| m.op)
                .unwrap_or(RunnerOp::Message { msg: String::new() });
            let should_exit = matches!(op, RunnerOp::Terminate);
            counter += 1;
            // `TASK-the-docks-window-list-is-as-stale-as-its-last-repaint`: what a dock
            // does when the host nudges it — asks for the list again — with what it was
            // sent and what it was then told painted side by side, so a test can hold
            // the nudge to carrying nothing and the list to being fresh.
            if mode == "window-nudge" || mode == "window-nudge-reaches" {
                if let RunnerOp::Message { msg } = &op {
                    let resp = match list_the_windows(&mut out, &mut lines) {
                        Ok(windows) => {
                            let report = serde_json::json!({ "msg": msg, "windows": windows });
                            let mut patch = vec![0x00u8];
                            patch.extend_from_slice(report.to_string().as_bytes());
                            // `window-nudge-reaches`: an app that answers *ask again* by
                            // reaching for a gesture nobody made. The daemon must serve the
                            // patch and neither of these.
                            let reaches = mode == "window-nudge-reaches";
                            RunnerOutput::MessageHandled {
                                patches: vec![SurfacePatch { surface, patch }],
                                launches: if reaches {
                                    vec![kotton_wire::runner::LaunchRequest {
                                        app_nsid: "sh.kotton.editor".to_string(),
                                        name: None,
                                        args: vec![],
                                    }]
                                } else {
                                    vec![]
                                },
                                raises: if reaches { vec![surface] } else { vec![] },
                            }
                        }
                        Err(message) => RunnerOutput::Error { message },
                    };
                    write_response(&mut out, resp);
                    continue;
                }
            }
            if let Some(resp) = respond(&op, &mode, counter, surface) {
                write_response(&mut out, resp);
            }
            if should_exit {
                return; // clean shutdown after Terminate
            }
        }
    }
}
