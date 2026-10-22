// SPDX-License-Identifier: AGPL-3.0-or-later
//! Drive a command at a real terminal and answer what it asks.
//!
//! Some of Kotton's credential prompts read the console device directly rather
//! than stdin — deliberately, so a secret never lands in a shell's history, and
//! the reason is written at `prompt_passphrase`. A pipe does not satisfy them:
//! with no terminal `kotton id create` fails with `No such device or address`.
//!
//! **The seam is a terminal, not an environment variable.** A variable holding a
//! passphrase is the shape `connect_as` was written to avoid, and adding one for
//! a caller's convenience puts the credential back in the environment for
//! everybody. This drives the real path rather than a bypass of it: the child
//! gets a controlling terminal, `rpassword` takes it, and what is typed is what a
//! person would type.
//!
//! # Why it is a crate rather than a copy
//!
//! It was written for `tests/tests/suite/common/cli.rs`, which uses it to run the
//! identity ceremony as separate processes
//! (`TASK-no-test-walks-the-cli-the-way-a-person-does`). `cargo xtask seed` needs
//! exactly the same thing and cannot reach a test target, so the choice was one
//! definition here or two that drift. The repository's own rule about a second
//! definition being the beginning of a different product applies to its tools.
//!
//! Its dependency is a **tooling** dependency and must stay one: nothing under
//! `core/` or `client/` may depend on this crate.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// What the child printed, and whether it exited cleanly.
pub struct Transcript {
    /// Everything the child wrote to the terminal, for an assertion message or a
    /// diagnostic. Both streams, because a terminal does not separate them.
    pub text: String,
    /// Whether the process exited successfully.
    pub ok: bool,
    /// Answers that were prepared and never asked for. Non-zero means a prompt
    /// the caller expected did not appear, which is a failure worth reporting
    /// rather than a silent pass.
    pub unasked: usize,
}

/// How long a quiet child is taken to mean *it is waiting for me*.
const QUIET: Duration = Duration::from_millis(400);

/// Run `program` at a pseudo-terminal, typing `answers` as it asks for them.
///
/// `envs` replaces the environment entirely — the child must not reach the
/// caller's real base directory, session cache or daemon — except for `PATH`,
/// which is carried through so the child can find what it needs.
///
/// ## How the answers are timed
///
/// Not by matching the prompt's wording. A caller that knows a prompt's words
/// breaks when somebody improves them. Instead: send the next answer once the
/// child has printed something and then gone quiet, which is what *it is waiting
/// for me* looks like from outside.
pub fn run_on_a_terminal(
    program: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    answers: &[&str],
    timeout: Duration,
) -> Transcript {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    let pair = native_pty_system()
        .openpty(PtySize { rows: 24, cols: 120, pixel_width: 0, pixel_height: 0 })
        .expect("open a pty");

    let mut cmd = CommandBuilder::new(program);
    for a in args {
        cmd.arg(a);
    }
    cmd.env_clear();
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.env("NO_COLOR", "1");
    cmd.env("TERM", "dumb");
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());

    let mut child = pair.slave.spawn_command(cmd).expect("spawn at a terminal");
    // The parent must not keep the child's side open, or the read below never
    // sees EOF when the child exits.
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().expect("read the terminal");
    let mut writer = pair.master.take_writer().expect("type at the terminal");
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let pump = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut text = String::new();
    let mut remaining = answers.iter();
    let deadline = Instant::now() + timeout;
    let mut spoke_since_last_answer = false;
    loop {
        match rx.recv_timeout(QUIET) {
            Ok(chunk) => {
                text.push_str(&String::from_utf8_lossy(&chunk));
                spoke_since_last_answer = true;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if spoke_since_last_answer {
                    if let Some(answer) = remaining.next() {
                        let _ = writeln!(writer, "{answer}");
                        let _ = writer.flush();
                        spoke_since_last_answer = false;
                        continue;
                    }
                }
                if Instant::now() > deadline {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let status = child.wait().expect("wait for the child");
    drop(writer);
    drop(pair.master);
    let _ = pump.join();

    Transcript { text, ok: status.success(), unasked: remaining.count() }
}
