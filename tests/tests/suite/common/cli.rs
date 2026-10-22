// SPDX-License-Identifier: AGPL-3.0-or-later
//! Running a `kotton` subcommand the way a person does: as its own process.
//!
//! ## Why this exists
//!
//! Every other test in this suite drives the daemon through a `KottonClient` the
//! test itself constructed, and usually one that `create_user` has already bound a
//! session to. That is a real path and it was green. It is not the path a person
//! walks, and the difference is not cosmetic:
//!
//! | | the suite, before today | a person |
//! |---|---|---|
//! | Connection | one client, reused across calls | a fresh process per command |
//! | Session | bound to that connection by an earlier call | loaded from disk, or absent |
//! | Daemon | handed to the client as an endpoint | found by computing a path |
//!
//! `TASK-six-id-subcommands-connected-without-a-session` is what lived in that
//! gap: `IdCommand::execute` opened an **unauthenticated** connection for all
//! eleven `id` subcommands, six of which send a request the daemon answers only
//! inside a session. Every one of those six was refused, for months, with a green
//! suite — because `tests/suite/user_lifecycle.rs` calls `add_recovery_phrase` on
//! the client that just ran `create_user`, where the session is already there.
//!
//! ## What a child process needs, and how it gets it
//!
//! Two facts, both from the environment, both of which the child derives rather
//! than being told:
//!
//! - **Which daemon.** `KottonClient::connect()` calls
//!   `daemon_socket_path(kuserd_ipc_name())`. On unix that is
//!   `runtime_dir()/kuserd.sock`, and `runtime_dir()` is `$XDG_RUNTIME_DIR/kotton`,
//!   else `$TMPDIR/kotton`, else `base_dir()/run`. [`Cli`] clears the environment
//!   and sets only `KOTTON_BASE_DIR`, so the third tier applies and the path is
//!   `<base>/run/kuserd.sock` while that fits a socket path. [`discoverable_socket`]
//!   asks the same rule over the same environment rather than writing it out, so the
//!   daemon is put where the child will look.
//! - **Whose session.** `connect_as` reads `<base>/sessions/<user>.session`. In a
//!   real run `id create` or `id unlock` writes it; neither can be driven from a
//!   test, because both prompt through `rpassword`, which reads the console device
//!   directly and by design cannot be piped. So [`seed_session`] writes the file,
//!   which is exactly what `cache_session` does and is the *arrange* step — the
//!   thing under test is what the CLI does with it.
//!
//! ## What is deliberately not faked
//!
//! Stdin is null, so `std::io::stdin().is_terminal()` is false in the child, which
//! is what a script or a CI job gets. That is not a limitation to work around: a
//! command that needs a credential and has no terminal must say so and exit, and
//! `a_command_with_no_session_says_what_to_do` asserts it does.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The `kotton` binary. Bin-only, so it cannot be a dev-dependency of this
/// package — the path comes from `tests/build.rs` and is checked with every other
/// binary the suite runs ([`super::bins`]), so a failure names all that are missing.
pub fn kotton_bin() -> &'static str {
    super::bins::require(super::bins::Bin::Kotton).to_str().expect("build.rs emits a UTF-8 path")
}

/// Where `kotton` will look for the daemon's socket, given `base` as its
/// `KOTTON_BASE_DIR` and nothing else in the environment.
///
/// Asked of the rule the child asks, `kotton_common::paths::kuserd_door_in`,
/// over the environment [`Cli::run`] gives it — not written out here. A copy of tier 3
/// would name `<base>/run/kuserd.sock` even where that does not fit `sun_path` and the
/// child goes to a short `/tmp` path instead; the rule names wherever the child goes
/// (`TASK-two-harnesses-still-derive-a-daemons-door-by-a-copy-of-the-rule`).
/// `NO_COLOR` and `PATH` are left out: neither decides a door.
#[cfg(unix)]
pub fn discoverable_socket(base: &Path) -> PathBuf {
    let base = base.to_str().expect("the test base dir is UTF-8");
    let env = |key: &str| (key == "KOTTON_BASE_DIR").then(|| base.to_string());
    kotton_common::paths::kuserd_door_in(&env).expect("kuserd_door_in")
}

/// The pipe name the child will use, given `KUSERD_IPC_NAME`.
#[cfg(windows)]
pub fn pipe_name(unique: &str) -> String {
    format!("kotton-cli-{unique}")
}

/// Where `kotton` will read `user`'s cached session token from, given `base` as
/// its `KOTTON_BASE_DIR`.
///
/// This harness's one re-derivation of a product rule — mirroring
/// `kotton_common::paths::sessions_dir` and `kotton::session_cache`, which have no
/// form that takes an environment. Held against the real one by
/// `the_session_cache_derivation_matches_the_products`: a copy is safe only while
/// something compares it.
pub fn session_file(base: &Path, user: &str) -> PathBuf {
    base.join("sessions").join(format!("{user}.session"))
}

/// A `kotton` invocation against one test daemon.
pub struct Cli {
    base: PathBuf,
    #[cfg(windows)]
    pipe: String,
}

impl Cli {
    /// Point a CLI at the daemon `TestEnv::spawn_cli_reachable` started.
    pub fn for_env(env: &super::TestEnv) -> Self {
        #[cfg(windows)]
        {
            let pipe = match &env.endpoint {
                kotton_sys::ipc::IpcEndpoint::NamedPipe(p) => p.clone(),
                other => panic!("not a named pipe: {other:?}"),
            };
            Self { base: env.base_dir.clone(), pipe }
        }
        #[cfg(unix)]
        Self { base: env.base_dir.clone() }
    }

    /// Point a CLI at a base directory with **no daemon behind it**.
    ///
    /// Every other constructor here hands the child a daemon to find, because
    /// every other command needs one. `device reset` is the exception by design:
    /// it acts on the base directory and the keychain entries scoped to it, so it
    /// must work for the person whose install will not start — and it *refuses*
    /// while a daemon is up. A harness that always spawns one could only ever
    /// exercise the refusal.
    ///
    /// On Windows the pipe name is one nothing serves, which is the same
    /// condition stated the way that platform states it.
    pub fn for_base(base: &Path) -> Self {
        #[cfg(windows)]
        {
            Self { base: base.to_path_buf(), pipe: pipe_name("no-daemon-listening") }
        }
        #[cfg(unix)]
        Self { base: base.to_path_buf() }
    }

    /// Write the session token `user` would have after `id create` or `id unlock`.
    ///
    /// Both of those prompt through `rpassword` and cannot be driven from a test,
    /// so this writes what they write. It is the arrange step: `connect_as`
    /// presenting this token, and the daemon accepting it, is the behaviour under
    /// test — not the writing of the file.
    ///
    /// Taking the token from `env.client.session_token` rather than minting one
    /// keeps it a real token from this daemon; a made-up one would be refused and
    /// the test would pass for the wrong reason.
    pub fn seed_session(&self, user: &str, token: &str) {
        let path = session_file(&self.base, user);
        std::fs::create_dir_all(path.parent().expect("sessions dir")).expect("create sessions dir");
        std::fs::write(path, token).expect("write session token");
    }

    /// Run `kotton <args...>` and return what it did.
    ///
    /// The environment is **cleared** rather than inherited, so the child cannot
    /// reach the developer's real base dir, real session cache, or real daemon —
    /// and so `runtime_dir()` falls to the tier this harness derives against
    /// (see the module docs).
    pub fn run(&self, args: &[&str]) -> Output {
        self.run_with_env(args, &[])
    }

    /// [`Cli::run`] with extra variables in the child's environment, set on top of
    /// the cleared one: for a command whose behaviour is a variable a person sets
    /// in their shell, such as `KOTTON_USER`.
    pub fn run_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(kotton_bin());
        cmd.args(args)
            .env_clear()
            .envs(env.iter().copied())
            .env("KOTTON_BASE_DIR", &self.base)
            .env("NO_COLOR", "1")
            // Not for the binary — it is invoked by absolute path — but some
            // platform crates shell out, and an empty PATH fails them obscurely.
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            // Null, not inherited: a CLI with no terminal must say so rather than
            // block on a prompt nobody can answer. See the module docs.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        cmd.env("KUSERD_IPC_NAME", &self.pipe);
        cmd.output().expect("run the kotton CLI")
    }
}

impl Cli {
    /// Start `kotton <args…>` with its stdin, stdout and stderr on pipes the
    /// caller holds, and return without waiting for it.
    ///
    /// For a command whose answer does not exist when it starts: the six
    /// digits a `device admit` asks for are derived only once its ceremony
    /// meets the other side, and are shown to someone else, who reads them
    /// out. [`Cli::run_on_a_terminal`] types answers prepared beforehand, so
    /// it cannot type these; this lets the caller write them when they have
    /// been shown. The shell's six-digit prompt reads stdin as a line, so a
    /// pipe is typed into exactly as a terminal is. The environment is the
    /// one [`Cli::run`] gives.
    pub fn spawn_on_pipes(&self, args: &[&str]) -> std::process::Child {
        let mut cmd = Command::new(kotton_bin());
        cmd.args(args)
            .env_clear()
            .env("KOTTON_BASE_DIR", &self.base)
            .env("NO_COLOR", "1")
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        cmd.env("KUSERD_IPC_NAME", &self.pipe);
        cmd.spawn().expect("start the kotton CLI")
    }
}

/// A `kotton` run driven through a real terminal, and everything it wrote back.
///
/// One stream, because a pty is one device: the child cannot tell its stdout from
/// its stderr on a terminal either, and neither can a person.
pub struct Session {
    pub transcript: String,
    pub ok: bool,
}

impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exited {}\n--- terminal ---\n{}",
            if self.ok { "0" } else { "non-zero" },
            self.transcript
        )
    }
}

impl Cli {
    /// Run `kotton <args…>` **with a terminal on its stdio**, answering each
    /// prompt in turn with the strings given.
    ///
    /// ## Why this exists
    ///
    /// `id create`, `id unlock`, `id set-passphrase`, `id bind-device`,
    /// `id rotate` and `id recover` read their credential through `rpassword`,
    /// which opens `/dev/tty` and puts it in raw mode rather than reading stdin.
    /// That is deliberate — it is what keeps a passphrase out of a shell's
    /// history and out of the process list — and it means [`Cli::run`], which
    /// gives the child a null stdin, cannot reach half of the identity ceremony.
    /// Until 2026-09-12 that half had no test at all
    /// (`TASK-no-test-walks-the-cli-the-way-a-person-does`).
    ///
    /// **The seam is a terminal, not an environment variable.** A variable
    /// holding a passphrase would be the shape `connect_as` was written to avoid,
    /// and adding one for a test puts the credential back in the environment for
    /// everybody. This drives the real path rather than a bypass of it: the child
    /// gets a controlling terminal, `rpassword` takes it, and what is typed is
    /// what a person would type.
    ///
    /// ## How the answers are timed
    ///
    /// Not by matching the prompt's wording. This suite tests behaviour and not
    /// copy, and a test that knows a prompt's words goes red when somebody
    /// improves them. Instead: send the next answer once the child has printed
    /// something and then gone quiet, which is what *it is waiting for me* looks
    /// like from outside. An answer nobody asked for is a prompt that never came,
    /// and that fails loudly rather than passing quietly.
    pub fn run_on_a_terminal(&self, args: &[&str], answers: &[&str]) -> Session {
        // The mechanism lives in `kotton-pty-drive` so this suite and
        // `cargo xtask seed` share one definition — the seeder needs exactly this
        // and cannot reach a test target. What stays here is the part that is
        // this suite's: which environment the child gets, and turning an unasked
        // answer into a failed assertion.
        let base = ("KOTTON_BASE_DIR", self.base.to_str().unwrap_or_default());
        #[cfg(windows)]
        let envs: Vec<(&str, &str)> = vec![base, ("KUSERD_IPC_NAME", self.pipe.as_str())];
        #[cfg(not(windows))]
        let envs: Vec<(&str, &str)> = vec![base];

        let t = kotton_pty_drive::run_on_a_terminal(
            std::path::Path::new(kotton_bin()),
            args,
            &envs,
            answers,
            std::time::Duration::from_secs(30),
        );
        assert_eq!(
            t.unasked, 0,
            "{} answer(s) were never asked for — a prompt this test expected did not \
             appear.\n--- terminal ---\n{}",
            t.unasked, t.text
        );
        Session { transcript: t.text, ok: t.ok }
    }
}

/// Everything the child printed, both streams, for an assertion message.
pub fn said(out: &Output) -> String {
    format!(
        "status: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
