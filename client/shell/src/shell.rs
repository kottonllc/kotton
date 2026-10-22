// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use colored::Colorize;
use kotton::KottonClient;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::commands::ExitCode;
use crate::completion::KottonCompleter;
use crate::executor::ShellExecutor;
use crate::state::ShellState;
use crate::ui;

/// Interactive shell session
pub struct Shell {
    user_id: String,
    executor: ShellExecutor,
}

impl Shell {
    /// Create a shell for a user. Authentication is handled automatically
    /// via the session cache (see `KottonClient::connect_as`).
    pub fn new(user_id: String) -> Self {
        Self { user_id, executor: ShellExecutor::new() }
    }

    /// Run on `executor` rather than the bare shell's — the REPL passes one that also
    /// names the one-shot form of every `kotton` verb it does not run.
    pub fn with_executor(mut self, executor: ShellExecutor) -> Self {
        self.executor = executor;
        self
    }

    /// Start the interactive shell loop.
    pub async fn start(self) -> Result<()> {
        self.run_shell_loop().await
    }
}

/// Display label for the node this runtime is attached to. Set by the two-node
/// harness (`KOTTON_NODE_LABEL`); falls back to the daemon's IPC name, then `local`.
fn node_label() -> String {
    std::env::var("KOTTON_NODE_LABEL")
        .or_else(|_| std::env::var("KUSERD_IPC_NAME"))
        .unwrap_or_else(|_| "local".to_string())
}

/// Shorten a `did:key:…` for display: `did:key:z6Mk1Q…8x2P`.
fn short_did(did: &str) -> String {
    if let Some(rest) = did.strip_prefix("did:key:") {
        if rest.len() > 14 {
            return format!("did:key:{}…{}", &rest[..6], &rest[rest.len() - 4..]);
        }
    }
    did.to_string()
}

/// The post-login context block: which node you're on and what's reachable, plus
/// the help/exit hint. The `Kotton` wordmark + greeting live in `onboard` (shown
/// once, before sign-in); this is just your standing context. (TERMINAL-RUNTIME-PIVOT.)
fn print_entry(node: &str, node_did: Option<&str>, peer_count: usize) {
    let did = node_did.map(short_did).unwrap_or_else(|| "—".to_string());
    let peers = match peer_count {
        0 => "no peers yet".to_string(),
        1 => "1 paired".to_string(),
        n => format!("{n} paired"),
    };

    ui::blank();
    ui::row("node", ui::notable(node), Some(&did));
    ui::row("peers", peers.dimmed(), None);
    ui::blank();
    ui::hint("`help` for commands · `exit` to leave");
    ui::blank();
}

/// The runtime prompt, identity-first: `user@node cwd $`. A non-zero exit code
/// from the last command shows in red before the marker.
///
/// Returns `(plain, colored)`. rustyline is given the **plain** prompt so it
/// measures the cursor column correctly (the Windows console width calc counts
/// ANSI escape bytes); the **colored** prompt is shown via `highlight_prompt`.
/// Both share the exact same visible layout so the two never disagree.
fn branded_prompt(node: &str, user_id: &str, cwd: &str, last_exit: i32) -> (String, String) {
    let plain = if last_exit == 0 {
        format!("{user_id}@{node} {cwd} $ ")
    } else {
        format!("{user_id}@{node} {cwd} [{last_exit}] $ ")
    };
    let status = if last_exit == 0 {
        String::new()
    } else {
        format!("{} ", format!("[{last_exit}]").red())
    };
    // Tonal hierarchy (identity-first, per the pivot): who-you-are is the standing
    // context, so the identity takes the notable tier; the node recedes after the
    // `@`; cwd is dim chrome; the `$` is the only saturated green (the "type here"
    // action). The `user@node` shape is instantly parseable by any terminal user.
    let colored = format!(
        "{}{}{} {} {}{} ",
        ui::notable(user_id),
        "@".dimmed(),
        node.dimmed(),
        cwd.dimmed(),
        status,
        ui::action("$").bold(),
    );
    (plain, colored)
}

/// Identity-first onboarding for `kotton repl` launched with no user name — you
/// ARE your key. Enter your key: if it matches an identity on this machine you're
/// in; if not, name it to set it up here; press Enter with no key to create a
/// brand-new identity (and back up the words). Returns the resolved user id — the
/// session is cached, so the REPL connects without prompting again.
///
/// Enter with no key also offers to join an identity from another device, the
/// question form of `kotton id join <name> [code]`.
///
/// Resolve who the runtime runs as. `Some(user_id)` → start the runtime as that
/// identity; `None` → a terminal onboarding action completed (e.g. joining a
/// device, which provisions the machine but doesn't yet open an interactive
/// session) and the caller should exit cleanly without starting a shell.
pub async fn onboard() -> anyhow::Result<Option<String>> {
    ui::blank();
    ui::header("Kotton", "your sovereign runtime");
    ui::blank();

    let key = crate::secret::read_hidden("enter your key, or Enter for a new identity")?;
    let key = key.trim().to_string();

    let mut client = KottonClient::connect()
        .await
        .map_err(|e| anyhow::anyhow!("could not reach the daemon (is it running?): {e}"))?;

    if key.is_empty() {
        return setup_machine(&mut client).await;
    }

    // Your key derives your DID locally; we look for a matching identity here.
    match client.login_with_recovery_key(&key, None, None).await {
        Ok((user_id, _)) => {
            ui::greet("welcome back,", &user_id);
            kotton::active_identity::initialise(&user_id);
            Ok(Some(user_id))
        }
        Err(_) => {
            // Valid key, but no identity with this DID is set up on this machine.
            ui::blank();
            ui::body("no identity on this machine matches that key.");
            let name = prompt_line(&ui::ask("name it to set it up here"))?;
            let name = name.trim().to_string();
            if name.is_empty() {
                anyhow::bail!("a name is required to set up the identity here");
            }
            let (user_id, _) = client
                .login_with_recovery_key(&key, Some(name), None)
                .await
                .map_err(|e| anyhow::anyhow!("could not set up that identity here: {e}"))?;
            ui::greet("set up as", &user_id);
            kotton::active_identity::initialise(&user_id);
            Ok(Some(user_id))
        }
    }
}

/// No key entered → set up this machine: a brand-new identity, or join one that
/// already exists on another of your devices (the "connect to a network" branch).
async fn setup_machine(client: &mut KottonClient) -> anyhow::Result<Option<String>> {
    ui::blank();
    ui::body("set up this machine —");
    ui::option("n", "create a new identity");
    ui::option("j", "join an identity from another device");
    let choice = prompt_line(&ui::ask("choose"))?;
    match choice.trim() {
        "j" | "join" => join_identity(client).await,
        _ => Ok(Some(create_identity(client).await?)),
    }
}

/// Join an identity that lives on another device: ask its name here and the code
/// the other device's `device add` printed (or none, to find that device on this
/// network), then run the one join [`crate::commands::join_identity`] is — the same
/// one `kotton id join <name> [code]` runs at a terminal. The new device shows six
/// digits, the device you have takes them, and this machine becomes a device of
/// that identity, acting as it.
///
/// The ceremony issues this device a session (it authenticated by completing the
/// FROST join), which the join keeps in the session cache — so we drop straight
/// into the runtime as the joined identity.
async fn join_identity(client: &mut KottonClient) -> anyhow::Result<Option<String>> {
    let name = prompt_line(&ui::ask("name this identity on this machine"))?;
    let name = name.trim().to_string();
    if name.is_empty() {
        anyhow::bail!("a name is required");
    }
    // Empty code → discover the offering device on this network (mDNS); otherwise
    // pair with the pasted connection code.
    let code = prompt_line(&ui::ask(
        "paste the code from your other device, or Enter to find it on this network",
    ))?;
    let code = code.trim().to_string();

    ui::blank();
    let outcome = crate::commands::join_identity(client, &name, &code, None).await?;
    if outcome.exit_code != crate::commands::ExitCode::Success {
        anyhow::bail!(
            "{}",
            outcome
                .stderr
                .unwrap_or_else(|| "join did not complete".to_string())
        );
    }
    Ok(Some(name))
}

/// Create a brand-new identity. No ceremony, and nothing to write down.
///
/// This used to print twenty-four words and tell the person they were "the only
/// way to recover this identity", which was true and was the problem: it demanded
/// a ceremony at the moment a person has least to lose, for a loss they cannot yet
/// picture. An identity is now born with a random key and **no** recovery
/// authority; setting one up is a later, separate act.
///
/// The line about having no way back in is not a warning dressed as advice — it is
/// the account's actual state, and one the KEL records (`empty_recovery_root`)
/// rather than something anybody has to remember.
async fn create_identity(client: &mut KottonClient) -> anyhow::Result<String> {
    let name = prompt_line(&ui::ask("create a new identity — name it"))?;
    let name = name.trim().to_string();
    if name.is_empty() {
        anyhow::bail!("a name is required to create an identity");
    }
    let passphrase = prompt_new_passphrase()?;
    let (did, _) = client
        .create_user(&name, &passphrase)
        .await
        .map_err(|e| anyhow::anyhow!("could not create identity: {e}"))?;

    ui::blank();
    ui::body(&format!("identity created {}", short_did(&did)));
    ui::body("this identity has no way back in yet — add a device or a recovery phrase when you want one.");
    // The first identity on this device is the one its surfaces act as, in
    // both processes: the CLI reads this file, and it must not be told "no
    // active identity" about the identity the shell just made.
    kotton::active_identity::initialise(&name);
    Ok(name)
}

/// Ask for a new unlock credential at the terminal, offering a generated one —
/// the one flow every surface chooses a passphrase by
/// ([`crate::secret::choose_new_passphrase`]), where the reason for the offer is
/// written down. `create_user` holds every credential to the same bar.
fn prompt_new_passphrase() -> anyhow::Result<String> {
    use crate::secret::{choose_new_passphrase, NewPassphrase};

    let mut said = vec![crate::out::Out::Note(
        "your unlock credential — this is what opens Kotton on this machine.".to_string(),
    )];
    match choose_new_passphrase(&mut crate::Asking::Terminal, &mut said, "passphrase (hidden, Enter to accept)")? {
        NewPassphrase::Chosen(passphrase) => Ok(passphrase),
        NewPassphrase::NobodyToAsk => anyhow::bail!("no passphrase was given — nothing was created"),
        NewPassphrase::Refused(why) => anyhow::bail!("{why} — nothing was created"),
    }
}

/// Print a prompt and read one line of (visible) input from stdin.
fn prompt_line(label: &str) -> anyhow::Result<String> {
    use std::io::Write;
    print!("{label}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line)
}

/// Resolve the per-identity command-history file: `<user store>/history`.
///
/// History belongs to the **identity, not the machine** — one shared
/// `~/.kotton_history` leaks identity A's commands into identity B's session (via
/// recall, and later inline ghost suggestions). Keying it to the user's own store
/// keeps recall inside the identity boundary. North-star seam: this small personal
/// record should eventually live in the identity's *encrypted* store and follow
/// the user across devices — a plain per-identity file now, without foreclosing it.
fn history_file(user_id: &str) -> Option<PathBuf> {
    kotton_common::user_config_dir(user_id)
        .ok()
        .map(|dir| dir.join("history"))
}

impl Shell {
    async fn run_shell_loop(&self) -> Result<()> {
        // The identity the runtime runs as. Mutable: `id use <name>` swaps it
        // in-session without leaving the REPL.
        let mut user_id = self.user_id.clone();

        // Connect + authenticate as the starting identity.
        let (mut client, mut state) = establish_session(&user_id).await?;

        // Display plumbing shared across identity switches. The colored prompt is
        // shared with the completer's `highlight_prompt`: rustyline gets a plain
        // prompt (correct width) and displays the colored one.
        let colored_prompt = Arc::new(std::sync::RwLock::new(String::new()));
        let executor = &self.executor;
        let mut rl = Editor::new()?;
        rl.set_helper(Some(KottonCompleter::new(
            executor.registry(),
            Arc::clone(&client),
            user_id.clone(),
            Arc::clone(&state.cwd),
            Arc::clone(&colored_prompt),
        )));

        // Load this identity's persisted command history.
        let mut hist_path = history_file(&user_id);
        if let Some(ref path) = hist_path {
            let _ = rl.load_history(path); // ignore if doesn't exist yet
        }

        // Branded runtime entry: make it feel like stepping into your own
        // sovereign environment, not a generic shell (TERMINAL-RUNTIME-PIVOT).
        // Pull the node identity + paired-peer count for the context block.
        let node = node_label();
        let (node_did, peer_count) = {
            let mut c = client.lock().await;
            let did = c.get_node_identity().await.ok().map(|(d, _)| d);
            let peers = c.list_nodes(&user_id).await.map(|p| p.len()).unwrap_or(0);
            (did, peers)
        };
        print_entry(&node, node_did.as_deref(), peer_count);

        loop {
            // Plain prompt → rustyline (measures cursor width correctly); colored
            // prompt → the completer's highlight_prompt for display.
            let (plain, colored) =
                branded_prompt(&node, &user_id, &state.current_dir, state.last_exit_code);
            if let Ok(mut slot) = colored_prompt.write() {
                *slot = colored;
            }

            match rl.readline(&plain) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let _ = rl.add_history_entry(line);

                    match executor.execute_line(&mut state, line).await {
                        Ok(output) => {
                            // Pillar-3 shapes render through the shared renderer;
                            // legacy string stdout/stderr still print directly until
                            // every command is converted.
                            if !output.out.is_empty() {
                                // No actor trailer in the REPL — the prompt shows it.
                                crate::out::render(&output.out, None);
                            }
                            if let Some(stdout) = &output.stdout {
                                println!("{}", stdout);
                            }
                            if let Some(stderr) = &output.stderr {
                                eprintln!("{} {}", "error:".red(), stderr);
                            }
                            match output.exit_code {
                                ExitCode::Success => {
                                    state.last_exit_code = 0;
                                }
                                ExitCode::Exit => break,
                                ExitCode::Code(code) => {
                                    state.last_exit_code = code;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("{} {}", "error:".red(), e);
                            state.last_exit_code = 1;
                        }
                    }

                    // Honor an in-session identity switch requested by `id use`:
                    // save the outgoing identity's history, re-establish as the new
                    // one, and load its history — recall never crosses the boundary.
                    if let Some(target) = state.pending_identity_switch.take() {
                        match establish_session(&target).await {
                            Ok((new_client, new_state)) => {
                                save_repl_history(&mut rl, &hist_path);
                                let _ = rl.clear_history();

                                client = new_client;
                                state = new_state;
                                user_id = target;

                                rl.set_helper(Some(KottonCompleter::new(
                                    executor.registry(),
                                    Arc::clone(&client),
                                    user_id.clone(),
                                    Arc::clone(&state.cwd),
                                    Arc::clone(&colored_prompt),
                                )));

                                hist_path = history_file(&user_id);
                                if let Some(ref path) = hist_path {
                                    let _ = rl.load_history(path);
                                }
                                ui::greet("now,", &user_id);
                            }
                            Err(e) => {
                                eprintln!("{} could not switch identity: {e}", "error:".red());
                            }
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    // Ctrl+C — cancel current input, continue the loop
                    continue;
                }
                Err(ReadlineError::Eof) => {
                    // Ctrl+D — exit
                    println!("{}", "bye".dimmed());
                    break;
                }
                Err(err) => {
                    eprintln!("{} {}", "error:".red(), err);
                    break;
                }
            }
        }

        // Persist the current identity's history on exit.
        save_repl_history(&mut rl, &hist_path);

        Ok(())
    }
}

/// Connect + authenticate as `user_id` and build the shell state for that session.
async fn establish_session(
    user_id: &str,
) -> Result<(Arc<Mutex<KottonClient>>, ShellState)> {
    let raw_client = KottonClient::connect_as(user_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let client: Arc<Mutex<KottonClient>> = Arc::new(Mutex::new(raw_client));
    let state = ShellState::new(user_id.to_string(), Arc::clone(&client));
    Ok((client, state))
}

/// Save the REPL history to `path`, creating the identity's store dir if needed.
fn save_repl_history<H: rustyline::Helper, I: rustyline::history::History>(
    rl: &mut Editor<H, I>,
    path: &Option<PathBuf>,
) {
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = rl.save_history(path);
    }
}
