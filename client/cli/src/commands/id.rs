// SPDX-License-Identifier: AGPL-3.0-or-later
use clap::Subcommand;
use kotton::{format_wait, KottonClient, LockMode, PinUnlock};
use std::io::{self, Write};

#[derive(Subcommand)]
pub enum IdCommand {
    /// Create a new identity on this device. Prompts for a name if omitted.
    #[command(alias = "add")]
    Create {
        /// Username / identity ID (prompted interactively if omitted)
        username: Option<String>,
    },
    /// Join an identity you have on another device: run `kotton device add` there,
    /// then this here.
    ///
    /// This device shows six digits; type them where `device add` asks for them, and
    /// answer `y` here. It ends with the identity on this device, acting as it when it
    /// acted as nobody. Needs no identity on this device first: it is how one arrives.
    /// The shell's `device join`, run as `<username>`.
    Join {
        /// What this device calls the identity (it need not match the other device's)
        username: String,
        /// The code `device add` printed; leave it out to find that device on this
        /// network
        code: Option<String>,
    },
    /// Remove a user from this device
    Rm {
        /// Username / user ID
        username: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
    /// Set up recovery: mint a 24-word phrase and commit it as an authority.
    ///
    /// Prints the twenty-four words and, under them, the line of each vault that
    /// keeps a copy of your sealed keys, once: write both on paper. `id recover`
    /// asks for them on any machine. Creation mints no phrase, so this is how an
    /// identity gains a way back in. It can be run more than once — the committed
    /// set only ever grows, so an added phrase never retires one you already have.
    /// Named for what it *adds*, not for recovering: `id recover` is the act, and
    /// two commands whose names both say "recover" would be one name for the setup
    /// and the act.
    #[command(alias = "recovery")]
    AddRecovery {
        /// Username / identity ID
        username: String,
    },
    /// Recover an account with a 24-word recovery phrase (prompted, hidden)
    Login {
        /// Username to restore (required when this is a fresh device)
        username: String,
    },
    /// Rotate your identity key with your recovery phrase (survive key compromise).
    /// Your identity (DID) stays the same; the old key stops working.
    /// The phrase is prompted (hidden), never taken on the command line.
    Rotate {
        /// Username / identity ID
        username: String,
    },
    /// Make this machine yours again, from the words and the line `id add-recovery`
    /// printed. Asks for your name (unless given), the twenty-four words at a hidden
    /// prompt, the vault's line, and a passphrase for this machine, before it begins.
    /// Then it claims the name here, adds the vault the line names, fetches your
    /// identity and sealed keys from it, proves the words against them, makes this
    /// machine's key yours, seals your keys here under the passphrase, records the
    /// vault as your drive, makes the identity the one this machine acts as, and
    /// syncs your things back. Words that
    /// do not prove the identity are refused: a machine that held nothing of the name
    /// holds nothing of it after, unless the refusal names lines to run, in order, to
    /// remove what it could not take back; and one that held it keeps it.
    Recover {
        /// Username / identity ID (asked for if omitted)
        username: Option<String>,
    },
    /// Set your daily unlock passphrase, so you unlock with it — not your recovery phrase
    #[command(alias = "set-pin")]
    SetPassphrase {
        /// Username / identity ID
        username: String,
    },
    /// Bind this identity to this device's hardware, so the vault opens only here
    BindDevice {
        /// Username / identity ID
        username: String,
    },
    /// Lock your vault now — your keys leave memory until your passphrase opens it again
    Lock {
        /// Username / identity ID
        #[arg(env = "KOTTON_USER")]
        username: String,
    },
    /// Unlock this device's session with your daily passphrase
    Unlock {
        /// Username / identity ID
        username: String,
        /// Repair your keys from your vault while unlocking: a key this device
        /// cannot read, or does not hold, is written back from the vault your
        /// passphrase opens. A key that reads is checked against the vault and
        /// never written over — if one differs, nothing is written and the
        /// refusal names it.
        #[arg(long)]
        repair: bool,
    },
    /// List all identities loaded on this device (`*` marks the active one)
    List,
    /// Set the active identity — the one your commands act as by default
    Use {
        /// Identity name to make active
        name: String,
    },
}

// The hidden prompts are the shell's (`kotton_shell::secret`), so a secret is
// asked for the same way at either door: `id rotate` and `id recover` run the
// shell's own verbs through the bridge, and the verbs answered here ask with the
// same two functions. Never on argv, never through a line editor.
use kotton_shell::secret::{prompt_passphrase, prompt_recovery_phrase};

/// Choose a new daily passphrase at the hidden prompt, by the one flow every
/// surface chooses one with ([`kotton_shell::secret::choose_new_passphrase`]): a
/// generated one is offered and Enter takes it; a typed one is asked again and
/// held to the bar, since a mistyped credential that seals the vault is a
/// credential nobody can open it with.
pub fn choose_passphrase() -> io::Result<String> {
    use kotton_shell::out::Out;
    use kotton_shell::secret::{choose_new_passphrase, NewPassphrase};

    let mut said = vec![Out::Note(
        "This is your daily passphrase, NOT your recovery phrase — that one stays written down."
            .to_string(),
    )];
    match choose_new_passphrase(
        &mut kotton_shell::Asking::Terminal,
        &mut said,
        "passphrase (hidden, Enter to accept the suggestion)",
    )? {
        NewPassphrase::Chosen(passphrase) => Ok(passphrase),
        NewPassphrase::NobodyToAsk => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no passphrase was given — nothing was changed",
        )),
        NewPassphrase::Refused(why) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{why} — nothing was changed\n  Press Enter at the prompt to use the suggested passphrase instead."),
        )),
    }
}

impl IdCommand {
    /// The identity this command acts **on behalf of**, or `None` when it either
    /// establishes a session itself or needs none.
    ///
    /// ## Why this is a table and not a line in each arm
    ///
    /// Measured 2026-09-11: `execute` opened one `KottonClient::connect()` — an
    /// **unauthenticated** connection — for all eleven subcommands. Six of them send a
    /// request the daemon answers only inside a session (`UserRequest::requires_session`):
    /// `rm`, `add-recovery`, `recover`, `rotate`, `set-passphrase` and `bind-device`.
    /// Every one of those was refused with `NoActiveSession` and, until the arm beneath
    /// each `match` learned to name it, reported to the person as *"unexpected response"*.
    ///
    /// The fact — *does this act for a user?* — was already stated authoritatively, in
    /// `core/wire`'s `requires_session()`, exhaustive and compiler-forced. It was then
    /// restated here by hand, once, badly, for a block of eleven. That is the shape this
    /// repository keeps finding: a fact in two places with nothing holding them in step.
    ///
    /// So this is **exhaustive with no wildcard arm** — the same device
    /// `required_trust()` uses. A twelfth subcommand does not compile until somebody
    /// decides whether it acts for somebody. And `id_connection_tests` compares every
    /// answer here against the request that subcommand actually sends, so the two
    /// tables cannot drift.
    fn acts_for(&self) -> Option<&str> {
        match self {
            // These four *establish* a session rather than presupposing one, so the
            // unauthenticated connection is not an oversight here — it is the only one
            // they could use. `create` mints the identity and its first session,
            // `login` exchanges the phrase for one, `unlock` the passphrase, and
            // `recover` starts with `login`'s exchange and runs the rest on the
            // session it opened.
            IdCommand::Create { .. } => None,
            IdCommand::Login { .. } => None,
            IdCommand::Unlock { .. } => None,
            IdCommand::Recover { .. } => None,
            // `join` brings the identity to this device; the ceremony is its proof,
            // and it runs as the shell's session-less `device join`.
            IdCommand::Join { .. } => None,
            // Read-only across every identity on the device; there is no single user to
            // authenticate as, and `ListUsers` is answered before any session exists
            // precisely so a person can find out who they might log in as.
            IdCommand::List => None,
            IdCommand::Use { .. } => None,

            // Each is scoped to one identity and was refused without a session.
            IdCommand::Rm { username, .. } => Some(username),
            IdCommand::AddRecovery { username } => Some(username),
            // `rotate` prompts for the recovery phrase itself, and
            // `connect_as` may ask for a credential first if no session is cached. Two
            // prompts is worth saying out loud, and it is the honest order: the daemon
            // will not rotate a key for a connection that has not proved who it is.
            IdCommand::Rotate { username } => Some(username),
            IdCommand::SetPassphrase { username } => Some(username),
            IdCommand::BindDevice { username } => Some(username),
            // Closing the vault is the owner's act, so it needs the owner's session.
            IdCommand::Lock { username } => Some(username),
        }
    }

    /// The name clap gives this subcommand, for test messages that name what broke.
    #[cfg(test)]
    fn name(&self) -> &'static str {
        match self {
            IdCommand::Create { .. } => "create",
            IdCommand::Join { .. } => "join",
            IdCommand::Rm { .. } => "rm",
            IdCommand::AddRecovery { .. } => "add-recovery",
            IdCommand::Login { .. } => "login",
            IdCommand::Rotate { .. } => "rotate",
            IdCommand::Recover { .. } => "recover",
            IdCommand::SetPassphrase { .. } => "set-passphrase",
            IdCommand::BindDevice { .. } => "bind-device",
            IdCommand::Unlock { .. } => "unlock",
            IdCommand::Lock { .. } => "lock",
            IdCommand::List => "list",
            IdCommand::Use { .. } => "use",
        }
    }

    pub async fn execute(&self) -> io::Result<()> {
        // One implementation, two doors: `kotton id add-recovery <name>` and
        // `kotton id rotate <name>` run the REPL's `id` verb of the same name as
        // `<name>`, so the phrase and the card print the same way from either, and
        // the phrase and the passphrase are asked at the one hidden prompt
        // (`kotton_shell::commands::id`, `kotton_shell::secret`). The bridge
        // connects as `<name>`, which is `acts_for`'s answer below.
        //
        // `kotton id recover` is the terminal's own: it asks before it connects,
        // then claims the name, which is the session the rest runs on
        // (`super::recover`). It asks for the card and sends `Recover` as the
        // REPL's `id recover` does (`kotton_shell::recover`), which is the piece
        // it runs for an identity a REPL already runs as.
        if let IdCommand::Recover { username } = self {
            return super::recover::run(username.as_deref()).await;
        }
        let shared = match self {
            IdCommand::AddRecovery { username } => Some(("add-recovery", username)),
            IdCommand::Rotate { username } => Some(("rotate", username)),
            _ => None,
        };
        if let Some((sub, username)) = shared {
            return crate::bridge::run_verb(Some(username.clone()), "id", vec![sub.to_string()], false)
                .await;
        }
        // `kotton id join <name> [code]` is the shell's `device join`, which runs
        // without a session as the identity named (`Command::execute_without_session`).
        if let IdCommand::Join { username, code } = self {
            let args = std::iter::once("join".to_string()).chain(code.clone()).collect();
            return crate::bridge::run_verb(Some(username.clone()), "device", args, false).await;
        }

        let mut client = match self.acts_for() {
            Some(user) => KottonClient::connect_as(user).await?,
            None => KottonClient::connect().await?,
        };

        match self {
            IdCommand::Create { username } => {
                // Interactive: a first-time user just runs `kotton user create` and is
                // asked for a name; tooling/automation passes it as an argument.
                let username = match username {
                    Some(u) => u.clone(),
                    None => {
                        print!("What should we call you? ");
                        io::stdout().flush()?;
                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        let name = input.trim().to_string();
                        if name.is_empty() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "a name is required to create an identity",
                            ));
                        }
                        name
                    }
                };
                // The credential is chosen before the identity exists, because
                // that is the order `create_user` enforces: it assesses first and
                // refuses with nothing created. Asking after would be a prompt the
                // person could dismiss.
                println!("\nChoose how you'll unlock '{username}' on this device.");
                let passphrase = choose_passphrase()?;
                let (did, _device_fingerprint) =
                    client.create_user(&username, &passphrase).await?;
                // The device now holds an identity. If it holds no other, that is
                // the one it acts as — see `active_identity::initialise`.
                crate::active_identity::initialise(&username);

                println!("\n✓ Identity '{}' created!", username);
                println!("  DID: {}", did);
                println!();
                println!("  This identity has no way back in yet.");
                println!("  Add a device or a recovery phrase when you want one.");
            }

            IdCommand::Rm { username, force } => {
                if !force {
                    print!("Remove user '{}' from this device? (yes/no): ", username);
                    io::stdout().flush()?;
                    let mut confirm = String::new();
                    io::stdin().read_line(&mut confirm)?;

                    if confirm.trim() != "yes" {
                        println!("Cancelled");
                        return Ok(());
                    }
                }

                client.logout_user(username).await?;
                println!("✓ User '{}' removed from this device", username);
            }

            // Answered before a connection is opened — see the top of this function.
            IdCommand::AddRecovery { .. } => unreachable!("routed through the shell's `id add-recovery`"),

            IdCommand::Login { username } => {
                let recovery_key = prompt_recovery_phrase(username)?;
                let (user_id, _device_fingerprint) = client
                    .login_with_recovery_key(&recovery_key, Some(username.clone()), None)
                    .await?;
                // This device now holds an identity. If it holds no other, that
                // is the one it acts as — see `active_identity::initialise`.
                crate::active_identity::initialise(&user_id);
                println!("✓ Recovered account '{}'", user_id);
            }

            // Answered before a connection is opened — see the top of this function.
            IdCommand::Recover { .. } => unreachable!("answered by `super::recover` before a connection is opened"),
            IdCommand::Rotate { .. } => unreachable!("routed through the shell's `id rotate`"),

            IdCommand::SetPassphrase { username } => {
                println!("Choose how you'll unlock '{username}' on this device.");
                let passphrase = choose_passphrase()?;
                client
                    .set_lock_policy(username, LockMode::Passphrase, 0, Some(&passphrase))
                    .await?;
                println!("\n✓ Passphrase set for '{username}'.");
                // RFC-0053 step 2 asks for this plainly, because the attempt
                // counter is the thing a user will assume protects them and it
                // is not. It bounds someone typing at this keyboard. It does
                // nothing about someone who copies the vault and guesses
                // elsewhere — that attack never reaches this daemon. A phone
                // gets away with a short PIN because its enclave counts failures
                // where the attacker cannot reach the counter; a desktop has no
                // such hardware yet, so the honest thing is to say so at the
                // moment the choice is made.
                println!(
                    "  It also encrypts this device's keys at rest. Failed attempts are slowed\n  \
                     here, but that cannot slow someone who copies the encrypted file and guesses\n  \
                     on their own machine — which is why it is a passphrase and not a PIN.\n  \
                     Your recovery phrase still works if you forget it."
                );
            }

            IdCommand::BindDevice { username } => {
                println!("Bind '{username}' to this device's hardware?\n");
                println!("  After this, this identity's keys can only be unlocked on this");
                println!("  machine — copying your data elsewhere will not be enough.\n");
                println!("  The trade: if this machine's security chip is cleared or reset,");
                println!("  or the disk moves to another machine, your recovery phrase");
                println!("  becomes the only way back in. Make sure you still have it.\n");
                let passphrase = prompt_passphrase(&format!("passphrase for '{username}' (hidden)"))?;
                if passphrase.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a passphrase is required — binding re-seals the vault, which means opening it",
                    ));
                }
                let backend = client.bind_device_hardware(username, &passphrase).await?;
                println!("\n✓ '{username}' is bound to this device ({backend}).");
            }

            IdCommand::Unlock { username, repair } => {
                let passphrase = prompt_passphrase(&format!("passphrase for '{username}' (hidden)"))?;
                if passphrase.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a passphrase is required",
                    ));
                }
                let (unlock, repaired) = if *repair {
                    client.unlock_repairing_roots(username, &passphrase).await?
                } else {
                    (client.unlock_with_pin(username, &passphrase).await?, None)
                };
                match unlock {
                    PinUnlock::Unlocked if *repair => match repaired {
                        Some(labels) if labels.is_empty() => println!(
                            "✓ Unlocked '{username}' — every key read and matched your vault; nothing was repaired"
                        ),
                        Some(labels) => {
                            println!("✓ Repaired from your vault and unlocked '{username}':");
                            for label in &labels {
                                println!("    {label}");
                            }
                        }
                        // A daemon that predates `--repair` ignores it and
                        // answers a plain unlock: say that, not that keys matched.
                        None => println!(
                            "✓ Unlocked '{username}' — but this device's daemon did not run a repair \
                             (it predates `--repair`), so nothing was checked against your vault"
                        ),
                    },
                    PinUnlock::Unlocked => println!("✓ Unlocked '{}'", username),
                    PinUnlock::Wrong { attempts_remaining } => {
                        return Err(io::Error::other(format!(
                            "wrong passphrase — {attempts_remaining} attempt(s) remaining"
                        )));
                    }
                    PinUnlock::RateLimited { retry_after_secs } => {
                        return Err(io::Error::other(format!(
                            "too many failed attempts — try again in {}; \
                             `kotton login {username}` unlocks with your recovery phrase meanwhile",
                            format_wait(retry_after_secs)
                        )));
                    }
                }
            }

            IdCommand::Lock { username } => {
                client.lock_custody(username).await?;
                println!(
                    "✓ Locked the vault for '{username}' — it opens again with `kotton id unlock {username}`"
                );
            }

            IdCommand::List => {
                let users = client.list_users().await?;
                let active = crate::active_identity::get();
                if users.is_empty() {
                    println!("no identities on this device — run `kotton id create` to make one");
                } else {
                    for user in users {
                        let marker = if active.as_deref() == Some(user.as_str()) {
                            "*"
                        } else {
                            " "
                        };
                        println!("  {marker} {user}");
                    }
                }
            }

            IdCommand::Join { .. } => unreachable!("routed through the shell's `device join`"),
            IdCommand::Use { name } => {
                // Only make an identity active if it actually exists on this device.
                let users = client.list_users().await?;
                if !users.iter().any(|u| u == name) {
                    return Err(io::Error::other(format!(
                        "no identity '{name}' on this device — run `kotton id list` to see them"
                    )));
                }
                crate::active_identity::set(name)?;
                println!("✓ active identity is now '{name}'");
                println!("  commands act as '{name}' unless you pass --user.");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod id_connection_tests {
    use super::*;
    use kotton_wire::ipc::UserRequest;

    const U: &str = "alice";

    fn user() -> String {
        U.to_string()
    }

    /// Every subcommand, beside the request it sends.
    ///
    /// Hand-written, like [`IdCommand::acts_for`] — and, unlike it before today,
    /// **checked**: the assertion below reads `requires_session()` out of `core/wire`,
    /// which is the authority both tables are approximations of.
    ///
    /// A subcommand that sends more than one request is listed under the one that needs
    /// the most: the connection is opened once, so it is the strictest request on it
    /// that decides. `use` is the case — it sends `ListUsers` and then writes a local
    /// file — and `unlock`'s `UnlockWithPin` is the credential exchange itself. So is
    /// `recover`'s first request, `LoginWithRecoveryKey`: every request after it,
    /// `Recover` among them, runs on the session that exchange opened.
    fn commands_and_requests() -> Vec<(IdCommand, UserRequest)> {
        vec![
            (
                IdCommand::Create { username: Some(user()) },
                UserRequest::CreateUser { user_id: user(), passphrase: kotton_wire::ipc::SecretText::new("") },
            ),
            (
                IdCommand::Login { username: user() },
                UserRequest::LoginWithRecoveryKey {
                    recovery_key: kotton_wire::ipc::SecretText::new(""),
                    device_name: None,
                    user_id: Some(user()),
                },
            ),
            (
                IdCommand::Unlock { username: user(), repair: false },
                UserRequest::UnlockWithPin { user_id: user(), pin: kotton_wire::ipc::SecretText::new(""), repair: false },
            ),
            (
                IdCommand::Lock { username: user() },
                UserRequest::LockCustody { user_id: user() },
            ),
            (
                IdCommand::Join { username: user(), code: None },
                UserRequest::DeviceJoin {
                    user_id: user(),
                    code: kotton_wire::ipc::SecretText::new(""),
                    as_name: None,
                },
            ),
            (IdCommand::List, UserRequest::ListUsers),
            (IdCommand::Use { name: user() }, UserRequest::ListUsers),
            (
                IdCommand::Rm { username: user(), force: true },
                UserRequest::LogoutUser { user_id: user() },
            ),
            (
                IdCommand::AddRecovery { username: user() },
                UserRequest::AddRecoveryPhrase { user_id: user() },
            ),
            (
                IdCommand::Recover { username: Some(user()) },
                UserRequest::LoginWithRecoveryKey {
                    recovery_key: kotton_wire::ipc::SecretText::new(""),
                    device_name: None,
                    user_id: Some(user()),
                },
            ),
            (
                IdCommand::Rotate { username: user() },
                UserRequest::RotateIdentity {
                    user_id: user(),
                    recovery_key: kotton_wire::ipc::SecretText::new(""),
                    credential: None,
                },
            ),
            (
                IdCommand::SetPassphrase { username: user() },
                UserRequest::SetLockPolicy {
                    user_id: user(),
                    mode: LockMode::Passphrase,
                    auto_lock_minutes: 0,
                    pin: None,
                },
            ),
            (
                IdCommand::BindDevice { username: user() },
                UserRequest::BindDeviceHardware { user_id: user(), credential: kotton_wire::ipc::SecretText::new("") },
            ),
        ]
    }

    /// **The bug, as a test.** Before 2026-09-11 this was red for six of the eleven:
    /// `execute` connected unauthenticated and the daemon refused every session-scoped
    /// request on the connection.
    ///
    /// Note what it compares. Not "is the answer the one I expected" — that would be a
    /// third copy of the same guess — but the CLI's choice against `core/wire`'s
    /// `requires_session()`, which is the definition. Change the tier of a request there
    /// and this goes red until the CLI follows it.
    #[test]
    fn a_command_authenticates_exactly_when_its_request_needs_a_session() {
        for (cmd, request) in commands_and_requests() {
            let authenticates = cmd.acts_for().is_some();
            assert_eq!(
                authenticates,
                request.requires_session(),
                "`id {}` connects {}, but {} {} a session — \
                 an unauthenticated connection is refused with NoActiveSession",
                cmd.name(),
                if authenticates { "as the user" } else { "unauthenticated" },
                request.variant_name(),
                if request.requires_session() { "needs" } else { "does not need" },
            );
        }
    }

    /// A command that acts for somebody names the right somebody. Connecting as the
    /// wrong user is refused too, by `session_refusal`'s `target_user_id` arm, and it
    /// would read exactly like the failure above.
    #[test]
    fn the_user_authenticated_as_is_the_user_named() {
        for (cmd, _) in commands_and_requests() {
            if let Some(who) = cmd.acts_for() {
                assert_eq!(who, U, "`id {}` authenticated as somebody else", cmd.name());
            }
        }
    }

    /// The table above covers every variant. `acts_for` cannot compile with one missing,
    /// but this list can, and a subcommand absent from it is one the assertion never
    /// makes — a gate that passes over nothing, which is the failure mode
    /// `xtask/src/tree.rs` was written about.
    #[test]
    fn every_subcommand_is_in_the_table() {
        use clap::CommandFactory;
        #[derive(clap::Parser)]
        struct Probe {
            #[command(subcommand)]
            _id: IdCommand,
        }
        let declared: Vec<String> = Probe::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect();
        let covered: Vec<String> =
            commands_and_requests().iter().map(|(c, _)| c.name().to_string()).collect();
        for d in &declared {
            assert!(covered.contains(d), "`id {d}` is not in commands_and_requests()");
        }
        assert_eq!(declared.len(), covered.len(), "declared: {declared:?}, covered: {covered:?}");
    }
}
