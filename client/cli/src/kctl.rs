// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kctl` — Kotton device-owner operator CLI.
//!
//! Communicates with the `kdeviced` device daemon via IPC.  All commands
//! except `daemon ping` require the caller to prove DID ownership with their
//! Ed25519 recovery mnemonic before the daemon will accept them.
//!
//! ## Usage
//!
//! ```
//! kctl daemon ping
//! kctl daemon status
//! kctl sudoers list
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use clap::{Parser, Subcommand};
use ed25519_dalek::Signer;
use kotton_sys::crypto::MnemonicProvider;
use kotton_sys::ipc::IpcEndpoint;
use kotton_operator::DeviceClient;
use kotton_crypto::{
    derive_identity_key, mnemonic_to_seed32, Bip39MnemonicProvider, DidKeyMethod,
};
use kotton_ipc::IpcClient;
#[cfg(unix)]
use kotton_common::{daemon_socket_path, kdeviced_door};
#[cfg(windows)]
use kotton_common::kdeviced_ipc_name;
use std::io;
use std::process::ExitCode;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name = "kctl", about = "Device-owner operator CLI for Kotton")]
struct Cli {
    /// Break-glass: authenticate with the recovery mnemonic instead of this
    /// machine's operator key (e.g. from a device that has never run kctl).
    #[arg(long, global = true)]
    recover: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Communicate with the kdeviced daemon
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },
    /// Manage device identity and name
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Manage user sessions on this device
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Manage the device sudoers set
    Sudoers {
        #[command(subcommand)]
        cmd: SudoersCmd,
    },
    /// IPC session inspection
    Ipc {
        #[command(subcommand)]
        cmd: IpcCmd,
    },
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// Check connectivity (no authentication required)
    Ping,
    /// Show daemon status
    Status,
    /// Gracefully restart the kdeviced daemon
    Restart,
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Show device identity and name
    Show,
    /// Set a human-readable name for this device
    Rename {
        /// The new device name
        name: String,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// List all active user sessions on this device
    List,
    /// Create a user on this device: start its daemon, mint its identity,
    /// and enroll the new identity as a device owner
    Create {
        /// The user id (short name) for the new user
        user_id: String,
    },
    /// Stop a user's daemon and wipe local session material and VFS cache
    Remove {
        /// The user DID to remove
        did: String,
    },
}

#[derive(Subcommand)]
enum SudoersCmd {
    /// List this device's operators: each key, and whose it is
    List,
    /// Make a person with an account here an operator, holding a key of their own
    Add {
        /// The key (did:key) the new operator authenticates with
        did: String,
        /// The account on this device it answers for — its DID in the users
        /// registry. Defaults to the key itself, for an account whose DID is
        /// its own `did:key`
        #[arg(long)]
        person: Option<String>,
    },
    /// Step an operator down — one key, or a person and every key of theirs.
    /// The last operator is never removed.
    Remove {
        /// The key, or the person, to step down
        did: String,
    },
}

#[derive(Subcommand)]
enum IpcCmd {
    /// List authenticated kctl operator sessions on kdeviced.
    Inspect,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    kotton_cli::finish(run().await)
}

async fn run() -> io::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let recover = cli.recover;

    let endpoint = kdeviced_endpoint()?;
    let mut dev = DeviceClient::new(IpcClient::connect(endpoint).await?);

    match cli.command {
        Commands::Daemon {
            cmd: DaemonCmd::Ping,
        } => {
            dev.diag().ping().await?;
            println!("pong");
        }

        Commands::Daemon {
            cmd: DaemonCmd::Status,
        } => {
            let _did = authenticate(&mut dev, recover).await?;
            let s = dev.diag().status().await?;
            println!("version:      {}", s.version);
            println!("uptime:       {}s", s.uptime_secs);
            println!("active users: {}", s.active_user_count);
        }

        Commands::Daemon {
            cmd: DaemonCmd::Restart,
        } => {
            let _did = authenticate(&mut dev, recover).await?;
            dev.diag().restart().await?;
            println!("daemon is restarting");
        }

        Commands::Device {
            cmd: DeviceCmd::Show,
        } => {
            let _did = authenticate(&mut dev, recover).await?;
            let info = dev.device().show().await?;
            println!(
                "did:  {}",
                info.did.as_deref().unwrap_or("(not yet assigned)")
            );
            println!("name: {}", info.name.as_deref().unwrap_or("(unnamed)"));
        }

        Commands::Device {
            cmd: DeviceCmd::Rename { name },
        } => {
            let _did = authenticate(&mut dev, recover).await?;
            dev.device().rename(&name).await?;
            println!("device renamed to {name:?}");
        }

        Commands::User { cmd: UserCmd::List } => {
            let _did = authenticate(&mut dev, recover).await?;
            let sessions = dev.session().list().await?;
            if sessions.is_empty() {
                println!("(no active user sessions)");
            } else {
                for s in &sessions {
                    println!("{} — socket: {}  pid: {}", s.user_did, s.socket_name, s.pid);
                }
            }
        }

        Commands::User {
            cmd: UserCmd::Create { user_id },
        } => {
            // The RFC-0063 supervised create: the device daemon starts a
            // per-user daemon, the identity is minted inside it (a supervised
            // kuserd may create exactly its own principal), and the new
            // identity is enrolled as a device owner — see
            // DEC-0017.
            let caller_did = authenticate(&mut dev, recover).await?;
            let (socket_name, _pid, already) = dev.device().start_user(&user_id).await?;
            if already {
                eprintln!("daemon for '{user_id}' already running on {socket_name}");
            }

            let mut user_client = connect_user_daemon(&socket_name).await?;
            println!();
            println!("Choose how you'll unlock '{user_id}' on this device.");
            let passphrase = kotton_cli::commands::id::choose_passphrase()?;
            let (did, device_fingerprint) =
                user_client.create_user(&user_id, &passphrase).await?;

            // The first person on a device is its operator (trust on first
            // use, DEC-0017): the key this kctl authenticated with — the
            // machine's first-run key — is bound to them. Their account's DID
            // is a `did:kel`, which names the person and signs nothing here, so
            // it is the row's person and never its key. Anyone after that has
            // whatever standing an operator hands them, and no more
            // (TASK-a-device-has-operators-not-an-operator).
            let operators = dev.device().sudoers().await?;
            let first_person = operators.iter().all(|o| o.person.is_none());
            if first_person {
                dev.device().sudoers_add(&caller_did, &did).await?;
            }

            println!("user created: {user_id}");
            println!("did:          {did}");
            println!("device:       {device_fingerprint}");
            println!("socket:       {socket_name}");
            if first_person {
                println!("an operator of this device — the first person on it");
            } else {
                println!(
                    "not an operator — an operator makes them one with `kctl sudoers add <their key> --person {did}`"
                );
            }
            println!();
            println!("no recovery authority yet — this identity has no way back in.");
        }

        Commands::User {
            cmd: UserCmd::Remove { did },
        } => {
            let _did = authenticate(&mut dev, recover).await?;
            let user_did = dev.device().remove_user(&did).await?;
            println!("removed and wiped: {user_did}");
        }

        Commands::Sudoers {
            cmd: SudoersCmd::List,
        } => {
            let _did = authenticate(&mut dev, recover).await?;
            let operators = dev.device().sudoers().await?;
            if operators.is_empty() {
                println!("(no operators enrolled)");
            } else {
                for o in operators {
                    let person = o.person.as_deref().unwrap_or("(first-run key, answering for nobody yet)");
                    println!("{}  {person}  added by {}", o.did, o.added_by);
                }
            }
        }

        Commands::Sudoers {
            cmd: SudoersCmd::Add { did, person },
        } => {
            let _did = authenticate(&mut dev, recover).await?;
            let person = person.unwrap_or_else(|| did.clone());
            dev.device().sudoers_add(&did, &person).await?;
            println!("{person} is an operator of this device, holding {did}");
        }

        Commands::Sudoers {
            cmd: SudoersCmd::Remove { did },
        } => {
            let caller_did = authenticate(&mut dev, recover).await?;
            if did == caller_did {
                eprintln!("stepping yourself down as an operator");
            }
            dev.device().sudoers_remove(&did).await?;
            println!("{did} is no longer an operator of this device");
        }

        Commands::Ipc {
            cmd: IpcCmd::Inspect,
        } => {
            let _did = authenticate(&mut dev, recover).await?;
            let sessions = dev.diag().ipc_sessions().await?;
            if sessions.is_empty() {
                println!("(no authenticated kdeviced sessions)");
            } else {
                println!("{:<66}  {:<8}  REQUESTS", "DID", "SINCE");
                println!("{}", "─".repeat(82));
                for s in &sessions {
                    let since = format_kctl_since(s.authenticated_at);
                    let requests = format_kctl_count(s.request_count);
                    println!("{:<66}  {:<8}  {}", s.did, since, requests);
                }
            }
        }
    }

    Ok(())
}

// ── Challenge-response authentication ────────────────────────────────────────

/// Authenticate to kdeviced and return the caller's DID.
///
/// The default credential is this machine's **warm operator key** — minted on
/// first use and auto-enrolled as the first sudoer (trust on first use: the
/// person at a fresh install is the owner/operator;
/// `DEC-0017`). `--recover` derives the
/// identity key from the recovery mnemonic instead — the break-glass path, no
/// longer the daily one: the mnemonic is a safety deposit box, not a login
/// (RFC-0031).
///
/// Once this returns `Ok`, all subsequent requests on the same `client`
/// connection are authorized by kdeviced for the lifetime of the connection.
async fn authenticate(dev: &mut DeviceClient, recover: bool) -> io::Result<String> {
    let signing_key = if recover {
        // Prompt for the recovery mnemonic (hidden — no echo to terminal) and
        // derive: BIP-39 mnemonic → seed32 →
        // HKDF-SHA256("kotton:identity:ed25519:v1") → scalar.
        let mnemonic_str = rpassword::prompt_password("Recovery mnemonic: ")?;
        Bip39MnemonicProvider
            .validate(&mnemonic_str)
            .map_err(|e| io::Error::other(format!("invalid mnemonic: {e}")))?;
        let seed32 = mnemonic_to_seed32(&mnemonic_str);
        ed25519_dalek::SigningKey::from_bytes(&derive_identity_key(&seed32))
    } else {
        operator_signing_key()?
    };

    let verifying_key = signing_key.verifying_key();
    let did = DidKeyMethod::from_public_key(&verifying_key).to_string();

    // Request a challenge nonce, decode, and sign it.
    //
    // The signing happens here rather than inside `kotton-operator`, which takes a
    // finished signature. The operator facade never holds a key — the same
    // separation the crate's own docs claim, kept honest at its only caller.
    let nonce_b64 = dev.session().challenge().await?;
    let nonce_raw = URL_SAFE_NO_PAD
        .decode(&nonce_b64)
        .map_err(|e| io::Error::other(format!("server returned invalid nonce: {e}")))?;

    let sig = signing_key.sign(&nonce_raw);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let did = dev
        .session()
        .authenticate(&did, &nonce_b64, &sig_b64)
        .await
        .map_err(|e| {
            if recover {
                io::Error::other(format!("authentication failed: {e}"))
            } else {
                io::Error::other(format!(
                    "authentication failed: {e}\n\
                     this machine's operator key is not enrolled on this device — \
                     if you are the owner, retry with --recover to authenticate \
                     with your recovery mnemonic, then `kctl sudoers add` this \
                     machine's operator DID ({did})"
                ))
            }
        })?;
    eprintln!("authenticated as {did}");
    Ok(did)
}

/// This machine's warm operator key: loaded from the OS keychain, minted and
/// stored on first use.
///
/// The keychain is defense-in-depth, never the trust boundary — what admits
/// the key is kdeviced's sudoers set, and revoking it there revokes it
/// everywhere.
fn operator_signing_key() -> io::Result<ed25519_dalek::SigningKey> {
    // Scoped like every other secret: a dev install's operator key is not the
    // production install's, matching the per-base-dir sudoers DB it authenticates
    // against.
    let base = kotton_common::base_dir().map_err(io::Error::other)?;
    // Same chooser the runtime uses, so kctl against a throwaway root does not
    // leave a permanent operator key behind either.
    let store = kotton_secret::secrets_for_base_dir(&base).map_err(io::Error::other)?;
    operator_signing_key_in(store.as_ref())
}

/// [`operator_signing_key`] over the store it is handed.
///
/// A key is minted only when the store answered that it holds none. A store
/// that could not be read — a locked keychain — and a value that does not
/// decode are both refused, naming the label: the key they stand for is the one
/// kdeviced's sudoers set enrolled, and minting would replace it with one
/// nobody enrolled
/// (`TASK-a-key-the-store-cannot-read-is-taken-for-no-key-and-a-new-one-is-minted`).
/// Until 2026-10-02 the read was `if let Ok(Some(..))`, which took both for
/// first use, and a corrupt value was replaced with a warning.
fn operator_signing_key_in(store: &dyn kotton_sys::secret::SecretsStore) -> io::Result<ed25519_dalek::SigningKey> {
    let label = kotton_common::crypto::kdf_labels::device_operator_key();

    let stored = store
        .get_secret(&label)
        .map_err(|e| io::Error::other(format!("could not read this machine's operator key ({label}): {e}")))?;
    if let Some(hex_seed) = stored {
        let seed = hex::decode(&hex_seed)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| {
                io::Error::other(format!(
                    "this machine's operator key ({label}) does not read as a key, so nothing was minted over it"
                ))
            })?;
        return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
    }

    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    store
        .set_secret(&label, &hex::encode(key.to_bytes()))
        .map_err(|e| io::Error::other(format!("could not store the operator key: {e}")))?;
    eprintln!("minted this machine's operator key (first use)");
    Ok(key)
}

// ── IPC endpoints ─────────────────────────────────────────────────────────────

/// This machine's `kdeviced`: the door it binds, asked of `kotton_common` rather
/// than composed here from its name.
fn kdeviced_endpoint() -> io::Result<IpcEndpoint> {
    #[cfg(windows)]
    {
        Ok(IpcEndpoint::NamedPipe(kdeviced_ipc_name()))
    }
    #[cfg(unix)]
    {
        Ok(IpcEndpoint::UnixSocket(kdeviced_door().map_err(io::Error::other)?))
    }
}

/// Build the IPC endpoint for a per-user daemon's socket name — the one
/// `start_user` returns — the same way that daemon binds it.
fn endpoint_for(name: &str) -> io::Result<IpcEndpoint> {
    #[cfg(windows)]
    {
        Ok(IpcEndpoint::NamedPipe(name.to_string()))
    }
    #[cfg(unix)]
    {
        Ok(IpcEndpoint::UnixSocket(
            daemon_socket_path(name).map_err(io::Error::other)?,
        ))
    }
}

/// Connect to a freshly started per-user daemon, retrying while it binds its
/// socket.
async fn connect_user_daemon(socket_name: &str) -> io::Result<kotton::KottonClient> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match kotton::KottonClient::connect_to(endpoint_for(socket_name)?).await {
            Ok(client) => return Ok(client),
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                return Err(io::Error::other(format!(
                    "user daemon on '{socket_name}' did not accept a connection within 30s: {e}"
                )))
            }
        }
    }
}

// ── kctl ipc inspect helpers ──────────────────────────────────────────────────

fn format_kctl_since(ts: i64) -> String {
    if ts <= 0 {
        return "—".to_string();
    }
    let secs_in_day = ts % 86400;
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn format_kctl_count(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::operator_signing_key_in;
    use kotton_sys::secret::{SecretsError, SecretsResult, SecretsStore};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A store whose every read fails — a locked or unreachable keychain — and
    /// which counts the writes it is asked for, refusing none, so a caller that
    /// minted over it would be seen doing it
    /// (`TASK-a-key-the-store-cannot-read-is-taken-for-no-key-and-a-new-one-is-minted`).
    #[derive(Default)]
    struct UnreadableStore {
        writes: AtomicUsize,
    }

    impl SecretsStore for UnreadableStore {
        fn get_secret(&self, _key: &str) -> SecretsResult<Option<String>> {
            Err(SecretsError::Storage("the keychain did not answer".into()))
        }
        fn set_secret(&self, _key: &str, _value: &str) -> SecretsResult<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn delete_secret(&self, _key: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    /// **An operator key the store cannot read is refused, never minted over.**
    /// The key is enrolled in kdeviced's sudoers set; a fresh one would be a key
    /// nobody enrolled, and the enrolled one would be gone from the store.
    #[test]
    fn an_operator_key_the_store_cannot_read_is_refused_and_never_minted_over() {
        let store = UnreadableStore::default();
        let e = operator_signing_key_in(&store).expect_err("an unreadable store must refuse");
        assert!(e.to_string().contains("the keychain did not answer"), "the read's error is named: {e}");
        assert_eq!(store.writes.load(Ordering::SeqCst), 0, "set_secret was called: a key was minted");
    }

    /// **A stored operator key that does not read as a key is refused, naming
    /// the label, and left as it was** — the record's default for the open half.
    #[test]
    fn a_stored_operator_key_that_does_not_read_as_a_key_is_refused_not_replaced() {
        let store = kotton_secret::MemorySecrets::new();
        let label = kotton_common::crypto::kdf_labels::device_operator_key();
        store.set_secret(&label, "not a key").unwrap();
        let e = operator_signing_key_in(&store).expect_err("a corrupt key must refuse");
        assert!(e.to_string().contains(&label), "the label is named: {e}");
        assert_eq!(store.get_secret(&label).unwrap().as_deref(), Some("not a key"), "left as it was");
    }

    /// A store that holds no operator key is the first use: one is minted and kept.
    #[test]
    fn an_empty_store_mints_and_keeps_the_operator_key() {
        let store = kotton_secret::MemorySecrets::new();
        let key = operator_signing_key_in(&store).unwrap();
        assert_eq!(operator_signing_key_in(&store).unwrap().to_bytes(), key.to_bytes(), "the kept key is read back");
    }
}
