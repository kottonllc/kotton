// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kvaultd` — the node a person rents to keep their data (RFC-0084).
//!
//! ```text
//! kvaultd create --state-dir <dir> --operator <key>
//!                               create the vault for its operator's key, offline
//!                               and before it serves, and print its line
//! kvaultd                       serve: the peer port and the landlord's door
//! kvaultd join <user> <code>    hand a pairing code to the running vault's door
//! kvaultd invite <user> [--ttl secs] [--quota bytes]
//!                               mint an invite, set the pool's quota if
//!                               given, and wait at the relay to be admitted
//! kvaultd capacity <user> [--set bytes]
//!                               bytes held and the pool's own quota; with
//!                               --set, change the quota first
//! kvaultd tenants               every tenant: name, bytes held, quota, and
//!                               how many of their devices are paired here
//! kvaultd drop <user> [--yes]   drop exactly one tenant — their pool, chain,
//!                               sealed recovery copy, pairing and quota —
//!                               after the tenant's name is typed back
//! kvaultd operator enrol <key>  add an operator credential by its public
//!                               half, and print where this vault is
//! kvaultd operator revoke <key>  revoke one (its desktop's standing ends,
//!                               every other operator's stands); never the last
//! kvaultd operator revoke --all --keep <key>
//!                               revoke every operator but the one named
//! ```
//!
//! **A vault is created with its operator, and does not start without one**
//! (RFC-0084 V18, V19; [`kvaultd::instance`]). `create` records the key it is
//! given as the first operator and prints the vault's line; a vault whose
//! state names no operator ends its start in one sentence that names `create`.
//! Every start prints the line again. The line carries no secret.
//!
//! A pool the landlord gave no `--quota` is held to `KVAULTD_QUOTA_BYTES`.
//!
//! `invite` is the way a person at home admits a rented vault: their laptop
//! cannot be dialled and nothing here listens to be, so both meet at the relay
//! this vault stands at — the relay its operator's desktop told it — the three words of the
//! invite being the password. The address the laptop records for the vault is
//! the host's one address, `KOTTON_PUBLIC_ADDR`, announced inside the ceremony.
//!
//! ```sh
//! KOTTON_BASE_DIR=/var/lib/kotton KVAULTD_IPC_NAME=kvaultd \
//! KOTTON_PEER_LISTEN_PORT=7710 KVAULTD_QUOTA_BYTES=1099511627776 kvaultd
//! ```
//!
//! The door is a local socket named by `KVAULTD_IPC_NAME` (default `kvaultd`).
//! `join`, `invite`, `capacity`, `tenants`, `drop` and `operator` are what a
//! landlord does at it, so they are in this binary rather than in a device's shell: a vault's
//! host need not carry the tools of a machine that can read.
//!
//! **A verb typed bare at a host finds the vault running there.** `install.sh`
//! places this binary at `<root>/usr/local/bin/kvaultd` and the vault's settings
//! at `<root>/etc/kotton/vault.env`, which the unit hands the daemon with
//! `EnvironmentFile=`. A verb run from that binary reads the same file itself,
//! so it looks for the door where the daemon made it, and is told the host's
//! address as the daemon was — not where root's login session would put a
//! socket ([`installed_env_file`], [`take_installed_env`]). A caller who names
//! a door in `KVAULTD_IPC_NAME` gets that door, and the file is not read.

use kotton_ipc::IpcClient;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::ipc::{UserRequest, UserResponse, VaultRequest, VaultTenant};
#[cfg(unix)]
use kotton_common::daemon_socket_path;
use kvaultd::settings::env_file_pairs;
use kvaultd::Vault;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use tracing_subscriber::{fmt, EnvFilter};

fn endpoint() -> io::Result<IpcEndpoint> {
    let name = std::env::var("KVAULTD_IPC_NAME").unwrap_or_else(|_| "kvaultd".to_string());
    #[cfg(windows)]
    return Ok(IpcEndpoint::NamedPipe(name));
    #[cfg(unix)]
    Ok(IpcEndpoint::UnixSocket(
        daemon_socket_path(&name).map_err(|e| io::Error::other(e.to_string()))?,
    ))
}

/// Connect to the door as a client of `$req`, or end in the sentence
/// [`unanswered`] says. A macro because the client's bounds are serde's, which
/// this crate does not name.
macro_rules! door {
    ($req:ty) => {{
        let ep = endpoint()?;
        IpcClient::<$req, UserResponse>::connect(ep.clone())
            .await
            .map_err(|_| unanswered(&ep))
    }};
}

/// The sentence a verb ends with when the door does not answer. The client's
/// own error carries no kind, so the door's path is looked at instead: a
/// directory the caller may not enter is the door's policy, anything else is a
/// vault that is not running.
fn unanswered(ep: &IpcEndpoint) -> io::Error {
    #[cfg(unix)]
    let IpcEndpoint::UnixSocket(path) = ep;
    #[cfg(windows)]
    let IpcEndpoint::NamedPipe(path) = ep;
    #[cfg(unix)]
    if matches!(std::fs::metadata(path), Err(e) if e.kind() == io::ErrorKind::PermissionDenied) {
        return io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the vault's door at {} is open to root and the vault's own user, and this is neither",
                Path::new(path).display()
            ),
        );
    }
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no vault is running here: nothing answers at {} (`systemctl status kotton-vault` says why)",
            Path::new(path).display()
        ),
    )
}

/// The env file `install.sh` placed beside this binary, when it was installed:
/// `<root>/usr/local/bin/kvaultd` has its settings at `<root>/etc/kotton/vault.env`,
/// `/` on a host and a directory of its own under `KOTTON_ROOT`. `None` for a
/// binary anywhere else — a build under `target/` has no installed settings.
fn installed_env_file(exe: &Path) -> Option<PathBuf> {
    let bin = exe.parent()?;
    if !bin.ends_with("usr/local/bin") {
        return None;
    }
    Some(bin.parent()?.parent()?.parent()?.join("etc/kotton/vault.env"))
}


/// Take the installed vault's settings into this process, as the unit gives
/// them to the daemon, so a verb typed bare at the host's shell finds the running
/// vault. The file's values win over the caller's, as `EnvironmentFile=` wins
/// over the environment systemd starts with: root's login has an
/// `XDG_RUNTIME_DIR` of its own, which is not where the vault's door is.
///
/// Nothing is read when the caller names a door (`KVAULTD_IPC_NAME`) or when
/// this binary was not installed; a file that is there and closed to the caller
/// is refused in one sentence rather than silently skipped, which would send
/// the verb to a door nobody made. Called before the runtime starts a thread,
/// so setting the environment races nothing.
fn take_installed_env() -> Result<(), String> {
    if std::env::var_os("KVAULTD_IPC_NAME").is_some() {
        return Ok(());
    }
    let Some(file) = std::env::current_exe().ok().as_deref().and_then(installed_env_file) else {
        return Ok(());
    };
    let text = match std::fs::read(&file) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "cannot read {}, where the running vault is named ({e}): run this as root or as the vault's own user",
                file.display()
            ))
        }
    };
    // Read as the installer and systemd read it, or not at all: a line in another form is
    // refused naming it, never trimmed into a setting or taken with its quotes.
    let pairs = env_file_pairs(&text).map_err(|why| {
        format!(
            "{}: {why}; the vault reads its settings only in the plain form install.sh writes (docs/use/run-a-vault.md)",
            file.display()
        )
    })?;
    for (key, value) in pairs {
        std::env::set_var(key, value);
    }
    Ok(())
}

fn main() -> io::Result<()> {
    // The caller's log level, taken before the installed settings: the file's
    // RUST_LOG is the journal's.
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();
    tracing_log::LogTracer::init().ok();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let command = match parse(&args) {
        Ok(command) => command,
        Err(why) => {
            if !why.is_empty() {
                eprintln!("{why}");
            }
            eprintln!("{USAGE}");
            std::process::exit(2)
        }
    };
    // The daemon is told by its unit; a verb — `create` among them — reads the
    // settings the unit hands the daemon, so it is told what the daemon is.
    let serving = command == Command::Serve;
    if !serving {
        if let Err(why) = take_installed_env() {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
    let runtime = tokio::runtime::Runtime::new()?;
    let outcome = runtime.block_on(async {
        match command {
            Command::Serve => {
                let vault = std::sync::Arc::new(Vault::new(endpoint()?).await?);
                // Every start prints the vault's line (RFC-0084 V20): it names
                // the vault's key and where it is reached, and confers nothing.
                println!("{}", vault.line().to_text());
                vault.run().await
            }
            Command::Create { state_dir, operator } => create(state_dir, operator).await,
            Command::Join { user, code } => join(user, code).await,
            Command::Invite { user, ttl, quota } => invite(user, ttl, quota).await,
            Command::Capacity { user, set } => capacity(user, set).await,
            Command::Tenants => tenants().await,
            Command::Drop { user, yes } => drop_tenant(user, yes).await,
            Command::OperatorEnrol { key } => operator_enrol(key).await,
            Command::OperatorRevoke { key } => operator_revoke(key).await,
        }
    });
    match outcome {
        // A failure is a sentence for the person at the shell or in the
        // journal, not a Debug dump — a start refused for want of an operator
        // most of all.
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
        Ok(()) => Ok(()),
    }
}

const USAGE: &str = "usage: kvaultd | kvaultd create --state-dir <dir> --operator <key> | \
                     kvaultd join <user> <code> | \
                     kvaultd invite <user> [--ttl secs] [--quota bytes] | \
                     kvaultd capacity <user> [--set bytes] | \
                     kvaultd tenants | kvaultd drop <user> [--yes] | \
                     kvaultd operator enrol <key> | \
                     kvaultd operator revoke <key> | kvaultd operator revoke --all --keep <key>";

/// What the landlord typed.
#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    Serve,
    Create { state_dir: &'a str, operator: &'a str },
    Join { user: &'a str, code: &'a str },
    Invite { user: &'a str, ttl: u64, quota: Option<u64> },
    Capacity { user: &'a str, set: Option<u64> },
    Tenants,
    Drop { user: &'a str, yes: bool },
    OperatorEnrol { key: &'a str },
    OperatorRevoke { key: Revoke<'a> },
}

/// Which operators a revocation ends: always naming a key, because a vault
/// keeps a set and is never left with none (RFC-0084 V19, fork 3).
#[derive(Debug, PartialEq, Eq)]
enum Revoke<'a> {
    /// This one, never the last.
    One(&'a str),
    /// Every one but this one.
    AllBut(&'a str),
}

/// Read the arguments; `Err` carries the sentence to print above the usage.
fn parse<'a>(args: &[&'a str]) -> Result<Command<'a>, String> {
    let number = |flag: &str, v: &str| {
        v.parse::<u64>()
            .map_err(|_| format!("{flag} takes a number, got '{v}'"))
    };
    match args {
        [] => Ok(Command::Serve),
        ["create", rest @ ..] => {
            let (mut state_dir, mut operator) = (None, None);
            let mut flags = rest.iter();
            while let Some(flag) = flags.next() {
                let value = flags.next().ok_or_else(|| format!("{flag} takes a value"))?;
                match *flag {
                    "--state-dir" if state_dir.is_none() => state_dir = Some(*value),
                    "--operator" if operator.is_none() => operator = Some(*value),
                    other => return Err(format!("create does not take '{other}' here")),
                }
            }
            match (state_dir, operator) {
                (Some(state_dir), Some(operator)) => Ok(Command::Create { state_dir, operator }),
                _ => Err("create takes --state-dir <dir> and --operator <key>, the operator's public key \
                          (64 hex, what the desktop's `mint vault` printed)"
                    .to_string()),
            }
        }
        ["join", user, code] => Ok(Command::Join { user, code }),
        ["invite", user, rest @ ..] => {
            let (mut ttl, mut quota) = (None, None);
            let mut flags = rest.iter();
            while let Some(flag) = flags.next() {
                let value = flags.next().ok_or_else(|| format!("{flag} takes a value"))?;
                match *flag {
                    "--ttl" if ttl.is_none() => ttl = Some(number("--ttl", value)?),
                    "--quota" if quota.is_none() => quota = Some(number("--quota", value)?),
                    other => return Err(format!("invite does not take '{other}' here")),
                }
            }
            Ok(Command::Invite {
                user,
                ttl: ttl.unwrap_or(kvaultd::control::INVITE_TTL_SECS),
                quota,
            })
        }
        ["capacity", user] => Ok(Command::Capacity { user, set: None }),
        ["capacity", user, "--set", bytes] => Ok(Command::Capacity {
            user,
            set: Some(number("--set", bytes)?),
        }),
        ["tenants"] => Ok(Command::Tenants),
        ["drop", user] => Ok(Command::Drop { user, yes: false }),
        ["drop", user, "--yes"] => Ok(Command::Drop { user, yes: true }),
        ["drop", _, other, ..] => Err(format!("drop does not take '{other}' — the flag is --yes")),
        ["operator", "enrol", key] => Ok(Command::OperatorEnrol { key }),
        ["operator", "revoke", "--all", "--keep", keep] => Ok(Command::OperatorRevoke { key: Revoke::AllBut(keep) }),
        ["operator", "revoke", "--all", ..] => Err(
            "revoke --all names the key that stays — `--all --keep <key>`: a vault is never left with no operator"
                .to_string(),
        ),
        ["operator", "revoke", key] if !key.starts_with("--") => Ok(Command::OperatorRevoke { key: Revoke::One(key) }),
        ["operator", "revoke", ..] => Err(
            "revoke takes the key to revoke, or --all --keep <key> — this vault may keep several operators".to_string(),
        ),
        ["operator", ..] => Err("operator takes `enrol <key>`, `revoke <key>` or `revoke --all --keep <key>`".to_string()),
        _ => Err(String::new()),
    }
}

/// Hand a pairing code to the running vault and see the ceremony through: the
/// six digits appear here, the person confirms them on their device, and the
/// landlord confirms here. The vault joins blind; a payload with keys in it is
/// refused by the vault itself, not by this tool.
async fn join(user: &str, code: &str) -> io::Result<()> {
    let ep = endpoint()?;
    let client = IpcClient::<UserRequest, UserResponse>::connect(ep.clone())
        .await
        .map_err(|_| unanswered(&ep))?;
    let mut rx = client
        .send_streaming(&UserRequest::DeviceJoin {
            user_id: user.to_string(),
            code: kotton_wire::ipc::SecretText::new(code),
            as_name: None,
        })
        .await?;
    while let Some(frame) = rx.recv().await {
        match frame {
            UserResponse::PairConnecting => println!("connecting to the device that offered the code…"),
            UserResponse::PairConnected => println!("connected."),
            UserResponse::PairShowCode { token, sas, peer_label } => {
                let who = peer_label.as_deref().unwrap_or("the device");
                println!("type these six digits on {who}: {sas:06}");
                print!("join? [y/N] ");
                io::stdout().flush()?;
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
                let matches = matches!(line.trim(), "y" | "Y" | "yes");
                let mut confirm = IpcClient::<UserRequest, UserResponse>::connect(ep.clone()).await?;
                confirm
                    .send(&UserRequest::PairConfirmCode {
                        user_id: user.to_string(),
                        token,
                        matches,
                    })
                    .await?;
                if !matches {
                    println!("refused.");
                }
            }
            UserResponse::PairAwaitingPeer => println!("waiting for the device to confirm…"),
            UserResponse::PairTransferring => println!("receiving the chain and the sealed recovery copy…"),
            UserResponse::PairingComplete { node, .. } => {
                println!("this vault now keeps for {user}: paired with {} ({}).", node.id, node.device_did);
                return Ok(());
            }
            UserResponse::PairFailed { reason } => {
                eprintln!("pairing failed: {reason}");
                std::process::exit(1);
            }
            // A join the vault refuses before the ceremony starts — a code
            // that is not one, no operational key — arrives in the refusal's
            // own words (`TASK-an-ipc-door-answers-a-handlers-error-by-closing-with-nothing-said`).
            UserResponse::Error { message } => {
                eprintln!("{message}");
                std::process::exit(1);
            }
            _ => {}
        }
    }
    Err(io::Error::other("the vault closed the ceremony without a result"))
}

/// Mint an invite and wait to be admitted through the relay: print the invite
/// for the landlord to hand the person, then the six digits when their device
/// dials. Nothing listens on a public port, so this can run on the day the host
/// is set up rather than the minute of pairing; the default window is a day.
/// The person's device is the gate — they type the six there — so this side
/// confirms on sight, as a gateway does. Lines are `key=value` on stdout.
///
/// `quota`, when given, is set once the vault has minted the invite and before
/// the invite is printed (`TASK-networking-is-the-drawn-one`, 2026-09-23): an
/// invite the vault refuses — `user` is someone it already keeps — sets
/// nothing, and the pool is still never admitted under anything but the
/// landlord's number, because nobody can take an invite not yet printed.
async fn invite(user: &str, ttl_seconds: u64, quota: Option<u64>) -> io::Result<()> {
    let ep = endpoint()?;
    let client = IpcClient::<UserRequest, UserResponse>::connect(ep.clone())
        .await
        .map_err(|_| unanswered(&ep))?;
    let mut rx = client
        .send_streaming(&UserRequest::DeviceInvite {
            user_id: user.to_string(),
            ttl_seconds,
            as_name: None,
        })
        .await?;
    while let Some(frame) = rx.recv().await {
        match frame {
            UserResponse::PairAdvertising { code, expires_at } => {
                if let Some(q) = quota {
                    set_quota(user, q).await?;
                }
                let code = code.expose();
                println!("invite={code}");
                eprintln!("on the person's device: `device admit {code}`  (until {expires_at})");
            }
            UserResponse::PairShowCode { token, sas, .. } => {
                println!("sas={sas:06}");
                eprintln!("type these six on the person's device. nothing is handed over until they match there.");
                let mut confirm = IpcClient::<UserRequest, UserResponse>::connect(ep.clone()).await?;
                confirm
                    .send(&UserRequest::PairConfirmCode {
                        user_id: user.to_string(),
                        token,
                        matches: true,
                    })
                    .await?;
            }
            UserResponse::PairTransferring => eprintln!("receiving the chain and the sealed recovery copy…"),
            UserResponse::PairingComplete { node, .. } => {
                println!("enrolled={}", node.id);
                eprintln!("this vault now keeps for {user}: paired with {} ({}).", node.id, node.device_did);
                return Ok(());
            }
            UserResponse::PairFailed { reason } => {
                eprintln!("pairing failed: {reason}");
                std::process::exit(1);
            }
            UserResponse::Error { message } => {
                eprintln!("{message}");
                std::process::exit(1);
            }
            _ => {}
        }
    }
    Err(io::Error::other("the vault closed the ceremony without a result"))
}

/// Set the pool's own quota at the door. The verb is the door's alone
/// (`VaultRequest::SetQuota`): a tenant's device has no way to say it.
async fn set_quota(user: &str, quota: u64) -> io::Result<(u64, Option<u64>)> {
    let mut client = door!(VaultRequest)?;
    match client
        .send(&VaultRequest::SetQuota {
            user_id: user.to_string(),
            quota,
        })
        .await?
    {
        UserResponse::VaultCapacityResult { held, quota } => Ok((held, quota)),
        UserResponse::Error { message } => Err(io::Error::other(message)),
        other => Err(io::Error::other(format!("unexpected answer: {other:?}"))),
    }
}

/// The pool's readout — bytes held and its own quota — after setting the
/// quota when `--set` was given.
async fn capacity(user: &str, set: Option<u64>) -> io::Result<()> {
    let (held, quota) = match set {
        Some(q) => set_quota(user, q).await?,
        None => {
            let mut client = door!(UserRequest)?;
            match client
                .send(&UserRequest::VaultCapacity {
                    user_id: user.to_string(),
                })
                .await?
            {
                UserResponse::VaultCapacityResult { held, quota } => (held, quota),
                UserResponse::Error { message } => return Err(io::Error::other(message)),
                other => return Err(io::Error::other(format!("unexpected answer: {other:?}"))),
            }
        }
    };
    println!("held   {held} bytes");
    match quota {
        Some(q) => println!("quota  {q} bytes"),
        None => println!("quota  none"),
    }
    Ok(())
}

/// Ask the door for every tenant's readout.
async fn list_tenants() -> io::Result<Vec<VaultTenant>> {
    let mut client = door!(VaultRequest)?;
    match client.send(&VaultRequest::Tenants).await? {
        UserResponse::VaultTenants { tenants } => Ok(tenants),
        UserResponse::Error { message } => Err(io::Error::other(message)),
        other => Err(io::Error::other(format!("unexpected answer: {other:?}"))),
    }
}

fn quota_text(quota: Option<u64>) -> String {
    quota.map_or_else(|| "none".to_string(), |q| q.to_string())
}

/// Every tenant, one line each: the name, bytes held, the quota and how many
/// devices are paired. Nothing that names a device or a key.
async fn tenants() -> io::Result<()> {
    let tenants = list_tenants().await?;
    if tenants.is_empty() {
        println!("this vault keeps for no one");
        return Ok(());
    }
    let width = tenants.iter().map(|t| t.user_id.len()).max().unwrap_or(0).max("tenant".len());
    println!("{:<width$}  {:>15}  {:>15}  {:>7}", "tenant", "held (bytes)", "quota (bytes)", "devices");
    for t in &tenants {
        println!(
            "{:<width$}  {:>15}  {:>15}  {:>7}",
            t.user_id,
            t.held,
            quota_text(t.quota),
            t.devices
        );
    }
    Ok(())
}

/// Drop exactly one tenant. Says what goes, and asks for the tenant's name
/// back unless `--yes` — the one confirmation, since `docker compose down -v`
/// asks none.
async fn drop_tenant(user: &str, yes: bool) -> io::Result<()> {
    let Some(tenant) = list_tenants().await?.into_iter().find(|t| t.user_id == user) else {
        eprintln!("this vault keeps nothing under '{user}' — `kvaultd tenants` lists who it keeps for");
        std::process::exit(1);
    };
    println!(
        "drop '{user}': their sealed pool ({} bytes), identity chain and sealed recovery copy,",
        tenant.held
    );
    println!(
        "the pairing of {} device(s) and their quota ({}). Nothing of any other tenant's is touched.",
        tenant.devices,
        quota_text(tenant.quota)
    );
    println!("Their data stays theirs, on their own devices; a device of theirs that holds only the");
    println!("phrase can no longer recover from this vault.");
    if !yes {
        print!("type the tenant's name to confirm: ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if line.trim() != user {
            println!("not dropped");
            std::process::exit(1);
        }
    }
    let mut client = door!(VaultRequest)?;
    match client
        .send(&VaultRequest::DropTenant {
            user_id: user.to_string(),
        })
        .await?
    {
        UserResponse::TenantDropped { tenant } => {
            println!(
                "dropped={}  ({} bytes, {} device(s) unpaired)",
                tenant.user_id, tenant.held, tenant.devices
            );
            Ok(())
        }
        UserResponse::Error { message } => {
            eprintln!("{message}");
            std::process::exit(1);
        }
        other => Err(io::Error::other(format!("unexpected answer: {other:?}"))),
    }
}

/// Connect to the door, waiting for it while the vault starts: `operator enrol`
/// may be typed the moment `systemctl enable --now` returns, before the vault
/// has necessarily bound its socket. Thirty seconds of nothing ends in the
/// sentence [`unanswered`] says.
async fn door_when_ready() -> io::Result<IpcClient<VaultRequest, UserResponse>> {
    let ep = endpoint()?;
    let mut tries = 0;
    loop {
        match IpcClient::<VaultRequest, UserResponse>::connect(ep.clone()).await {
            Ok(c) => return Ok(c),
            Err(e) if tries < 30 => {
                tries += 1;
                tracing::debug!(error = %e, "the door is not up yet");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(_) => return Err(unanswered(&ep)),
        }
    }
}

/// Ask the door one thing and read one answer.
async fn ask_door(request: &VaultRequest) -> io::Result<UserResponse> {
    door_when_ready().await?.send(request).await
}

/// Create the vault at `state_dir` for `operator` and print its line as the
/// last output (RFC-0084 V18). Its key is kept where the serving vault's
/// secrets provider keeps it — under the settings this verb read as the
/// daemon's unit reads them — and the line names the address and port those
/// settings announce.
async fn create(state_dir: &str, operator: &str) -> io::Result<()> {
    // The directory first — the one write `create` makes before its lock —
    // made `0700` when absent, and on the path as given checked before it is
    // resolved: a symlinked leaf is refused here, not followed, and an
    // existing directory that is not this user's and closed is refused
    // unchanged (`instance::own_state_dir`). Then the path is decided from what
    // it really is: `..`, a symlinked parent and a temporary directory under
    // another name all resolve, and whether the key will outlive this process
    // is asked of that, once.
    let asked = std::path::absolute(state_dir)?;
    // Every directory this makes, the leaf first, so a refusal removes them all
    // and leaves the tree as it found it.
    let made: Vec<PathBuf> = asked.ancestors().take_while(|d| !d.exists()).map(Path::to_path_buf).collect();
    kvaultd::instance::own_state_dir(&asked)?;
    let state_dir = std::fs::canonicalize(&asked)?;
    let provider = kotton_secret::SecretsProvider::for_base_dir(&state_dir);
    if !provider.outlives_the_process() {
        // Only directories this made, and only while empty: `remove_dir`
        // refuses anything that holds something.
        for dir in &made {
            let _ = std::fs::remove_dir(dir);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is under the system's temporary directory, where a vault's key is kept in memory only \
                 (KOTTON_SECRETS is not read there), so the key create made would be gone when it exits and \
                 the vault could never start: nothing was created — give a state directory outside it",
                state_dir.display()
            ),
        ));
    }
    let public_ip = match std::env::var("KOTTON_PUBLIC_ADDR") {
        Ok(v) if !v.trim().is_empty() => Some(kotton_net::resolve_advertise(&format!("{}:0", v.trim())).await?.ip()),
        _ => None,
    };
    let port = std::env::var("KOTTON_PEER_LISTEN_PORT").ok().and_then(|p| p.trim().parse::<u16>().ok());
    let line = kvaultd::instance::create_recorded(&state_dir, provider, operator, kvaultd::instance::hint(public_ip, port)).await?;
    if line.hint.is_empty() {
        eprintln!(
            "this vault announces no address (KOTTON_PUBLIC_ADDR and KOTTON_PEER_LISTEN_PORT), so its line names \
             nowhere to reach it — a vault with no public address is not on 0.1's path"
        );
    }
    println!("{}", line.to_text());
    Ok(())
}

/// Enrol the operator credential's public half — a second operator, beside the
/// one the vault was created for — then print the vault's line (RFC-0084 V20):
/// its key, and the host's one address and the peer port, as creation and every
/// start print it. The line confers nothing. The person pastes it into their
/// desktop's `enrol <line>`, which completes the key it minted
/// (DEC-0083) and holds the vault to the key the line names. No relay: where a
/// vault stands is what its operator's desktop tells it after the enrol
/// (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`).
async fn operator_enrol(key: &str) -> io::Result<()> {
    match ask_door(&VaultRequest::OperatorAdmit { key: key.to_string() }).await? {
        UserResponse::Ok => {}
        UserResponse::Error { message } => {
            eprintln!("{message}");
            std::process::exit(1);
        }
        other => return Err(io::Error::other(format!("unexpected answer: {other:?}"))),
    }
    let vault_key: [u8; 32] = match ask_door(&VaultRequest::GetNodeIdentity).await? {
        UserResponse::NodeIdentity { signing_pubkey_hex, .. } => hex::decode(&signing_pubkey_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| io::Error::other(format!("the vault named a key that is not 32 bytes: {signing_pubkey_hex}")))?,
        other => return Err(io::Error::other(format!("unexpected answer: {other:?}"))),
    };
    let public_ip = match std::env::var("KOTTON_PUBLIC_ADDR") {
        Ok(v) if !v.trim().is_empty() => Some(kotton_net::resolve_advertise(&format!("{}:0", v.trim())).await?.ip()),
        _ => None,
    };
    let port = std::env::var("KOTTON_PEER_LISTEN_PORT").ok().and_then(|p| p.trim().parse::<u16>().ok());
    let line = kvaultd::instance::line(kvaultd::instance::hint(public_ip, port), vault_key);
    if line.hint.is_empty() {
        eprintln!(
            "this vault announces no address (KOTTON_PUBLIC_ADDR), so its desktop has nowhere to reach it — \
             a vault with no public address is not on 0.1's path"
        );
    }
    println!("{}", line.to_text());
    // Said, not printed as a line: the desktop tells it, after its `enrol`.
    match ask_door(&VaultRequest::NodeRelay { user_id: String::new() }).await? {
        UserResponse::NodeRelayResult { relay_url: Some(url), .. } => {
            eprintln!("this vault stands at {url}, as its operator's desktop last told it")
        }
        _ => eprintln!("this vault stands at no relay until its operator's desktop tells it where — its `enrol <this line>` does"),
    }
    eprintln!("the operator credential is enrolled: its desktop may invite, list, resize and drop, and nothing else");
    Ok(())
}

/// Revoke one operator credential, or every one but the one named. The
/// desktop holding a revoked one is refused its next request; every other
/// operator's stands. The vault refuses to revoke its last.
async fn operator_revoke(key: Revoke<'_>) -> io::Result<()> {
    let request = match key {
        Revoke::One(key) => VaultRequest::OperatorRevoke { key: key.to_string() },
        Revoke::AllBut(keep) => VaultRequest::OperatorRevokeAllBut { keep: keep.to_string() },
    };
    match ask_door(&request).await? {
        UserResponse::Ok => {
            match key {
                Revoke::One(_) => println!("revoked: that operator credential has no standing at this vault"),
                Revoke::AllBut(_) => println!("revoked: only the operator credential named has standing at this vault"),
            }
            Ok(())
        }
        UserResponse::Error { message } => {
            eprintln!("{message}");
            std::process::exit(1);
        }
        other => Err(io::Error::other(format!("unexpected answer: {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_installed_binary_has_an_env_file_beside_it() {
        assert_eq!(
            installed_env_file(Path::new("/usr/local/bin/kvaultd")),
            Some(PathBuf::from("/etc/kotton/vault.env"))
        );
        assert_eq!(
            installed_env_file(Path::new("/srv/staged/usr/local/bin/kvaultd")),
            Some(PathBuf::from("/srv/staged/etc/kotton/vault.env")),
            "under KOTTON_ROOT, the file install.sh placed beside it"
        );
        assert_eq!(installed_env_file(Path::new("/home/me/kotton/target/debug/kvaultd")), None);
        assert_eq!(installed_env_file(Path::new("/usr/bin/kvaultd")), None);
        assert_eq!(installed_env_file(Path::new("/opt/local/bin/kvaultd")), None);
    }

    #[test]
    fn invite_takes_a_quota_and_a_ttl_in_either_order() {
        assert_eq!(
            parse(&["invite", "alice"]),
            Ok(Command::Invite {
                user: "alice",
                ttl: 86_400,
                quota: None
            })
        );
        assert_eq!(
            parse(&["invite", "alice", "--quota", "1073741824"]),
            Ok(Command::Invite {
                user: "alice",
                ttl: 86_400,
                quota: Some(1 << 30)
            })
        );
        assert_eq!(
            parse(&["invite", "alice", "--quota", "5", "--ttl", "60"]),
            parse(&["invite", "alice", "--ttl", "60", "--quota", "5"]),
        );
        assert!(parse(&["invite", "alice", "--quota"]).is_err(), "a flag with no value");
        assert!(parse(&["invite", "alice", "--quota", "lots"]).is_err());
        assert!(parse(&["invite", "alice", "--quota", "1", "--quota", "2"]).is_err());
        assert!(parse(&["invite", "alice", "--size", "1"]).is_err());
    }

    #[test]
    fn capacity_reads_or_sets_the_pools_number() {
        assert_eq!(
            parse(&["capacity", "bob"]),
            Ok(Command::Capacity { user: "bob", set: None })
        );
        assert_eq!(
            parse(&["capacity", "bob", "--set", "4096"]),
            Ok(Command::Capacity {
                user: "bob",
                set: Some(4096)
            })
        );
        assert!(parse(&["capacity", "bob", "--set", "-1"]).is_err());
        assert!(parse(&["capacity", "bob", "--raise", "1"]).is_err());
    }

    #[test]
    fn tenants_takes_nothing_and_drop_takes_one_name_and_yes() {
        assert_eq!(parse(&["tenants"]), Ok(Command::Tenants));
        assert!(parse(&["tenants", "alice"]).is_err());
        assert_eq!(
            parse(&["drop", "alice"]),
            Ok(Command::Drop { user: "alice", yes: false })
        );
        assert_eq!(
            parse(&["drop", "alice", "--yes"]),
            Ok(Command::Drop { user: "alice", yes: true })
        );
        assert!(parse(&["drop"]).is_err(), "a drop names one tenant");
        assert!(parse(&["drop", "alice", "bob"]).is_err(), "and only one");
        assert!(parse(&["drop", "alice", "--force"]).is_err());
    }

    #[test]
    fn operator_enrols_one_key_or_revokes() {
        assert_eq!(
            parse(&["operator", "enrol", "ab"]),
            Ok(Command::OperatorEnrol { key: "ab" })
        );
        assert_eq!(
            parse(&["operator", "revoke", "--all", "--keep", "cd"]),
            Ok(Command::OperatorRevoke { key: Revoke::AllBut("cd") })
        );
        assert_eq!(
            parse(&["operator", "revoke", "ab"]),
            Ok(Command::OperatorRevoke { key: Revoke::One("ab") })
        );
        // A vault keeps a set: a bare revoke would not say whose standing ends,
        // and `--all` alone would leave it with none (RFC-0084 V19, fork 3).
        assert!(parse(&["operator", "revoke"]).is_err());
        assert!(parse(&["operator", "revoke", "--all"]).is_err());
        assert!(parse(&["operator", "revoke", "--all", "--keep"]).is_err());
        assert!(parse(&["operator"]).is_err());
        assert!(parse(&["operator", "enrol"]).is_err(), "enrol names the key");
        assert!(parse(&["operator", "revoke", "ab", "cd"]).is_err(), "revoke names one key");
    }

    #[test]
    fn create_takes_a_state_directory_and_an_operator_key_in_either_order() {
        assert_eq!(
            parse(&["create", "--state-dir", "/var/lib/kotton-vault", "--operator", "ab"]),
            Ok(Command::Create { state_dir: "/var/lib/kotton-vault", operator: "ab" })
        );
        assert_eq!(
            parse(&["create", "--operator", "ab", "--state-dir", "/s"]),
            parse(&["create", "--state-dir", "/s", "--operator", "ab"]),
        );
        assert!(parse(&["create"]).is_err(), "creation is for a key, in a directory");
        assert!(parse(&["create", "--state-dir", "/s"]).is_err(), "no operator, no vault");
        assert!(parse(&["create", "--operator", "ab"]).is_err());
        assert!(parse(&["create", "--state-dir", "/s", "--operator"]).is_err());
        assert!(parse(&["create", "--state-dir", "/s", "--operator", "ab", "--operator", "cd"]).is_err());
        assert!(parse(&["claim"]).is_err(), "there is no claim");
    }
}
