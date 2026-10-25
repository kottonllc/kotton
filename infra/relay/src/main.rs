// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton-relay` — peer address exchange and DM store-and-forward server.
//!
//! # Usage
//!
//! Plain HTTP (dev / behind a reverse proxy):
//! ```sh
//! kotton-relay --bind 0.0.0.0:7700
//! ```
//!
//! With TLS (production):
//! ```sh
//! kotton-relay --bind 0.0.0.0:7701 \
//!              --tls-cert /etc/kotton/relay.crt \
//!              --tls-key  /etc/kotton/relay.key
//! ```
//!
//! A relay is created for its operator's key, and does not start without one
//! (RFC-0084 V18, V19; [`instance`]). Its one rule, and who may set it
//! (`--state-dir`, or `KOTTON_RELAY_STATE_DIR`):
//! ```sh
//! kotton-relay --state-dir … create --operator <key>          # once, before it serves; prints its line
//! kotton-relay --state-dir /var/lib/kotton-relay              # serve; the rule is kept here
//! kotton-relay --state-dir … operator enrol <key>             # at the terminal only, to a set that has one
//! kotton-relay --state-dir … operator revoke <key>            # never the last
//! kotton-relay --state-dir … operator revoke --all --keep <key>
//! kotton-relay --operator <key>                               # no state directory: created as it starts
//! ```
//!
//! Its own key is kept there too, made at creation (`identity.key`), and
//! proved to whoever asks at `GET /identity?nonce=<hex>`; `--advertise` (or
//! `KOTTON_RELAY_ADVERTISE`) is the address it signs beside the nonce, and the
//! hint its line carries. Every start prints the line; it carries no secret.
//! Once its sockets are bound it prints where it listens, as the OS bound them,
//! `listening http=<addr> stun=<addr>`: with `--bind 127.0.0.1:0` that line is
//! the one meant to be read for the port it was given (the `info` log says it
//! too, as a log, and only at that level).

mod admission;
mod auth;
mod circuit;
mod identity;
#[cfg(test)]
mod identity_tests;
mod instance;
#[cfg(test)]
mod instance_tests;
mod logid;
#[cfg(test)]
mod operator_file_tests;
#[cfg(test)]
mod rule_tests;
mod server;
mod store;
mod stun;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use server::{build_router, AppState};
use store::{spawn_eviction_task, RendezvousStore};

#[derive(Parser, Debug)]
#[command(
    name = "kotton-relay",
    version,
    about = "The Kotton relay: address exchange and blind circuits between a user's devices. It carries and keeps nothing."
)]
struct Cli {
    /// Address and port to listen on.
    #[arg(long, env = "KOTTON_RELAY_BIND", default_value = "0.0.0.0:7700")]
    bind: SocketAddr,

    /// Path to TLS certificate (PEM). When provided, `--tls-key` must also be set.
    #[arg(long, env = "KOTTON_RELAY_TLS_CERT")]
    tls_cert: Option<std::path::PathBuf>,

    /// Path to TLS private key (PEM). When provided, `--tls-cert` must also be set.
    #[arg(long, env = "KOTTON_RELAY_TLS_KEY")]
    tls_key: Option<std::path::PathBuf>,

    /// TTL in seconds for stored address entries.
    #[arg(long, env = "KOTTON_RELAY_TTL", default_value_t = 60)]
    ttl: u32,

    /// Disable signed Authorization header requirement on lookup requests.
    /// Useful for development; not recommended in production.
    #[arg(long, env = "KOTTON_RELAY_NO_AUTH_LOOKUP", default_value_t = false)]
    no_auth_lookup: bool,

    /// Path to the SQLite database file for the DM inbox store.
    /// Blobs are persisted here and survive relay restarts.
    /// UDP address for the built-in STUN binding responder (reflexive-address
    /// discovery), so nodes need no 3rd-party STUN server (RFC-0024 / sprint 07).
    #[arg(long, env = "KOTTON_RELAY_STUN_BIND", default_value = "0.0.0.0:7700")]
    stun_bind: SocketAddr,

    /// Where the relay keeps its one rule and its operators' keys — the relay's
    /// own configuration and none of what it carries. Absent, the relay is
    /// created as it starts, for `--operator`, and keeps its rule, its key and
    /// that operator in memory.
    #[arg(long, env = "KOTTON_RELAY_STATE_DIR", global = true)]
    state_dir: Option<std::path::PathBuf>,

    /// The address this relay announces about itself, signed into every answer
    /// to `GET /identity` so a dialler learns where the relay says it is. A hint,
    /// never a name: the relay is its key. Empty announces none.
    #[arg(long, env = "KOTTON_RELAY_ADVERTISE", default_value = "", global = true)]
    advertise: String,

    /// The operator a relay with no state directory is created for, as it
    /// starts: 64 hex, the public key the desktop's `mint relay` printed. A
    /// relay with a state directory is created by `create --operator`.
    #[arg(long)]
    operator: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Create this relay for its operator's key, before it serves, and print its
    /// line (RFC-0084 V18). Over state that names no operator, adopt it, keeping
    /// its key; over state that has one, refuse and change nothing.
    Create {
        /// The operator's public key, 64 hex.
        #[arg(long)]
        operator: String,
    },
    /// Who may set the rule — at this terminal only, never over the wire.
    Operator {
        #[command(subcommand)]
        action: OperatorAction,
    },
}

#[derive(clap::Subcommand, Debug)]
enum OperatorAction {
    /// Add one operator key (64 hex, the public key the desktop's `mint relay`
    /// printed) to a relay that has an operator, and leave the others.
    Enrol { key: String },
    /// End one operator's standing — never the last — or, with `--all --keep
    /// <key>`, every one but that. Their next request is refused.
    Revoke {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        key: Option<String>,
        #[arg(long, requires = "keep")]
        all: bool,
        /// With `--all`: the operator that stays.
        #[arg(long, requires = "all")]
        keep: Option<String>,
    },
}

/// The terminal's verbs: they edit the operators' file and exit. A running relay
/// reads that file on every operator request, so neither needs a restart.
///
/// Typed as root at a directory the relay's user owns, the verb is typed again by
/// this binary as that user, and root opens nothing there by a path that user
/// could have planted ([`admission::type_verb`]).
fn operator_command(dir: Option<&std::path::Path>, action: OperatorAction) -> anyhow::Result<()> {
    let dir = dir.context("an operator is kept in the state directory: pass --state-dir or set KOTTON_RELAY_STATE_DIR")?;
    let verb = match &action {
        OperatorAction::Enrol { key } => admission::Verb::Enrol(key),
        OperatorAction::Revoke { key: Some(key), .. } => admission::Verb::Revoke(key),
        OperatorAction::Revoke { keep: Some(keep), .. } => admission::Verb::RevokeAllBut(keep),
        OperatorAction::Revoke { .. } => anyhow::bail!("revoke names a key, or --all --keep <key>"),
    };
    type_at(dir, verb)
}

/// `kotton-relay create`: typed as the state directory's owner, as the operator
/// verbs are, after making the directory if it is not there — as the user who
/// typed it, `0700`. The self-host adapter runs it as the relay's own user.
fn create_command(dir: Option<&std::path::Path>, operator: &str, advertise: &str) -> anyhow::Result<()> {
    let dir = dir.context("a relay is created in its state directory: pass --state-dir or set KOTTON_RELAY_STATE_DIR")?;
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    type_at(dir, admission::Verb::Create { operator, advertise })
}

/// Type `verb` at `dir` ([`admission::type_verb`]) and print what it said.
fn type_at(dir: &std::path::Path, verb: admission::Verb<'_>) -> anyhow::Result<()> {
    let said = admission::type_verb(dir, verb, || {
        let mut again = std::process::Command::new(std::env::current_exe()?);
        again
            .env_clear()
            .arg("--state-dir")
            .arg(std::path::absolute(dir)?)
            .args(verb.args());
        Ok(again)
    })?;
    println!("{said}");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logging — respect RUST_LOG; default to info for this crate.
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("kotton_relay=info,tower_http=warn")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Operator { action }) => return operator_command(cli.state_dir.as_deref(), action),
        Some(Command::Create { operator }) => {
            return create_command(cli.state_dir.as_deref(), &operator, &cli.advertise)
        }
        None => {}
    }

    // No relay exists unowned (RFC-0084 V19). Before anything is bound: a
    // relay with a state directory holds it alone and names an operator there;
    // one with none is created now, for `--operator`, or does not start.
    let (admission, identity, _held) = match cli.state_dir.as_deref() {
        Some(dir) => {
            anyhow::ensure!(cli.operator.is_none(), "--operator creates a relay with no state directory; this one is created by `kotton-relay --state-dir {} create --operator <key>`", dir.display());
            // Held first, before anything in it is read: a `create` mid-run is
            // never read half-written. A directory that is not there was never
            // created, and is not made here.
            anyhow::ensure!(dir.is_dir(), "{}", instance::no_operator(dir));
            let held = instance::StateLock::take(dir)?;
            instance::refuse_unless_operated(dir)?;
            // A relay operated before the claim was deleted may still keep its
            // file, with a secret in it: removed at every start, as at adoption.
            instance::remove_leftover_secret(dir)?;
            let admission = admission::Admission::open(dir)?;
            let key = instance::existing_key(dir)?;
            (admission, key, Some(held))
        }
        None => {
            let operator = cli.operator.as_deref().context(instance::NO_OPERATOR_IN_MEMORY)?;
            anyhow::ensure!(
                admission::is_key_hex(operator),
                "--operator is 64 hex characters, the public key the desktop's `mint relay` printed"
            );
            (admission::Admission::in_memory(operator, Default::default()), identity::RelayKey::in_memory(), None)
        }
    };
    info!(rule = ?admission.rule(), kept = cli.state_dir.is_some(), "relay admission rule");
    info!(key = %identity.public_hex(), advertise = %cli.advertise, "relay key");
    // Every start prints the relay's line (RFC-0084 V20): its key and where it
    // says it is reached. It confers nothing, so the journal may keep it.
    println!("{}", instance::line(&identity, &cli.advertise).to_text());

    let store = RendezvousStore::new();
    spawn_eviction_task(store.clone());

    // Built-in STUN responder (UDP) — reflexive-address discovery without a
    // 3rd-party STUN server (RFC-0024 / sprint 07).
    let stun_sock = tokio::net::UdpSocket::bind(cli.stun_bind)
        .await
        .context("failed to bind STUN responder UDP socket")?;
    let stun_bound = stun_sock.local_addr()?;
    info!(stun_bind = %stun_bound, "kotton-relay STUN responder listening (UDP)");
    tokio::spawn(stun::run_stun_responder(stun_sock));

    let state = Arc::new(AppState {
        store,
        ttl_secs: cli.ttl,
        require_lookup_auth: !cli.no_auth_lookup,
        admission,
        circuits: circuit::Circuits::new(),
        identity,
        advertise: cli.advertise,
    });

    let router = build_router(state);

    let tls = match (cli.tls_cert, cli.tls_key) {
        (Some(cert), Some(key)) => {
            Some(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?)
        }
        (None, None) => None,
        _ => anyhow::bail!("--tls-cert and --tls-key must be provided together"),
    };
    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    let bound = listener.local_addr()?;
    // Where it listens, read off the sockets rather than from `--bind`: a bind on
    // port 0 is given its port by the OS, and this line is the one meant to be
    // read for that port; the `info!` lines below are logs. Printed once both are bound, so whoever reads it can dial.
    println!("{}", listening_line(bound, stun_bound));

    match tls {
        Some(tls_config) => {
            info!(bind = %bound, "kotton-relay starting (TLS)");
            axum_server::from_tcp_rustls(listener.into_std()?, tls_config)
                .serve(router.into_make_service())
                .await?;
        }
        None => {
            info!(bind = %bound, "kotton-relay starting (plain HTTP)");
            axum::serve(listener, router).await?;
        }
    }

    Ok(())
}

/// What a start prints once its HTTP listener and its STUN socket are bound:
/// `listening http=<addr> stun=<addr>`, each the address the OS bound.
fn listening_line(http: SocketAddr, stun: SocketAddr) -> String {
    format!("listening http={http} stun={stun}")
}
