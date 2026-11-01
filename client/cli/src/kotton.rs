// SPDX-License-Identifier: AGPL-3.0-or-later
use clap::Parser;
use kotton_cli::commands::{Commands, ReplCommand};
use kotton_cli::Cli;
use std::io;
use std::process::ExitCode;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> ExitCode {
    kotton_cli::finish(run().await)
}

async fn run() -> io::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();
    // Resolve the active identity into KOTTON_USER before clap parses, so a bare
    // command acts as the chosen identity (never a silent default). An explicit
    // --user flag still wins.
    kotton_cli::active_identity::apply_to_env();
    let cli = Cli::parse();
    let json = cli.json;

    // The front door is the runtime, not a help wall: bare `kotton` enters the REPL
    // as the active identity (or onboards). Verbs remain for scripting.
    let Some(command) = cli.command else {
        let user_id = std::env::var("KOTTON_USER").ok().filter(|v| !v.is_empty());
        return ReplCommand { user_id }.execute().await;
    };

    match command {
        Commands::App { user, args } => kotton_cli::bridge::run_verb(user, "app", args, json).await,
        Commands::Login(cmd) => cmd.execute().await,
        Commands::Id(cmd) => cmd.execute().await,
        Commands::Whoami => kotton_cli::commands::whoami::run().await,
        Commands::Repl(cmd) | Commands::Shell(cmd) => cmd.execute().await,
        Commands::Peer { user, args } => kotton_cli::bridge::run_verb(user, "peer", args, json).await,
        // `reset` is the one `device` subcommand that is not the REPL's. It acts
        // on this device's own directory and keychain, so it must not need the
        // daemon that lives in them — see `commands::device`.
        Commands::Device { user, args } if args.first().map(String::as_str) != Some("reset") => {
            kotton_cli::bridge::run_verb(user, "device", args, json).await
        }
        Commands::Device { args, .. } => kotton_cli::commands::device::reset(&args[1..]).await,
        Commands::Schema(cmd) => cmd.execute().await,
        Commands::Handler(cmd) => cmd.execute().await,
        Commands::Record(cmd) => cmd.execute().await,
        Commands::Records(cmd) => cmd.execute().await,
        Commands::Import(cmd) => cmd.execute().await,
        Commands::Sync { user, args } => kotton_cli::bridge::run_verb(user, "sync", args, json).await,
        Commands::Drive { user, args } => kotton_cli::bridge::run_verb(user, "drive", args, json).await,
        Commands::Pin { user, args } => kotton_cli::bridge::run_verb(user, "pin", args, json).await,
        Commands::Status { user, args } => kotton_cli::bridge::run_verb(user, "status", args, json).await,
        Commands::Logs { user, args } => kotton_cli::bridge::run_verb(user, "logs", args, json).await,
        Commands::Issuer { user, args } => kotton_cli::bridge::run_verb(user, "issuer", args, json).await,
        Commands::Cp { user, args } => kotton_cli::bridge::run_verb(user, "cp", args, json).await,
        Commands::Cat { user, args } => kotton_cli::bridge::run_verb(user, "cat", args, json).await,
        Commands::Keep { user, args } => kotton_cli::bridge::run_verb(user, "keep", args, json).await,
        Commands::Mint { user, args } => kotton_cli::bridge::run_verb(user, "mint", args, json).await,
        Commands::Enrol { user, args } => kotton_cli::bridge::run_verb(user, "enrol", args, json).await,
        Commands::Relay { user, args } => kotton_cli::bridge::run_verb(user, "relay", args, json).await,
        Commands::Vault { user, args } => kotton_cli::bridge::run_verb(user, "vault", args, json).await,
        Commands::Grant(cmd) => cmd.execute().await,
        Commands::Extension(cmd) => cmd.execute().await,
        Commands::Contact(cmd) => cmd.execute().await,
        Commands::Message(cmd) => cmd.execute().await,
        Commands::Org(cmd) => cmd.execute().await,
        Commands::Config(cmd) => cmd.execute().await,
        Commands::Model(cmd) => cmd.execute().await,
        Commands::Sidecars(cmd) => cmd.execute().await,
        Commands::Ipc(cmd) => cmd.execute().await,
        Commands::Net(cmd) => cmd.execute().await,
        Commands::Vfs(cmd) => cmd.execute().await,
    }
}
