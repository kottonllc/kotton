// SPDX-License-Identifier: AGPL-3.0-or-later
use clap::Subcommand;

mod config;
mod contact;
pub mod device;
mod extension;
mod frost_org;
mod grant;
mod handler;
pub mod id;
mod recover;
mod import;
mod ipc;
mod login;
mod message;
mod model;
mod net;
mod org;
mod record;
mod records;
mod repl;
mod schema;
mod sidecars;
mod vfs;
pub mod whoami;
pub use config::ConfigCommand;
pub use contact::ContactCommand;
pub use extension::ExtensionCommand;
pub use frost_org::FrostOrgCommand;
pub use grant::GrantCommand;
pub use handler::HandlerCommand;
pub use id::IdCommand;
pub use import::ImportCommand;
pub use ipc::IpcCommand;
pub use login::LoginCommand;
pub use message::MessageCommand;
pub use model::ModelCommand;
pub use net::NetCommand;
pub use org::OrgCommand;
pub use record::RecordCommand;
pub use records::RecordsCommand;
pub use repl::ReplCommand;
pub use schema::SchemaCommand;
pub use sidecars::SidecarsCommand;
pub use vfs::VfsCommand;

/// One word handed through to a shared verb: anything but `--user`, which is refused.
///
/// The verbs' words are raw (`trailing_var_arg` + `allow_hyphen_values`) so a verb's own
/// flags — `--push`, `--as`, `-n` — reach it untouched. The price is that clap binds
/// nothing after the first word: once a hyphen-accepting positional has started, every
/// `--x` is a value to it (clap_builder 4.6, `Parser::parse_long_arg`), and dropping
/// `trailing_var_arg` does not change that. So `kotton peer add <4> --user bob` used to
/// parse with `user = None` and run as the active identity, having passed `bob` to the
/// verb as a word. Clap cannot bind the flag there; the word type can refuse it, and a
/// refusal the person reads is the honest answer where binding is not
/// (`TASK-a-trailing-user-flag-is-swallowed-and-the-verb-acts-as-someone-else`).
fn verb_word(word: &str) -> Result<String, String> {
    if word == "--user" || word.starts_with("--user=") {
        return Err(
            "`--user` goes before the verb's words — `kotton <verb> --user <name> …`. \
                    Here it would reach the verb as a word, and the verb would act as the \
                    active identity instead"
                .into(),
        );
    }
    Ok(word.to_string())
}

/// The help a shared verb's `--help` ends on: the shell verb's own page, read from the one
/// registry the terminal's door runs (`bridge::run_verb`), so the words `kotton <verb>
/// --help` documents are the words the verb takes, and never a copy of them. The page's
/// `RETIRED:` block is generated from the noun's verb table
/// (`kotton_shell::CommandRegistry::help_of`), so this door's help cannot say of a retired
/// word what the table does not; nothing here writes a sentence about one.
fn shell_help(name: &str) -> String {
    static DOOR: std::sync::OnceLock<std::sync::Arc<kotton_shell::CommandRegistry>> = std::sync::OnceLock::new();
    DOOR.get_or_init(|| kotton_shell::ShellExecutor::new().registry()).help_of(name).unwrap_or_default()
}

/// The `<ARGS>` help of `device`, in its siblings' form (`Arguments to the verb:`, each
/// alternative in backticks, so `<code>` and `<id>` render as placeholders, not markup): the
/// shell's grammar ([`kotton_shell::device_grammar`]), each alternative as it is, since clap
/// prints `kotton device` before it, so both doors print one grammar and this one spells none
/// of the shell's words (kotton #326, #361); then `reset`, which is this door's alone, with its
/// own word ([`device::YES_WORD`], the one `reset` reads).
fn device_args_help() -> String {
    let reset = format!("reset [{}]", device::YES_WORD);
    let alternatives: Vec<String> = kotton_shell::device_grammar()
        .iter()
        .chain(std::iter::once(&reset))
        .map(|line| format!("`{line}`"))
        .collect();
    format!("Arguments to the verb: {}", alternatives.join(" | "))
}

#[derive(Subcommand)]
pub enum Commands {
    /// Authenticate and cache a session token for a user
    Login(LoginCommand),
    /// App lifecycle (list, launch, new, sideload, build, rm, …) — shares the REPL's `app` verb
    #[command(after_help = shell_help("app"))]
    App {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments to the verb: `list` | `launch <id>` | `new <name>` | `sideload <path>` | `rm <id>` | …
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Identity management — your identities on this device (list, use, create, recover, rotate, unlock)
    #[command(subcommand)]
    Id(IdCommand),
    /// Show the identity your commands act as (the active identity)
    Whoami,
    /// Launch the interactive REPL for a user
    Repl(ReplCommand),
    /// Alias for `repl` — launch the interactive REPL for a user
    #[command(hide = true)]
    Shell(ReplCommand),
    /// Peer node management (identity, list, show, add, revoke, mount) — shares the REPL's `peer` verb
    #[command(after_help = shell_help("peer"))]
    Peer {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments to the verb: `list` | `show <remote>` | `add …` | `revoke <remote>` | `mount …`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Manage the devices on your identity — add, join, list, revoke, name
    /// (six-digit pairing) — shares the REPL's `device` verb. `reset` is
    /// the exception: it starts this whole device fresh and needs no daemon.
    #[command(after_help = shell_help("device"))]
    Device {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        // Its help is `device_args_help()`: the shell's grammar, rendered after this door's
        // prefix, so it is not written here.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word, help = device_args_help())]
        args: Vec<String>,
    },
    /// Schema management (list, show, register)
    #[command(subcommand)]
    Schema(SchemaCommand),
    /// Handler registry (register, unregister, get, list, set-default)
    #[command(subcommand)]
    Handler(HandlerCommand),
    /// Record addressing — open records by kotton:// URL
    #[command(subcommand)]
    Record(RecordCommand),
    /// The project's records in a root its org owns — init, invite, import, export
    #[command(subcommand)]
    Records(RecordsCommand),
    /// Bring your history with you — read an export (.ics) into your own records
    Import(ImportCommand),
    /// Sync this device's drives, now — the REPL's `sync`, one parser for both
    #[command(after_help = shell_help("sync"))]
    Sync {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: none, or `--no-wait` (the words this verb retired are in the RETIRED block, from its table)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Your drives — create, list, show, move, enrol — the REPL's `drive`, one parser for both
    #[command(after_help = shell_help("drive"))]
    Drive {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `create <name> [--on <vault>]` | `list [--json]` | `show <name> [--json]` | `move <name> --to <vault>` | `enrol <invite>`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// What this device keeps of your drives — default, a drive or folder, list — the REPL's `pin`, one parser for both
    #[command(after_help = shell_help("pin"))]
    Pin {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `default whole|on-demand` | `<drive>[:/<folder>] whole|on-demand|default` | `list [--json]`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// When this device last synced, what it keeps of each drive, and the notices — shares the REPL's `status` verb
    #[command(after_help = shell_help("status"))]
    Status {
        /// Identity to act as (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word, hide = true)]
        args: Vec<String>,
    },
    /// Read your event log — by level, category or age, or follow it live — shares the
    /// REPL's `logs` verb
    #[command(after_help = shell_help("logs"))]
    Logs {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `[--level <level>] [--category <cat>] [--since <secs>] [-n <count>] [-f|--follow]`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Trusted-issuer registry (add, remove, list) — shares the REPL's `issuer` verb
    #[command(after_help = shell_help("issuer"))]
    Issuer {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments to the verb: `add <did>` | `remove <did>` | `list`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Copy files into and out of your tree — shares the REPL's `cp` verb. `host:` names this
    /// computer's own files, a relative one from the directory the command is run in
    #[command(after_help = shell_help("cp"))]
    Cp {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `<src> <dst>`, each a path in your tree or `host:<path>` on this computer
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Keep a folder of yours in your tree, and copy only what changed when run again —
    /// shares the REPL's `keep` verb. The folder is on this computer, a relative one from the
    /// directory the command is run in; with no arguments it lists what is kept
    #[command(after_help = shell_help("keep"))]
    Keep {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `<folder> [as /<name>]`, a folder on this computer and where in your tree it goes; none lists what is kept
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Print a file in your tree — shares the REPL's `cat` verb
    #[command(after_help = shell_help("cat"))]
    Cat {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `<file>`, a path in your tree
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Make the key a relay or a vault of your own is created for, and print the command its
    /// host runs — shares the REPL's `mint` verb
    #[command(after_help = shell_help("mint"))]
    Mint {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `relay [<r>] [--rule <rule>]` | `vault [<v>]`, then `--rev <rev>` | `--key`; none lists the keys minted and not yet enrolled
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Complete a key `mint` made, from the line its relay or vault printed when it was
    /// created — shares the REPL's `enrol` verb
    #[command(after_help = shell_help("enrol"))]
    Enrol {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `<line> [<line>…]`, each the line a relay or a vault of your own printed
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// This device's relay (set, clear, status), and a relay of your own (rule, invite,
    /// forget) — shares the REPL's `relay` verb
    #[command(after_help = shell_help("relay"))]
    Relay {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `status` | `set <line or invite>` | `clear` | `rule [<r>] [<rule>]` | `invite [<r>]` | `forget [<r>]`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// A vault of your own (people, invite, digits, space, drop, stand, move, forget) —
    /// shares the REPL's `vault` verb
    #[command(after_help = shell_help("vault"))]
    Vault {
        /// Identity to act as, before the verb's words (defaults to the active identity / KOTTON_USER)
        #[arg(long)]
        user: Option<String>,
        /// Arguments: `people` | `invite <name>` | `invite --me` | `digits <name>` | `space <name> <bytes>` | `drop <name> --confirm <name>` | `stand` | `move <r>` | `forget`, each naming its vault first when you operate more than one
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_parser = verb_word)]
        args: Vec<String>,
    },
    /// Grant management (revoke, import)
    #[command(subcommand)]
    Grant(GrantCommand),
    /// Confined extensions (install, list, remove)
    #[command(subcommand)]
    Extension(ExtensionCommand),
    /// The people you can message — pair, join, list
    #[command(subcommand)]
    Contact(ContactCommand),
    /// Messaging (send, inbox, channels)
    #[command(subcommand)]
    Message(MessageCommand),
    /// Org identity management (new, show, list, grant, member)
    #[command(subcommand)]
    Org(OrgCommand),
    /// Device configuration — relay, TURN, STUN
    #[command(subcommand)]
    Config(ConfigCommand),
    /// The models you have installed — add, ls, rm, use
    #[command(subcommand)]
    Model(ModelCommand),
    /// Show sidecar process state (kuserd supervision tree)
    #[command(hide = true)]
    Sidecars(SidecarsCommand),
    /// IPC session inspection
    #[command(subcommand, hide = true)]
    Ipc(IpcCommand),
    /// Network status snapshot (peers, gateways, sync, rendezvous)
    Net(NetCommand),
    /// Raw VFS file operations (write, read, ls, rm)
    #[command(subcommand, hide = true)]
    Vfs(VfsCommand),
}
