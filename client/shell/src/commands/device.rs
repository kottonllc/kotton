// SPDX-License-Identifier: AGPL-3.0-or-later
//! `device` — RFC-0040 committed-SAS device pairing, in lockstep with the `kotton`
//! CLI's `device` verb (they drive the same SDK path). Replaces the retired
//! `invite`/`node_enroll` flow, which used the legacy no-SAS pinned handshake.
//!
//! ```text
//! device add          [--as NAME] [posture flag]   (existing device)
//! device join [code]  [--as NAME]                  (new device)
//! device name [NAME]                                (show/set this device's name)
//! ```
//!
//! The posture flags are `device_add_word`'s (`kotton_schemas::membership`), and the usage
//! line and the help page print them from there.
//!
//! Both `add` and `join` run the committed handshake and derive the **same six
//! digits**. The new device shows them; you confirm by **typing them into the
//! existing device** (RFC-0040 §3) — transcription, not a blind `[y/N]`, so a code
//! you never read can't be waved through. Keys never touch the human's eyes or
//! keyboard; each device announces its own name and the peer adopts it.

use anyhow::Result;
use async_trait::async_trait;
use kotton_schemas::membership::Posture;
use kotton::{KottonClient, UserResponse};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::mpsc;

use super::{Command, CommandOutput, Verb};
use crate::out::Out;
use crate::state::ShellState;
use crate::ui;

/// How long the offer stays open (seconds) — long enough to walk to the other
/// device, short enough that a stray code expires.
const ADD_TTL_SECS: u64 = 120;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Role {
    Issuer,
    Joiner,
    /// This screen is the trusted one a phone's browser pairs against
    /// (DEC-0053): it shows the six digits the phone shows, and the person here
    /// says whether they match. There is no node to sync afterwards — the phone
    /// is a view, and it is in the moment the person says yes.
    Browser,
    /// This screen admits a machine with no screen of its own — a gateway
    /// (`device add` with the gateway's word), or a vault as [`Role::Vault`]. The ceremony is
    /// the issuer's, but its six digits are printed in *that machine's
    /// terminal*, so the prompt says so rather than sending the person to look
    /// for a "new device" screen that does not exist.
    Box,
    /// [`Role::Box`] for a vault (`drive enrol`): the same prompt, and a success
    /// line that says the posture in words, since no flag said it.
    Vault,
    /// This screen admits the vault it operates (`vault invite <v> --me`,
    /// DEC-0086). The vault's key, pinned by the operator credential, confirms
    /// in place of the six digits, so no digits are shown and none are typed:
    /// a `PairShowCode` frame here is refused, never answered — there is no
    /// fallback to a spoken code.
    OwnVault,
}

pub struct DeviceCommand;

/// The words `device` has. Both doors read it: `execute` refuses a word outside it with
/// the usage line before dispatching, and `execute_without_session` does the same before
/// any session. An arm in `execute` with no entry here is therefore unreachable, and an
/// entry with no arm falls to the usage line, so a mismatch shows as a refusal rather than
/// as two lists quietly disagreeing.
const KNOWN_VERBS: &[&str] = &["add", "admit", "join", "name", "list", "revoke", "reset"];

/// Whether `word` is a `device` verb.
fn known_verb(word: &str) -> bool {
    KNOWN_VERBS.contains(&word)
}

/// What the admitting side says of each drive the join did not hand: the device
/// it joined, and the note's sentence for the node the drive is reached through.
/// Both names are data in prose, printed by [`kotton_wire::note::quoted`]
/// (kottonllc/kotton#597, 43A; kottonllc/kotton#643).
pub(crate) fn not_handed_lines(joined: &str, not_handed: &[kotton_wire::note::RowNote]) -> Vec<String> {
    let joined = kotton_wire::note::quoted(joined);
    not_handed
        .iter()
        .map(|n| {
            format!(
                "{joined} was not handed the drive reached through {}: {}",
                kotton_wire::note::quoted(&n.name),
                kotton_wire::note::sentence(n, DEVICE_REVOKE)
            )
        })
        .collect()
}

/// The verb that removes a paired node, or a member of the person's set with no
/// row, by the name a note gives it: the one `device list`, `peer list`, `drive
/// list` and the admitting side of a join name in a note's sentence
/// (kottonllc/kotton#605, kottonllc/kotton#610).
pub(crate) const DEVICE_REVOKE: &str = "device revoke";

/// One line for each note a listing carried beside its rows, as
/// [`kotton_wire::note::sentence`] says it with [`DEVICE_REVOKE`].
///
/// A note's sentence gives a command to type only with a name that is one plain
/// word ([`kotton_wire::note::one_plain_word`]), and that set is ASCII, as a
/// stated concession (kottonllc/kotton#597, 25A). What is conceded: a command
/// is printed only with a name in ASCII; nothing is refused for it, and a name
/// in any script is stored, listed, shown with each character it holds
/// ([`kotton_wire::note::shown`]) and taken by `device revoke` whole. What it
/// costs: a device named in another script is given its DID as stored to copy,
/// and a row with no plain name is told `device revoke` and that it removes the
/// row by this name, as recorded, with no line to copy. Why: a printed command
/// is held to reach its row typed as printed, and the stores compare a name byte
/// for byte. A name a vault or a relay is minted under is in NFC; a label and a
/// DID as stored are in no normal form, and no normal form is applied where a
/// typed name is compared. The seam is the one predicate, widened after a normal
/// form is applied where a name is stored and where it is compared, with this
/// shell's read-back test over the wider set
/// (`a_notes_name_is_one_word_the_shell_takes_to_its_row`); the first step is
/// done for a minted name. The same is said for a person in
/// `docs/cli/reference.md`, under `--json`.
pub(crate) fn notes_said(notes: &[kotton_wire::note::RowNote]) -> Vec<Out> {
    notes.iter().map(|n| Out::Note(kotton_wire::note::sentence(n, DEVICE_REVOKE))).collect()
}

/// `device list`'s table of the machines on this identity: each label as
/// stored, a shortened DID, and when it was paired. The renderer prints each
/// cell with every character it holds shown, and `--json` carries the label as
/// stored (kottonllc/kotton#597, 39A).
fn device_table(nodes: &[kotton_wire::peer::PairedNode]) -> Out {
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|n| vec![n.id.clone(), short_did(&n.device_did.to_string()), human_since(n.paired_at)])
        .collect();
    Out::Table { columns: vec!["device".into(), "did".into(), "paired".into()], rows }
}

/// `device list`'s second table, of the browsers admitted with `device add
/// --browser`, as a pure function of them as [`device_table`] is of the nodes:
/// each name as stored, printed by the renderer (39A). None when there are none.
fn browser_table(browsers: &[kotton_wire::ipc::types::BrowserDevice]) -> Option<Out> {
    if browsers.is_empty() {
        return None;
    }
    Some(Out::Table {
        columns: vec!["browser".into(), "admitted".into(), "last seen".into()],
        rows: browsers
            .iter()
            .map(|b| {
                vec![b.name.clone(), human_since(b.created_at), b.last_used_at.map(human_since).unwrap_or_else(|| "—".into())]
            })
            .collect(),
    })
}

/// The usage refusal, exit 2: what `device` prints for a word it does not have: the
/// grammar ([`device_grammar`]), each alternative after this door's prefix, the verb word,
/// and an aside that `reset` is the CLI's.
fn usage() -> CommandOutput {
    let grammar: Vec<String> = device_grammar().iter().map(|line| format!("device {line}")).collect();
    CommandOutput::usage(
        format!("usage: {}   (`kotton device reset` starts this device fresh)", grammar.join(" | ")),
        None,
    )
}

/// `device`'s grammar as data: every line the shell runs, one alternative each, without the
/// verb word, since each door prints its own prefix (kotton #361). The usage line ([`usage`])
/// puts `device ` before each; the CLI door's argument help for `device` (`kotton_cli`'s
/// `device_args_help`) prints each as it is, after clap's `kotton device`. So there is one
/// grammar and neither door re-spells a word of it (kotton #326). The posture bracket (its
/// flags sorted) and each word with a value are assembled by walking [`device_add_word`] over
/// every posture, the vocabulary `parse_add` reads, and the shell's own words are
/// `DEVICE_AS_WORD` and `DEVICE_BROWSER_WORD` (`kotton_schemas::membership`), the constants
/// `parse_add`, `join_args` and `revoke` read, so the printed grammar has no spelling of its
/// own. `reset` is not in it: the shell does not run it, and each door says so its own way.
pub fn device_grammar() -> Vec<String> {
    let mut lines = vec![
        format!("add [{AS_WORD} NAME] [{}]", device_add_posture_bracket()),
        format!("add {BROWSER_WORD}"),
    ];
    lines.extend(valued_words().map(|(word, _)| format!("add {word}")));
    lines.extend([
        format!("join [code] [{AS_WORD} NAME]"),
        "list".to_owned(),
        "revoke <id>".to_owned(),
        format!("revoke {BROWSER_WORD} <name>"),
        "name [NAME]".to_owned(),
    ]);
    lines
}

/// Every `device add` word that takes a value, with its value's kind, in [`Posture::ALL`]'s
/// order: what the usage line and the help page print after the posture bracket.
fn valued_words() -> impl Iterator<Item = (DeviceAddWord, DeviceAddValue)> {
    Posture::ALL
        .iter()
        .filter_map(|&posture| match device_add_word(posture) {
            word @ DeviceAddWord::FlagWithValue { value, .. } => Some((word, value)),
            DeviceAddWord::Bare | DeviceAddWord::Flag(_) => None,
        })
}

/// The posture flags of `device add` as one bracket's contents, sorted and joined with `|`
/// (`--blind|--cosigner`): every [`DeviceAddWord::Flag`] [`device_add_word`] yields, for
/// [`device_grammar`].
fn device_add_posture_bracket() -> String {
    let mut flags: Vec<&str> = Posture::ALL
        .iter()
        .filter_map(|&posture| match device_add_word(posture) {
            DeviceAddWord::Flag(flag) => Some(flag),
            DeviceAddWord::Bare | DeviceAddWord::FlagWithValue { .. } => None,
        })
        .collect();
    flags.sort_unstable();
    flags.join("|")
}

/// `device admit`, whatever follows it: the word the command-tree decision's table retired
/// for `drive enrol <invite>`. Refused, exit 2, in both doors and before any session; the
/// words after it are not read, since nothing here runs them.
fn retired_admit() -> CommandOutput {
    super::retired("device admit", "drive enrol <invite>")
}

#[async_trait]
impl Command for DeviceCommand {
    /// Each word with a value is [`device_add_word`]'s, printed from it and said by its kind
    /// ([`valued_words`]), and the browser's is [`BROWSER_WORD`], so the page names the flags
    /// `parse_add` reads and a change to either vocabulary changes the page with it. Built
    /// once and kept, since the trait hands out a `&'static str`.
    fn help_text(&self) -> &'static str {
        static HELP: LazyLock<String> = LazyLock::new(|| {
            let valued: String = valued_words()
                .map(|(word, value)| match value {
                    DeviceAddValue::GatewayCode => format!(", `{word}` a gateway elsewhere"),
                })
                .collect();
            format!(
                "device add|join|list|name|revoke — pair another of your machines to this \
                 identity (six-digit confirmation); `{BROWSER_WORD}` admits a phone's browser\
                 {valued}. A vault's invite is `drive enrol \
                 <invite>`. \
                 `kotton device reset` starts this whole device fresh and is the CLI's, not this \
                 shell's — it deletes the directory this runtime is using"
            )
        });
        HELP.as_str()
    }

    /// `device` is not yet the command-tree decision's: only the word its table moved to `drive` is
    /// declared, so the verb check holds that word and not the rest.
    fn verbs(&self) -> &'static [Verb] {
        // The table names the verb (`drive enrol`); the printed line adds its argument
        // (`drive enrol <invite>`). `verb-check` reads only the noun of `now`, so they may differ.
        const VERBS: &[Verb] = &[Verb::gone("admit", "drive enrol")];
        VERBS
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if !args.first().is_some_and(|w| known_verb(w)) {
            return Ok(usage());
        }
        match args.first().map(String::as_str) {
            Some("add") => self.add(&args[1..], state).await,
            Some("admit") => Ok(retired_admit()),
            Some("join") => self.join(&args[1..], state).await,
            Some("name") => self.name(&args[1..], state).await,
            Some("list") => self.list(state).await,
            Some("revoke") => self.revoke(&args[1..], state).await,
            // Not a gap. `reset` deletes the base directory this runtime is
            // running out of, so it cannot be one of this runtime's verbs — it
            // is `kotton device reset`, and it refuses while a daemon is up.
            // Answered by name rather than falling to the usage line below,
            // because "unknown subcommand" for a verb the product does have is
            // the confusing half of a correct refusal.
            Some("reset") => Ok(CommandOutput::fail(
                "device reset is `kotton device reset`, run from a terminal rather than from \
                 in here: it deletes the directory this runtime is using, so it refuses while \
                 a daemon is running. Leave the runtime, then run it.",
                None,
            )),
            _ => Ok(usage()),
        }
    }

    /// `device join` needs no session: it is how an identity arrives on a device, so
    /// on a device with none it is the only way one can, and every request it sends
    /// is answered before anyone is signed in. At a terminal it runs here, as the
    /// identity the door was told (`kotton id join <name>`), on a connection that
    /// presents nothing.
    async fn execute_without_session(
        &self,
        args: &[String],
        named: Option<&str>,
    ) -> Option<Result<CommandOutput>> {
        match args.first().map(String::as_str) {
            Some("join") => {}
            // Retired, so refused here: the refusal asks the daemon nothing, and
            // `drive enrol` is where the ceremony is.
            Some("admit") => return Some(Ok(retired_admit())),
            // A word `device` does not have is refused here, as `drive`, `pin` and `sync`
            // refuse theirs: the usage line asks the daemon nothing. A known verb falls
            // through to its session, whose authority is the daemon's and unchanged.
            Some(word) if !known_verb(word) => return Some(Ok(usage())),
            // A known verb whose words do not parse is the same refusal, before any
            // session: `parse_add` is the one reader of `add`'s words, here and in `execute`.
            Some("add") => return parse_add(&args[1..]).err().map(Ok),
            _ => return None,
        }
        let Some(user) = named else {
            return Some(Ok(CommandOutput::fail(
                "name the identity this device joins: `kotton id join <name> [code]`",
                None,
            )));
        };
        let client = match KottonClient::connect().await {
            Ok(client) => client,
            Err(e) => {
                return Some(Err(anyhow::anyhow!(
                    "could not reach the daemon (is it running?): {e}"
                )))
            }
        };
        let (code, as_name) = join_args(&args[1..]);
        Some(join_identity(&client, user, &code, as_name.as_deref()).await)
    }
}

impl DeviceCommand {
    /// `device add` — issuer side. Prints a connection code, waits for the new
    /// device, then shows six digits to confirm against its screen.
    async fn add(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let (as_name, posture) = match parse_add(args) {
            Ok(Add::Browser) => return self.add_browser(state).await,
            Ok(Add::Gateway { flag, code }) => return self.add_gateway(flag, &code, state).await,
            Ok(Add::Device { as_name, posture }) => (as_name, posture),
            Err(refused) => return Ok(refused),
        };
        let user_id = state.user_id.clone();
        let client = state.client.lock().await;
        let mut rx = client
            .device_add_stream(&user_id, as_name.as_deref(), ADD_TTL_SECS, 0, posture)
            .await
            .map_err(|e| anyhow::anyhow!("device add: {e}"))?;
        // The issuer holds the offer open for ADD_TTL_SECS; pass that so the ceremony
        // can draw a live countdown while it waits for the other device to connect.
        run_ceremony(
            &client,
            &user_id,
            &mut rx,
            Role::Issuer,
            Some(Duration::from_secs(ADD_TTL_SECS)),
        )
        .await
    }

    /// `device join` — new-device side. With no code, discovers the offer on this
    /// network (mDNS); a code pairs off-LAN. Either way, shows six digits to confirm.
    /// Admit a gateway on another machine (RFC-0078): it printed `code` from
    /// `khttpd enroll` and is listening; this node dials it and the ceremony
    /// runs as for any device, this screen typing the six the gateway shows.
    async fn add_gateway(&self, flag: &str, code: &str, state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let client = state.client.lock().await;
        let mut rx = client
            .gateway_enroll_stream(&user_id, code, ADD_TTL_SECS)
            .await
            .map_err(|e| anyhow::anyhow!("device add {flag}: {e}"))?;
        run_ceremony(
            &client,
            &user_id,
            &mut rx,
            Role::Box,
            Some(Duration::from_secs(ADD_TTL_SECS)),
        )
        .await
    }

    /// Open the desk a phone's browser pairs at. The phone opens the gateway's
    /// page; when it commits to six digits they appear here, and the answer
    /// given here is what admits it (DEC-0053, RFC-0078).
    async fn add_browser(&self, state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let client = state.client.lock().await;
        let mut rx = client
            .web_shell_pair_stream(&user_id, ADD_TTL_SECS)
            .await
            .map_err(|e| anyhow::anyhow!("device add {BROWSER_WORD}: {e}"))?;
        run_ceremony(
            &client,
            &user_id,
            &mut rx,
            Role::Browser,
            Some(Duration::from_secs(ADD_TTL_SECS)),
        )
        .await
    }

    async fn join(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let (code, as_name) = join_args(args);
        let user_id = state.user_id.clone();
        let client = state.client.lock().await;
        join_identity(&client, &user_id, &code, as_name.as_deref()).await
    }

    /// `device name [NAME]` — show or set this device's announced name.
    async fn name(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let mut client = state.client.lock().await;
        let new_name = args.first().map(String::as_str);
        let name = client
            .device_name(new_name)
            .await
            .map_err(|e| anyhow::anyhow!("device name: {e}"))?;
        if new_name.is_some() {
            ui::greet("this device is now named", &name);
        } else {
            ui::literal(&name);
        }
        Ok(CommandOutput::success())
    }

    /// `device list` — the machines on this identity (`*` isn't marked here; the
    /// prompt already shows which one you're on).
    async fn list(&self, state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;
        let nodes = client
            .list_nodes(&user_id)
            .await
            .map_err(|e| anyhow::anyhow!("device list: {e}"))?;
        let mut shapes = vec![device_table(&nodes)];
        shapes.extend(notes_said(&nodes.notes));
        // The browsers admitted with `device add --browser`, beside the devices:
        // a browser is paired like a device (DEC-0053), so what acts as you is
        // one list read in one place, and the revoke below takes either.
        let browsers = client
            .list_browsers(&user_id)
            .await
            .map_err(|e| anyhow::anyhow!("device list: {e}"))?;
        shapes.extend(browser_table(&browsers));
        Ok(CommandOutput::shapes(shapes))
    }

    /// `device revoke <id>` — remove a device from the identity (drops it from the
    /// mTLS allowlist on the next handshake). `<id>` is a row's label or DID as
    /// stored, or the DID as stored of a member of the set with no row, taken
    /// whole, through the daemon's one resolver (`kotton_peer::daemon::nodes::node_named`).
    ///
    /// `device revoke --browser <name>` revokes an admitted browser instead: its
    /// next visit needs a human again, and a channel it holds open now is ended
    /// rather than left to run out.
    async fn revoke(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let id = match revoke_target(args) {
            Revoke::Browser(Some(name)) => return self.revoke_browser(name, state).await,
            Revoke::Browser(None) => return Ok(CommandOutput::fail(revoke_browser_usage(), None)),
            Revoke::Node(Some(id)) => id,
            Revoke::Node(None) => return Ok(CommandOutput::fail("usage: device revoke <id>", None)),
        };
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;
        client
            .revoke_node(&user_id, &id)
            .await
            .map_err(|e| anyhow::anyhow!("device revoke: {e}"))?;
        Ok(CommandOutput::shapes(vec![Out::Confirm {
            action: format!("revoked device '{id}'"),
            subject: String::new(),
        }]))
    }

    /// `device revoke --browser <name>`.
    async fn revoke_browser(&self, name: String, state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;
        client
            .revoke_browser(&user_id, &name)
            .await
            .map_err(|e| anyhow::anyhow!("device revoke: {e}"))?;
        Ok(CommandOutput::shapes(vec![Out::Confirm {
            action: format!("revoked browser '{name}'"),
            subject: String::new(),
        }]))
    }
}

/// What `device revoke`'s words name: a browser after [`BROWSER_WORD`], else a
/// node by its first word; `None` where the word is missing.
#[derive(Debug, PartialEq)]
enum Revoke {
    Node(Option<String>),
    Browser(Option<String>),
}

/// How `device revoke` reads the words after `revoke`: the one reading its
/// command and the test of a note's sentence both use.
fn revoke_target(args: &[String]) -> Revoke {
    if args.first().map(String::as_str) == Some(BROWSER_WORD) {
        Revoke::Browser(args.get(1).cloned())
    } else {
        Revoke::Node(args.first().cloned())
    }
}

/// What a vault admitted by `drive enrol` is, said once it is in: the posture no
/// flag named.
const VAULT_POSTURE_LINE: &str =
    "it keeps what it cannot read: your data reaches it sealed, and no key to open it does.";

/// The line a pairing ends on when this side added the other: bare `sync`, which takes
/// no word after it (`SyncCommand`), and the joined device's label, `remote`, the word
/// `peer list` heads its column with and `peer show` takes. The label is data in prose,
/// printed by [`kotton_wire::note::quoted`], and is in no command
/// (kottonllc/kotton#597, 43A and 51A).
fn issuer_complete_line(node: &kotton_wire::peer::PairedNode) -> String {
    format!(
        "run `sync` when you want to copy data to it — its remote is {}.",
        kotton_wire::note::quoted(&node.id)
    )
}

/// What a browser that gave no name is called in its greeting: the shell's own words,
/// not a name, so they are printed with no delimiter (kottonllc/kotton#597, 55B).
const UNNAMED_BROWSER: &str = "your browser";

/// The greeting a join's completion hands the renderer for `role`: its words, and the
/// joined device's label, last on its line, by [`kotton_wire::note::quoted`]
/// (kottonllc/kotton#597, 43A and 55B; kottonllc/kotton#643). `label` is `None` only
/// for a browser that gave no name, which is greeted as [`UNNAMED_BROWSER`].
fn greeting(role: Role, label: Option<&str>) -> (&'static str, String) {
    let words = match role {
        Role::Issuer | Role::Box | Role::Vault => "added to your identity,",
        Role::OwnVault => "you keep at your own vault now —",
        Role::Joiner => "you're in — paired with",
        Role::Browser => "the phone is in —",
    };
    (words, label.map_or_else(|| UNNAMED_BROWSER.to_string(), kotton_wire::note::quoted))
}

/// The lines a join's completion hands the renderer under the greeting for `role`,
/// made from the joined `node`: its label, printed in prose by
/// [`kotton_wire::note::quoted`], and its DID, the only one of its names a command here
/// takes (kottonllc/kotton#597, 51A and 52C). `keeps` is what a vault keeps, read for
/// [`Role::Vault`] and [`Role::OwnVault`] only.
///
/// What the tests hold is these strings, as `run_ceremony_to` hands them to
/// [`ui::body`]: which of the node's names each line gives, and that every command
/// carries the DID (kottonllc/kotton#597, 58A). As [`ui::body`] wraps them, each
/// name's print and each command is held whole on one written line, at the narrowest
/// and the widest column (kottonllc/kotton#597, 56B and 57A; kottonllc/kotton#654).
fn completion_lines(role: Role, node: &kotton_wire::peer::PairedNode, keeps: Option<&Kept>) -> Vec<String> {
    match role {
        Role::Issuer | Role::Box => vec![issuer_complete_line(node)],
        Role::Vault => vault_complete_lines(node, keeps),
        Role::OwnVault => vec![vault_keeps_line(node, keeps)],
        Role::Joiner => vec!["run `sync` to pull your data when you want it.".to_string()],
        Role::Browser => Vec::new(),
    }
}

/// Drive a ceremony stream to completion: render each state, prompt the human on the
/// six-digit frame, and deliver the verdict via `pair_confirm_code`. Shared by the
/// `device` command and the first-run "join an identity" onboarding branch so both
/// use the identical committed-SAS flow (no drift).
/// What the ceremony says under the greeting when a vault is admitted: its
/// posture in words, then what it keeps ([`vault_keeps_line`]), as handed to the
/// renderer ([`completion_lines`]).
fn vault_complete_lines(node: &kotton_wire::peer::PairedNode, keeps: Option<&Kept>) -> Vec<String> {
    vec![VAULT_POSTURE_LINE.to_string(), vault_keeps_line(node, keeps)]
}

/// What a vault just enrolled keeps of the person's (kotton-protocol's
/// storage model; kotton #124), as `drive list` answers on a connection of its
/// own ([`kept_at`]), or `None` when it did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Kept {
    /// The names of the drives this vault lists.
    here: Vec<String>,
    /// Whether any vault lists `personal`.
    personal_anywhere: bool,
}

/// The line after a vault's enrolment ([`Kept`]). The first vault the person
/// enrols is where `personal` is made, and the line says so; a vault enrolled
/// after it holds nothing until a drive is made or moved there, and the line
/// says that, with the two verbs that do it. When no vault lists `personal` —
/// it could not be made at this, the first, because a vault did not answer —
/// the line says what `status` says of it, not that the vault holds nothing.
///
/// The vault `node`'s label is printed in prose by [`kotton_wire::note::quoted`]. The
/// two commands take its DID, whatever the label is: `--on` and `--to` take a DID to
/// this vault alone, and the DID a join records is one plain word, made from the key
/// (kottonllc/kotton#597, 52C). A label is in no command here.
fn vault_keeps_line(node: &kotton_wire::peer::PairedNode, keeps: Option<&Kept>) -> String {
    let personal = kotton_wire::ipc::FIRST_DRIVE_NAME;
    let did = &node.device_did;
    match keeps {
        None => format!("`drive list` says what {} keeps of yours.", kotton_wire::note::quoted(&node.id)),
        Some(k) if k.here.iter().any(|n| n == personal) => format!(
            "it keeps `{personal}`, your first drive: this device's files sync with it there. run `sync` when you want \
             to copy data to it."
        ),
        Some(k) if !k.personal_anywhere => {
            kotton_wire::ipc::PinNotice::NotFound { drive: personal.to_string() }.said_after_enrol()
        }
        Some(k) if k.here.is_empty() => format!(
            "it holds nothing of yours until a drive is made or moved there: `drive create <name> --on {did}` \
             makes one, and `drive move <name> --to {did}` moves one."
        ),
        Some(k) => format!("it keeps {}.", k.here.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", ")),
    }
}

/// What the vault `node` keeps, and whether any vault lists `personal`, as
/// `drive list` answers on a connection of its own, or `None` when it does
/// not answer.
async fn kept_at(client: &KottonClient, user: &str, node: &kotton_wire::peer::PairedNode) -> Option<Kept> {
    let at: String = node.public_key.iter().map(|b| format!("{b:02x}")).collect();
    let listed = client.drive_list_beside(user).await.ok()?;
    let personal_anywhere = listed.iter().any(|d| !d.unfinished && d.name == kotton_wire::ipc::FIRST_DRIVE_NAME);
    let mut here: Vec<String> = listed.into_iter().filter(|d| d.vault_key == at && !d.unfinished).map(|d| d.name).collect();
    here.dedup();
    Some(Kept { here, personal_anywhere })
}

/// What the ceremony says when the admit offered the relay the vault was met
/// at — this device stands at none: the offer in words, and the command that
/// takes it, holding it to the key the invite named. Nothing is taken unless
/// the person runs it (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`).
fn relay_offer_lines(line: &str) -> Vec<String> {
    let at = kotton_wire::line::InstanceLine::parse(line).map(|l| l.hint).unwrap_or_default();
    vec![
        format!("this device stands at no relay, so your other devices reach it only on this network. The vault was met at {at}."),
        format!("to stand this device there too: `relay set {line}`"),
    ]
}

/// Whether the relay a ceremony offered, `line`, is one of `take`: a relay's
/// line whose key is among them. Those are taken — this device stands there —
/// rather than said; any other is said as [`relay_offer_lines`] says it, for
/// the person to take or not.
pub(crate) fn relay_offer_taken(line: &str, take: &[[u8; 32]]) -> bool {
    kotton_wire::line::InstanceLine::parse(line)
        .is_ok_and(|l| l.kind == kotton_wire::ipc::OperatedService::Relay && take.contains(&l.key))
}

/// The role `drive enrol` runs its ceremony under. Named, so a test can hold
/// that the admit is a vault's ceremony and not the gateway's (`Role::Box`).
const ADMIT_ROLE: Role = Role::Vault;

/// What `device join` was given: the connection code, empty to find the offer on
/// this network, and `--as`, the name this device announces.
fn join_args(args: &[String]) -> (String, Option<String>) {
    let as_name = flag_value(args, AS_WORD);
    let code = args
        .iter()
        .find(|a| !a.starts_with("--") && as_name.as_deref() != Some(a.as_str()))
        .cloned()
        .unwrap_or_default();
    (code, as_name)
}

/// Join, as `user` on this device, the identity another device is offering with
/// `device add`: show the six digits, wait for that device to take them, and end with
/// this device acting as `user` when it acted as nobody, saying so in one line.
///
/// The one join. The shell's `device join`, its session-less form at a terminal
/// (`kotton id join`), and the first-run "join an identity" question all run it.
/// It sends only `DeviceJoin` and `PairConfirmCode`, which the daemon answers before
/// anyone is signed in, so `client` may present no session; the session the
/// ceremony issues is kept by `device_join_stream` itself.
pub(crate) async fn join_identity(
    client: &KottonClient,
    user: &str,
    code: &str,
    as_name: Option<&str>,
) -> Result<CommandOutput> {
    if code.is_empty() {
        ui::body("looking for a device offering to pair on this network…");
    } else {
        ui::body("connecting to your other device…");
    }
    let mut rx = client
        .device_join_stream(user, code, as_name)
        .await
        .map_err(|e| anyhow::anyhow!("device join: {e}"))?;
    // The joiner dials out; there's no offer window to count down against.
    let outcome = run_ceremony(client, user, &mut rx, Role::Joiner, None).await?;
    if outcome.exit_code == super::ExitCode::Success {
        kotton::active_identity::initialise(user);
        // `initialise` never overwrites a choice, so say what is true, not what was asked.
        // With no file at all, `initialise` has already said why it could not write one.
        match kotton::active_identity::get() {
            Some(acting) if acting == user => ui::greet("this device acts as", user),
            Some(acting) => ui::body(&format!(
                "this device still acts as {acting}; `kotton id use {user}` makes it act as {user}."
            )),
            None => {}
        }
    }
    Ok(outcome)
}

pub(crate) async fn run_ceremony(
    client: &KottonClient,
    user: &str,
    rx: &mut mpsc::Receiver<UserResponse>,
    role: Role,
    window: Option<Duration>,
) -> Result<CommandOutput> {
    Ok(run_ceremony_to(client, user, rx, role, window, &[]).await?.0)
}

/// [`run_ceremony`], and the node it completed with — the remote a first sync
/// names — when it completed; and the relay it offered, when that relay is one
/// of `take` ([`relay_offer_taken`]), which is then not said but handed back
/// for the caller to stand this device at.
pub(crate) async fn run_ceremony_to(
    client: &KottonClient,
    user: &str,
    rx: &mut mpsc::Receiver<UserResponse>,
    role: Role,
    window: Option<Duration>,
    take: &[[u8; 32]],
) -> Result<(CommandOutput, Option<String>, Option<String>)> {
    // While the issuer's offer is open we redraw a live countdown as we wait for the
    // other device to connect. `deadline` is armed when the offer is advertised and
    // disarmed the moment the next frame arrives.
    let mut deadline: Option<tokio::time::Instant> = None;
    loop {
        let frame = match deadline.take() {
            Some(dl) => recv_with_countdown(rx, dl).await,
            None => rx.recv().await,
        };
        let Some(frame) = frame else { break };
        match frame {
            UserResponse::PairAdvertising { code, .. } => {
                ui::blank();
                ui::body("on the new device, at a terminal:");
                ui::literal(&format!("kotton id join {user}"));
                ui::body("it should find this device on this network; if it can't, add the code:");
                ui::literal(&format!("kotton id join {user} {}", code.expose()));
                ui::blank();
                ui::body("waiting for it to connect…");
                deadline = window.map(|w| tokio::time::Instant::now() + w);
            }
            UserResponse::WebShellPairReady => {
                ui::blank();
                ui::body("open your page on the phone. when it shows six digits, they'll appear here.");
                ui::body("waiting for a phone…");
                deadline = window.map(|w| tokio::time::Instant::now() + w);
            }
            UserResponse::PairConnecting => ui::body("connecting…"),
            UserResponse::PairConnected => ui::body("connected — deriving the code…"),
            UserResponse::PairShowCode {
                token,
                sas,
                peer_label,
            } => {
                let matches = prompt_code_match(sas, peer_label.as_deref(), role)?;
                client
                    .pair_confirm_code(user, token.expose(), matches)
                    .await
                    .map_err(|e| anyhow::anyhow!("confirm: {e}"))?;
                if !matches {
                    ui::body("cancelled — nothing was shared.");
                }
                if role == Role::Browser {
                    // The phone's admission completes on the node the moment this
                    // answer lands; there is no transfer and no node to name.
                    return if matches {
                        ui::blank();
                        let (words, name) = greeting(role, peer_label.as_deref());
                        ui::greet(words, &name);
                        ui::body("it reaches home with no digits shown from now on.");
                        Ok((CommandOutput::success(), None, None))
                    } else {
                        Ok((CommandOutput::error(1, "the digits did not match".to_string()), None, None))
                    };
                }
            }
            UserResponse::PairAwaitingPeer => ui::body("waiting for the other device to confirm…"),
            UserResponse::PairTransferring => ui::body("setting things up…"),
            UserResponse::PairingComplete { node, relay_offer, not_handed, .. } => {
                ui::blank();
                let (words, name) = greeting(role, Some(&node.id));
                ui::greet(words, &name);
                let keeps = match role {
                    Role::Vault | Role::OwnVault => kept_at(client, user, &node).await,
                    _ => None,
                };
                for line in completion_lines(role, &node, keeps.as_ref()) {
                    ui::body(&line);
                }
                for line in not_handed_lines(&node.id, &not_handed) {
                    ui::body(&line);
                }
                let mut taken = None;
                if let Some(line) = relay_offer {
                    if relay_offer_taken(&line, take) {
                        taken = Some(line);
                    } else {
                        for said in relay_offer_lines(&line) {
                            ui::body(&said);
                        }
                    }
                }
                return Ok((CommandOutput::success(), Some(node.id), taken));
            }
            UserResponse::PairFailed { reason } => {
                return Ok((CommandOutput::error(1, reason), None, None));
            }
            UserResponse::Error { message } => {
                return Ok((CommandOutput::error(1, message), None, None));
            }
            _ => {}
        }
    }
    Ok((
        CommandOutput::error(1, "the pairing connection closed before it finished".to_string()),
        None,
        None,
    ))
}

/// Await the next ceremony frame, redrawing a live countdown bar until `deadline`
/// while we wait. TTY-only: off a terminal it just awaits, since a redrawing bar is
/// noise in a pipe. Clears the bar line before returning so the next line is clean.
async fn recv_with_countdown(
    rx: &mut mpsc::Receiver<UserResponse>,
    deadline: tokio::time::Instant,
) -> Option<UserResponse> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return rx.recv().await;
    }
    let total = deadline.saturating_duration_since(tokio::time::Instant::now());
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            frame = rx.recv() => {
                ui::clear_line();
                return frame;
            }
            now = tick.tick() => {
                ui::countdown(deadline.saturating_duration_since(now), total);
            }
        }
    }
}

/// Confirm the SAS. RFC-0040 §3 requires a *local* confirm on **both** devices;
/// the two roles split so that neither confirm can be blindly waved through:
///
/// - the **joiner** (new device) displays the six digits and consents to join
///   (authorising *becoming* a device);
/// - the **issuer** (existing device) confirms by **typing** the digits shown on the
///   new device — not a `[y/N]`. Transcription forces you to actually read the other
///   screen, so a code you never looked at can't be approved; and because a MITM
///   cannot make the two screens agree (§4), wrong digits abort. This transcription
///   *is* the issuer's local confirm (authorising key release), so the security
///   level is unchanged — one-in-a-million per ceremony — with the blind path removed.
fn prompt_code_match(sas: u32, peer_label: Option<&str>, role: Role) -> Result<bool> {
    ui::blank();
    match role {
        Role::Joiner => {
            ui::body("to admit this device, type these six digits on your other device:");
            ui::blank();
            ui::literal(&format_sas(sas));
            ui::blank();
            let question = match peer_label {
                Some(l) => format!("join \"{l}\"? [y/N]"),
                None => "join this identity? [y/N]".to_string(),
            };
            Ok(is_yes(&prompt_line(&ui::ask(&question))?))
        }
        Role::Issuer | Role::Box | Role::Vault => {
            if role == Role::Vault {
                // Shown to whoever minted the invite, wherever they minted it:
                // at their desktop (`vault digits`), or at the vault's host.
                ui::body(
                    "the person who invited you reads you six digits: from `vault digits` at their desktop, \
                     or from the `sas=` line where they ran `kvaultd invite`.",
                );
            } else if role == Role::Box {
                let who = peer_label.unwrap_or("the machine you are admitting");
                ui::body(&format!("{who} printed six digits in its own terminal, on the `sas=` line."));
            } else {
                ui::body("on the new device you'll see six digits.");
            }
            let typed = prompt_line(&ui::ask("type them here to add it:"))?;
            let ok = digits_only(&typed) == format!("{sas:06}");
            if !ok {
                ui::body("those digits don't match — nothing was shared.");
            }
            Ok(ok)
        }
        Role::OwnVault => {
            ui::body(
                "the vault asked for six digits. Its key is what confirms your own vault, and nothing \
                 stands in for it — nothing was shared.",
            );
            Ok(false)
        }
        Role::Browser => {
            ui::body("the phone shows six digits. type them here to admit it:");
            let typed = prompt_line(&ui::ask("digits:"))?;
            let ok = digits_only(&typed) == format!("{sas:06}");
            if !ok {
                ui::body("those digits don't match — nothing was shared, and someone may be between you.");
            }
            Ok(ok)
        }
    }
}

/// Keep only the ASCII digits, so `798 095`, `798095`, and `798-095` all compare equal.
fn digits_only(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// A yes/no answer, defaulting to no — a bare Enter, or anything but y/yes, is "no".
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Zero-pad to six digits and group as `"NNN NNN"` for reading aloud.
pub(super) fn format_sas(sas: u32) -> String {
    let s = format!("{sas:06}");
    format!("{} {}", &s[..3], &s[3..])
}

/// Abbreviate a device DID for a list: keep the method prefix and enough of the
/// key to recognise it, eliding the middle — `did:key:9646e108…350f`. The full DID
/// is never what a human needs at a glance, and it wraps the table if shown whole.
fn short_did(did: &str) -> String {
    match did.rfind(':') {
        Some(sep) if did.len() - sep > 13 => {
            let (prefix, id) = did.split_at(sep + 1);
            format!("{prefix}{}…{}", &id[..8], &id[id.len() - 4..])
        }
        _ => did.to_string(),
    }
}

/// A friendly "how long ago" for a unix-seconds timestamp — `just now`, `5m ago`,
/// `3h ago`, `2d ago`, `4mo ago`. A raw epoch integer is noise in a device list.
fn human_since(unix_secs: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(unix_secs);
    match now - unix_secs {
        d if d < 60 => "just now".to_string(),
        d if d < 3_600 => format!("{}m ago", d / 60),
        d if d < 86_400 => format!("{}h ago", d / 3_600),
        d if d < 2_592_000 => format!("{}d ago", d / 86_400),
        d => format!("{}mo ago", d / 2_592_000),
    }
}

/// `drive enrol <invite>` — take in a vault by the invite it minted (`kvaultd
/// invite`, RFC-0084 V8): this node meets it at the invite's relay, taking that
/// relay as its own if it has none, and the six digits are typed here. Blind is
/// the only posture this door has, so it is the default and needs no flag: `None`, the
/// line named none (`drive::split_invite`), is blind.
pub(crate) async fn enrol_vault(
    code: &str,
    posture: Option<Posture>,
    state: &mut ShellState,
) -> Result<CommandOutput> {
    let posture = posture.unwrap_or(Posture::BlindStorage);
    let user_id = state.user_id.clone();
    let client = state.client.lock().await;
    let mut rx = client
        .device_admit_stream(&user_id, code, ADD_TTL_SECS, posture)
        .await
        .map_err(|e| anyhow::anyhow!("drive enrol: {e}"))?;
    run_ceremony(
        &client,
        &user_id,
        &mut rx,
        ADMIT_ROLE,
        Some(Duration::from_secs(ADD_TTL_SECS)),
    )
    .await
}

/// The one vocabulary of `drive enrol`'s posture flags: each word and the posture it asks
/// for. `drive::split_invite` reads the table, keys as its grammar and the matching value as
/// the posture it hands the ceremony, so the two cannot disagree; no other place spells
/// these words. `device add` has a vocabulary of its own, [`device_add_word`]: the two differ
/// in default (blind here, [`ADD_DEFAULT_POSTURE`] full there) and in set (`--full` is a word
/// only here), so one table would have to carry both and say which door is asking.
///
/// The table is grammar and a map, not a judgement. `--cosigner` and `--full` are *sent*
/// for the daemon to refuse (`handle_device_admit`); there is no client-side posture check,
/// because a second copy of that refusal in the client would be a guard with nothing behind
/// it that the first does not hold. The daemon remains the only guard on posture; the
/// client's tables are grammar. `--blind` is the default and is still read so a line
/// typed from an older guide works.
pub(crate) const ENROL_POSTURES: [(&str, Posture); 3] = [
    ("--blind", Posture::BlindStorage),
    ("--cosigner", Posture::Cosigner),
    ("--full", Posture::Full),
];

// `device`'s own words, which are no posture's: the name a device announces for this
// ceremony (`device add` and `device join`), and the browser `device add` admits and `device
// revoke` revokes. Each is spelled once, in `kotton-schemas` beside `device_add_word`, so the
// daemon's tests of its hints read the same word (kotton #326). `parse_add`, `join_args` and
// `revoke` read them, and the usage grammar and the help page print them, so no reader can take
// a word the printed grammar does not name. They are not in `device_add_word` because they ask
// for no posture; a test in this module holds that neither is one.
use kotton_schemas::membership::{DEVICE_AS_WORD as AS_WORD, DEVICE_BROWSER_WORD as BROWSER_WORD};

/// What `device revoke` with the browser's word and no name says.
fn revoke_browser_usage() -> String {
    format!("usage: device revoke {BROWSER_WORD} <name>")
}

// The one vocabulary of `device add` is `device_add_word`, a total map over `Posture` in
// `kotton-schemas` beside it and not here, so the daemon's hints that name a `device add` line
// (`adds_instead`, `kotton-device`) walk the same words `parse_add` reads, and a new posture
// fails to compile there until it has a word. It is the sibling of `ENROL_POSTURES` and
// separate from it because the two doors differ: no flag is `ADD_DEFAULT_POSTURE` (full, a
// device of your own) here and blind there, and `--full` is not a word here (it is the
// default). Like the other it is grammar and a map: the daemon decides what each posture may
// do, and remains the only guard on it. The usage line, the help page and the CLI door's
// argument help are assembled from it, so none has a spelling of its own to hold.
// (A comment, not `///`: rustdoc renders no doc on a private `use`.)
use kotton_schemas::membership::{
    device_add_word, DeviceAddValue, DeviceAddWord,
    DEVICE_ADD_DEFAULT_POSTURE as ADD_DEFAULT_POSTURE,
};

/// What a `device add` line asks for.
#[derive(Debug, PartialEq)]
enum Add {
    /// `add --browser`: open the desk a phone's browser pairs at.
    Browser,
    /// `add` with a word whose value is a [`DeviceAddValue::GatewayCode`], and the code: admit
    /// a gateway elsewhere. `flag` is the word the line used, for the error that names it.
    Gateway { flag: &'static str, code: String },
    /// `add [--as NAME]` and at most one posture flag: the line named at most one posture, and
    /// [`ADD_DEFAULT_POSTURE`] when it named none.
    Device { as_name: Option<String>, posture: Posture },
}

/// The posture a flag `w` asks for, and its word, walking [`device_add_word`] over every
/// posture. The bare word is no flag, so no `w` finds it.
fn add_flag(w: &str) -> Option<(Posture, DeviceAddWord)> {
    Posture::ALL.iter().map(|&p| (p, device_add_word(p))).find(|(_, word)| match word {
        DeviceAddWord::Bare => false,
        DeviceAddWord::Flag(flag) | DeviceAddWord::FlagWithValue { flag, .. } => *flag == w,
    })
}

/// The words after `device add` as an [`Add`], or the usage refusal (exit 2). The one reader
/// of these words, for `execute` and for `execute_without_session`, so the refusal comes
/// before any session. Grammar only: at most one posture flag, no flag twice, no flag
/// outside [`device_add_word`], [`AS_WORD`] and [`BROWSER_WORD`], a word with a value and
/// the browser's word alone (with no other word), and a value after the name's word and a
/// word that takes one. A word with a value is read by its value's kind, which says what the
/// line starts, so no posture is named here and a new kind does not compile until it is given
/// a path. Nothing here judges a posture.
fn parse_add(words: &[String]) -> Result<Add, CommandOutput> {
    let mut seen: Vec<&str> = Vec::new();
    let mut as_name = None;
    let mut valued = None;
    let mut posture = None;
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        i += 1;
        if seen.contains(&w) {
            return Err(usage());
        }
        let mut value = || {
            let v = words.get(i).filter(|v| !v.is_empty() && !v.starts_with('-')).cloned();
            i += 1;
            v.ok_or_else(usage)
        };
        if w == AS_WORD {
            as_name = Some(value()?);
        } else if w != BROWSER_WORD {
            match add_flag(w) {
                Some((p, DeviceAddWord::Flag(_))) => {
                    if posture.replace(p).is_some() {
                        return Err(usage());
                    }
                }
                Some((_, DeviceAddWord::FlagWithValue { flag, value: kind })) => {
                    valued = Some(match kind {
                        DeviceAddValue::GatewayCode => Add::Gateway {
                            flag,
                            code: value()?,
                        },
                    })
                }
                Some((_, DeviceAddWord::Bare)) | None => return Err(usage()),
            }
        }
        seen.push(w);
    }
    let posture = posture.unwrap_or(ADD_DEFAULT_POSTURE);
    match (seen.contains(&BROWSER_WORD), valued) {
        (false, None) => Ok(Add::Device { as_name, posture }),
        (true, None) if seen.len() == 1 => Ok(Add::Browser),
        (false, Some(add)) if seen.len() == 1 => Ok(add),
        _ => Err(usage()),
    }
}

/// The value following `flag` in `args` (e.g. `--as phone` → `Some("phone")`).
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Print a prompt and read one visible line from stdin (mirrors `shell::prompt_line`).
fn prompt_line(label: &str) -> Result<String> {
    use std::io::Write;
    print!("{label}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::{
        digits_only, format_sas, human_since, is_yes, issuer_complete_line, join_args,
        relay_offer_lines, short_did, vault_complete_lines, vault_keeps_line, DeviceCommand, Kept, Role, ADMIT_ROLE,
        AS_WORD, BROWSER_WORD, VAULT_POSTURE_LINE,
    };
    use super::{parse_add, Add};
    use crate::commands::{Command, ExitCode};
    use kotton_schemas::membership::Posture;

    /// A DID a join records: the derivation's string for a key.
    const DID: &str = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX";

    /// A node a join completes with: `label`, under [`DID`], which is never its label.
    fn joined(label: &str) -> kotton_wire::peer::PairedNode {
        kotton_wire::peer::PairedNode {
            id: label.into(),
            device_did: kotton_wire::did::Did::parse(DID).unwrap(),
            public_key: [0xab; 32],
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: None,
        }
    }

    /// **A note's sentence on `device list`, `peer list`, `drive list` and a join's
    /// admitting side names a verb this shell registers, with the note's name**
    /// (kottonllc/kotton#605), for every key vector the Ed25519 rule refuses: the noun is
    /// a registered command and the verb is one `device` answers.
    #[test]
    fn a_notes_sentence_names_the_revoke_this_shell_registers() {
        let registry = crate::executor::ShellExecutor::new().registry();
        let (noun, verb) = super::DEVICE_REVOKE.split_once(' ').unwrap();
        assert!(registry.has_command(noun), "`{noun}` is not registered");
        assert!(super::known_verb(verb), "`{noun}` does not answer `{verb}`");
        for (name, bytes) in kotton_crypto::ed25519::refused_keys() {
            let did = kotton_crypto::DidKeyMethod::spelled_over(&bytes).to_string();
            for row in ["old", did.as_str()] {
                let note = kotton_wire::note::RowNote::names_no_key(row);
                let typed = format!("{} {row}", super::DEVICE_REVOKE);
                let said: Vec<String> = super::notes_said(std::slice::from_ref(&note))
                    .into_iter()
                    .map(|o| match o {
                        crate::out::Out::Note(t) => t,
                        other => panic!("{name}: {other:?}"),
                    })
                    .collect();
                assert_eq!(said.len(), 1, "{name}");
                assert!(said[0].contains("names no Ed25519 key") && said[0].contains(&typed), "{name}: {said:?}");
                let lines = super::not_handed_lines("laptop", std::slice::from_ref(&note));
                assert!(lines[0].contains("`laptop` was not handed the drive") && lines[0].contains(&typed), "{name}: {lines:?}");
            }
        }
        let stands = kotton_wire::note::RowNote {
            name: "phone".into(),
            is: kotton_wire::note::NoteKind::StandsByBytes { did_key: "did:key:z6MkA".into(), stored: "did:key:mB".into() },
        };
        let said = super::notes_said(&[stands]);
        assert!(
            matches!(&said[..], [crate::out::Out::Note(t)] if !t.contains(super::DEVICE_REVOKE) && t.contains("did:key:mB")),
            "{said:?}"
        );
    }

    /// The labels a note's name is held over: none is one plain word.
    const NOT_ONE_WORD: &[&str] =
        &["my phone", "a;b", "a|b", "a&&b", "it's", "say\"x", "a`b", "--old", "--browser", "bell\u{7}"];

    /// What this shell hands `device revoke` for `typed`, read as a typed line is:
    /// the chain's parser, the variables, the words, the redirect, then
    /// `revoke`'s own reading. Exactly one command must result.
    fn read_as_typed(typed: &str) -> super::Revoke {
        let chain = crate::parser::parse_command_chain(typed);
        assert_eq!(chain.len(), 1, "`{typed}` is {} commands: {chain:?}", chain.len());
        let words = crate::utils::parse_command(&crate::utils::expand_vars(&chain[0].command, &Default::default()));
        let (words, redirect) = crate::executor::parse_redirect(words);
        assert!(redirect.is_none(), "`{typed}` redirects");
        let (noun, verb) = super::DEVICE_REVOKE.split_once(' ').unwrap();
        assert_eq!(words.get(..2), Some(&[noun.to_owned(), verb.to_owned()][..]), "`{typed}`");
        super::revoke_target(&words[2..])
    }

    /// The `device revoke` command `line` gives to type, cut out of its backticks, or
    /// `None` where the line gives none. It reads only the backtick span the sentence
    /// opens as a command: the line's last span, ending the line with ` removes it`, and
    /// starting with the verb's words. A name between backticks holds no backtick of its
    /// own (43A), so the spans are the line's own, the join's leading device name among
    /// them (kottonllc/kotton#643). It asks nothing of the text
    /// before the span: each condition here can only turn a command the line gives into
    /// none, which the no-command tests would then pass on, so it holds no more than a
    /// command needs.
    fn command_in(line: &str) -> Option<String> {
        command_for(line, super::DEVICE_REVOKE)
    }

    /// [`command_in`] for the removal verb `verb`.
    fn command_for(line: &str, verb: &str) -> Option<String> {
        let parts: Vec<&str> = line.split('`').collect();
        if parts.len() < 3 || parts.len().is_multiple_of(2) {
            return None;
        }
        let span = parts[parts.len() - 2];
        let closed = parts[parts.len() - 1] == " removes it";
        let command = span.starts_with(&format!("{verb} "));
        (closed && command).then(|| span.to_owned())
    }

    /// The removal verbs a note's sentence names, one for each surface that registers one.
    const VERBS: [&str; 4] = [super::DEVICE_REVOKE, "vault forget", "relay forget", "kctl sudoers remove"];

    /// Names that begin with each verb's words, alone, with a word after them, and with
    /// the words a sentence closes a command with.
    fn names_beginning_with_a_verb() -> Vec<String> {
        let mut names = Vec::new();
        for verb in VERBS {
            names.push(verb.to_owned());
            names.push(format!("{verb} x"));
            names.push(format!("{verb} x removes it"));
            names.push(format!("{verb} x` removes it"));
            names.push(format!("{verb} `x` removes it"));
            names.push(format!("; `{verb} x` removes it"));
        }
        names
    }

    /// The names the second kind's sentence `said` says a command takes, with
    /// `stored` for "that recorded name".
    fn names_taken(said: &str, stored: &str) -> Vec<String> {
        let Some((_, takes)) = said.split_once(", and a command that names it takes ") else { return Vec::new() };
        let takes = takes.strip_suffix(", not the key's").unwrap_or_else(|| panic!("{said}"));
        let takes = takes.strip_suffix(", as recorded").unwrap_or(takes);
        match takes.strip_suffix(" or that recorded name") {
            _ if takes == "that recorded name" => vec![stored.to_owned()],
            Some(named) => vec![named.trim_matches('`').to_owned(), stored.to_owned()],
            None => vec![takes.trim_matches('`').to_owned()],
        }
    }

    /// **A note's name is one word the shell takes to its row** (kottonllc/kotton#597,
    /// 20A): each command a note's sentence gives to type, on `device list`, `peer list`,
    /// `drive list` and a join's admitting side, reads back through this shell's parser and
    /// `revoke`'s own reading as one command handing the revoke the note's name; and each
    /// name the second kind's sentence says a command takes reads back the same where it is
    /// one plain word. A name that is not one plain word is given no command: the first kind
    /// is told `device revoke` and that it takes the name (23A), and the second kind is told
    /// the name, shown, and that a command takes it as recorded. That the name resolves to
    /// its row is held in `kotton-peer` (`a_notes_name_is_one_word_the_shell_takes_to_its_row`).
    #[test]
    fn a_notes_name_is_one_word_the_shell_takes_to_its_row() {
        use kotton_wire::note::{NoteKind, RowNote};
        let did = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX";
        let base45 = "did:key:RD/T4NHD S5UEFOU51W*VRLU7R BKQPKA1CX30D2:YUW8HFYMN3E";
        let words = ["attic", did];
        let verbs = names_beginning_with_a_verb();
        for name in NOT_ONE_WORD.iter().copied().chain(words).chain([base45]).chain(verbs.iter().map(String::as_str)) {
            let note = RowNote::names_no_key(name);
            let mut lines: Vec<String> = super::notes_said(std::slice::from_ref(&note))
                .into_iter()
                .map(|o| match o {
                    crate::out::Out::Note(t) => t,
                    other => panic!("{other:?}"),
                })
                .collect();
            lines.extend(super::not_handed_lines("laptop", std::slice::from_ref(&note)));
            for line in &lines {
                match command_in(line) {
                    Some(typed) => assert_eq!(read_as_typed(&typed), super::Revoke::Node(Some(name.to_owned())), "{line}"),
                    None => {
                        assert!(!words.contains(&name), "a word was given no command: {line}");
                        assert!(line.contains("`device revoke` is the verb that removes it, by this name, as recorded"), "{line}");
                    }
                }
            }

            for stored in [did, base45] {
                let stands = RowNote {
                    name: name.into(),
                    is: NoteKind::StandsByBytes { did_key: "did:key:z6MkKey".into(), stored: stored.into() },
                };
                let said = match &super::notes_said(std::slice::from_ref(&stands))[..] {
                    [crate::out::Out::Note(t)] => t.clone(),
                    other => panic!("{other:?}"),
                };
                assert_eq!(command_in(&said), None, "{said}");
                let outside_the_name = said.replace(&kotton_wire::note::quoted(name), "");
                assert!(!outside_the_name.contains(super::DEVICE_REVOKE), "{said}");
                let taken = names_taken(&said, stored);
                for taken in taken.iter().filter(|t| kotton_wire::note::one_plain_word(t)) {
                    let typed = format!("{} {taken}", super::DEVICE_REVOKE);
                    assert_eq!(read_as_typed(&typed), super::Revoke::Node(Some(taken.clone())), "{said}");
                }
                let printed = kotton_wire::note::quoted(name).trim_matches('`').to_owned();
                assert!(taken.contains(&printed), "the name is not one a command takes: {said}");
                let all_words = taken.iter().all(|t| kotton_wire::note::one_plain_word(t));
                assert_eq!(said.contains(", as recorded,"), !all_words, "{said}");
            }
        }
    }

    /// **A row with no plain name is told `device revoke` and given no command, on
    /// `device list`, `peer list`, `drive list` and a join's admitting side**
    /// (kottonllc/kotton#618, 23A, 43A): a name in another script, one with a quote, one
    /// that starts with `-`, names that hold a backtick, a space and the verb's own
    /// words, and names that begin with each verb's words. The verb is in the sentence, the name is printed between its backticks with
    /// none of its own, and no command is read from either line.
    #[test]
    fn a_row_with_no_plain_name_is_told_device_revoke_and_given_no_command() {
        let names = [
            "\u{5c4b}\u{6839}\u{88cf}",
            "it's",
            "-attic",
            "a`b",
            "`",
            "a` b",
            "x` removes it; `device revoke y",
            "x`; `device revoke x` removes it",
            "x `device revoke y` removes it",
        ];
        let lines_of = |name: &str| {
            let note = kotton_wire::note::RowNote::names_no_key(name);
            let mut lines: Vec<String> = super::notes_said(std::slice::from_ref(&note))
                .into_iter()
                .map(|o| match o {
                    crate::out::Out::Note(t) => t,
                    other => panic!("{other:?}"),
                })
                .collect();
            lines.extend(super::not_handed_lines("laptop", std::slice::from_ref(&note)));
            lines
        };
        let ticks: Vec<usize> = lines_of("it's").iter().map(|l| l.matches('`').count()).collect();
        let verbs = names_beginning_with_a_verb();
        for name in names.into_iter().chain(verbs.iter().map(String::as_str)) {
            let lines = lines_of(name);
            assert_eq!(lines.len(), 2);
            for (line, ticks) in lines.iter().zip(&ticks) {
                assert!(line.contains("`device revoke` is the verb that removes it, by this name, as recorded"), "{line}");
                assert!(line.contains(&kotton_wire::note::quoted(name)), "{line}");
                assert_eq!(line.matches('`').count(), *ticks, "a backtick of the name was printed as one: {line}");
                assert_eq!(command_in(line), None, "{line}");
            }
        }
    }

    /// Labels that hold a character of each class `shown` prints by its escape
    /// (kottonllc/kotton#597, 42A), each beside the print the renderer gives it: a
    /// control, a format, a private-use and an unassigned character, a separator other
    /// than the space, a default-ignorable letter, U+2800, `\`, a mark with nothing
    /// before it, and a backtick, a letter of another script and a quote, which are
    /// printed as they are.
    const LABELS: [(&str, &str); 13] = [
        ("bell\u{7}", "bell\\u{7}"),
        ("two\nlines", "two\\nlines"),
        ("\u{202e}enohp", "\\u{202e}enohp"),
        ("ph\u{200d}one", "ph\\u{200d}one"),
        ("ph\u{e000}one", "ph\\u{e000}one"),
        ("ph\u{378}one", "ph\\u{378}one"),
        ("ph\u{2029}one", "ph\\u{2029}one"),
        ("ph\u{115f}one", "ph\\u{115f}one"),
        ("ph\u{2800}one", "ph\\u{2800}one"),
        ("\u{301}phone", "\\u{301}phone"),
        ("a\\b", "a\\\\b"),
        ("a`b", "a`b"),
        ("\u{5c4b}\u{6839}'s", "\u{5c4b}\u{6839}'s"),
    ];

    /// **Every cell that carries a label is printed by `shown`, and `--json` carries it as
    /// stored** (kottonllc/kotton#618, kottonllc/kotton#597, 39A): `device list`'s two
    /// tables and `peer list`'s, built from rows under [`LABELS`] and rendered by the
    /// renderer, hold none of the characters `shown` escapes and each label's print; the
    /// same shapes serialized as `--json` writes them and parsed back hold each label as
    /// stored. The join's line prints the name between backticks (43A).
    #[test]
    fn every_cell_that_carries_a_label_is_printed_by_shown() {
        let node = |label: &str| kotton_wire::peer::PairedNode {
            id: label.into(),
            device_did: kotton_wire::did::Did::parse("did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX").unwrap(),
            public_key: [0xab; 32],
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: None,
        };
        let browser = |label: &str| kotton_wire::ipc::types::BrowserDevice { name: label.into(), created_at: 0, last_used_at: None };
        let nodes: Vec<_> = LABELS.iter().map(|(l, _)| node(l)).collect();
        let browsers: Vec<_> = LABELS.iter().map(|(l, _)| browser(l)).collect();
        let mut device_list = vec![super::device_table(&nodes)];
        device_list.extend(super::browser_table(&browsers));
        assert_eq!(device_list.len(), 2, "both tables of `device list`");
        let peer_list = vec![crate::commands::peer::list_table(&nodes)];

        for shapes in [&device_list, &peer_list] {
            let text: String = shapes.iter().map(crate::out::render_shape).collect::<Vec<_>>().join("\n");
            let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(shapes).unwrap()).unwrap();
            for (i, shape) in shapes.iter().enumerate() {
                let crate::out::Out::Table { rows, .. } = shape else { panic!("a table: {shape:?}") };
                for (row, (label, said)) in rows.iter().zip(LABELS) {
                    assert_eq!(row[0], label, "a command put a print in the cell: {said}");
                    assert_eq!(kotton_wire::note::shown(&row[0]), said, "{label:?}");
                    assert!(text.lines().any(|l| l.trim_start().starts_with(said)), "{said} is not printed: {text}");
                }
                let read: Vec<String> = json[i]["table"]["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r[0].as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(read, LABELS.map(|(l, _)| l.to_owned()), "`--json` does not carry the label as stored");
            }
            for (label, said) in LABELS {
                if label != said {
                    // A line break is the renderer's own between rows; a label's is held by its
                    // print beginning a row, above.
                    for c in label.chars().filter(|c| !said.contains(*c) && *c != '\n') {
                        assert!(!text.contains(c), "{c:?} was printed as it is: {text}");
                    }
                }
            }
        }
        for (label, _) in LABELS {
            let lines = super::not_handed_lines("laptop", &[kotton_wire::note::RowNote::names_no_key(label)]);
            let quoted = kotton_wire::note::quoted(label);
            assert!(lines[0].starts_with(&format!("`laptop` was not handed the drive reached through {quoted}: ")), "{lines:?}");
        }
    }

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    /// An unknown verb is the usage refusal, exit 2, before any session; a known verb is
    /// left to its session (`None`).
    #[tokio::test]
    async fn an_unknown_verb_is_refused_before_a_session_and_a_known_one_is_not() {
        let refused = DeviceCommand
            .execute_without_session(&args(&["admitx"]), Some("nobody"))
            .await
            .expect("an unknown verb is answered without a session")
            .unwrap();
        assert_eq!(refused.exit_code, ExitCode::Code(2));
        let [crate::out::Out::Fail { what, .. }] = refused.out.as_slice() else {
            panic!("not one failure: {:?}", refused.out)
        };
        assert!(what.starts_with("usage: device add"), "{what}");
        assert!(DeviceCommand.execute_without_session(&args(&["list"]), None).await.is_none());
    }

    /// `device add`'s grammar: each single flag and `--as NAME` parses, with the default
    /// posture when none is named.
    #[test]
    fn parse_add_accepts_each_single_flag_and_as() {
        let device = |as_name: Option<&str>, posture| Add::Device { as_name: as_name.map(String::from), posture };
        assert_eq!(parse_add(&args(&[])).unwrap(), device(None, Posture::Full));
        assert_eq!(parse_add(&args(&["--blind"])).unwrap(), device(None, Posture::BlindStorage));
        assert_eq!(parse_add(&args(&["--cosigner"])).unwrap(), device(None, Posture::Cosigner));
        assert_eq!(parse_add(&args(&["--as", "phone"])).unwrap(), device(Some("phone"), Posture::Full));
        assert_eq!(
            parse_add(&args(&["--as", "phone", "--cosigner"])).unwrap(),
            device(Some("phone"), Posture::Cosigner)
        );
        assert_eq!(parse_add(&args(&["--browser"])).unwrap(), Add::Browser);
        assert_eq!(
            parse_add(&args(&["--gateway", "CODE"])).unwrap(),
            Add::Gateway { flag: "--gateway", code: "CODE".into() }
        );
    }

    /// Two posture flags, a flag twice, a flag the verb does not have, and a flag missing its
    /// value are usage, exit 2.
    #[test]
    fn parse_add_refuses_two_posture_flags_a_repeat_and_an_unknown_flag() {
        for line in [
            &["--blind", "--cosigner"][..],
            &["--cosigner", "--as", "x", "--blind"],
            &["--blind", "--blind"],
            &["--as", "a", "--as", "b"],
            &["--full"],
            &["--frob"],
            &["phone"],
            &["--as"],
            &["--gateway"],
            &["--browser", "--blind"],
            &["--gateway", "CODE", "--as", "x"],
        ] {
            let refused = parse_add(&args(line)).expect_err(&format!("{line:?}"));
            assert_eq!(refused.exit_code, ExitCode::Code(2), "{line:?}");
        }
    }

    /// The vocabulary `parse_add` and the daemon's hints share, walked over every posture: each
    /// posture's word parses back to that posture alone, and every pair of flags is the usage
    /// refusal, whichever way round.
    #[test]
    fn parse_add_and_the_shared_vocabulary_agree_on_every_posture_and_every_pair() {
        use kotton_schemas::membership::{device_add_word, DeviceAddValue, DeviceAddWord};
        let mut flags = Vec::new();
        for &posture in Posture::ALL {
            let word = device_add_word(posture);
            let parsed = parse_add(&args(&word.to_string().split_whitespace().collect::<Vec<_>>())).unwrap();
            // What the line asked for, read back as the word that asks for it.
            let read = match parsed {
                Add::Device { as_name: None, posture } => Some(device_add_word(posture)),
                Add::Gateway { flag, .. } => Some(DeviceAddWord::FlagWithValue {
                    flag,
                    value: DeviceAddValue::GatewayCode,
                }),
                _ => None,
            };
            assert_eq!(read, Some(word), "{word}");
            if let DeviceAddWord::Flag(flag) = word {
                flags.push(flag);
            }
        }
        for flag in &flags {
            for other in &flags {
                assert!(parse_add(&args(&[flag, other])).is_err(), "{flag} {other}");
            }
        }
    }

    /// The usage line assembled from the vocabulary is the line it printed when it was written
    /// by hand, byte for byte: the bracket's flags sorted, and the word with a value after
    /// `--browser`.
    #[test]
    fn the_assembled_usage_line_is_the_one_printed_before() {
        let printed = super::usage();
        let [crate::out::Out::Fail { what, .. }] = printed.out.as_slice() else {
            panic!("not one failure: {:?}", printed.out)
        };
        assert_eq!(
            what,
            "usage: device add [--as NAME] [--blind|--cosigner] | device add --browser | \
             device add --gateway <code> | device join [code] [--as NAME] | device list | \
             device revoke <id> | device revoke --browser <name> | \
             device name [NAME]   (`kotton device reset` starts this device fresh)"
        );
    }

    /// Every `device add` flag `device`'s help page names is a word [`device_add_word`] yields,
    /// or one of the shell's own words `parse_add` reads, [`AS_WORD`] and [`BROWSER_WORD`];
    /// and every word with a value is named whole, placeholder and all. A hand-spelled posture
    /// flag the vocabulary no longer has is a word in neither, and fails here.
    #[test]
    fn every_device_add_flag_the_help_names_is_one_device_add_word_yields() {
        use kotton_schemas::membership::{device_add_word, DeviceAddWord};
        let help = DeviceCommand.help_text();
        let words: Vec<DeviceAddWord> = Posture::ALL.iter().map(|&p| device_add_word(p)).collect();
        let table: Vec<&str> = words
            .iter()
            .filter_map(|w| match *w {
                DeviceAddWord::Bare => None,
                DeviceAddWord::Flag(flag) | DeviceAddWord::FlagWithValue { flag, .. } => Some(flag),
            })
            .collect();
        // The shell's own words, the constants `parse_add` reads: neither is a posture's.
        let own = [AS_WORD, BROWSER_WORD];
        assert!(parse_add(&args(&[AS_WORD, "x"])).is_ok());
        assert!(parse_add(&args(&[BROWSER_WORD])).is_ok());
        for word in own {
            assert!(!table.contains(&word), "{word} is a posture's word and the shell's own");
        }
        let named: Vec<&str> = help
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .filter(|t| t.starts_with("--"))
            .collect();
        assert!(named.iter().any(|w| table.contains(w)), "the help names no posture's word: {help}");
        for word in &named {
            assert!(
                table.contains(word) || own.contains(word),
                "`device`'s help names `{word}`, which `device_add_word` does not yield: {help}"
            );
        }
        for word in &words {
            if let DeviceAddWord::FlagWithValue { .. } = word {
                assert!(help.contains(&format!("`{word}`")), "the help does not name `{word}` whole: {help}");
            }
        }
    }

    /// The same refusal before any session: a known verb whose words do not parse is answered
    /// by `execute_without_session`, and one that parses is left to its session.
    #[tokio::test]
    async fn a_device_add_line_that_does_not_parse_is_refused_before_a_session() {
        let refused = DeviceCommand
            .execute_without_session(&args(&["add", "--blind", "--cosigner"]), Some("nobody"))
            .await
            .expect("answered without a session")
            .unwrap();
        assert_eq!(refused.exit_code, ExitCode::Code(2));
        assert!(DeviceCommand
            .execute_without_session(&args(&["add", "--as", "x", "--blind"]), None)
            .await
            .is_none());
    }

    /// The admit ends by saying what the flag used to: the vault keeps what it
    /// cannot read.
    #[test]
    fn a_vault_admitted_is_told_its_posture_in_words() {
        assert!(VAULT_POSTURE_LINE.starts_with("it keeps what it cannot read"), "{VAULT_POSTURE_LINE}");
        // The admit runs the vault's ceremony, and that ceremony's success says the
        // posture before what to do next.
        assert!(ADMIT_ROLE == Role::Vault, "`drive enrol` must run the vault's ceremony");
        let said = vault_complete_lines(&joined("vault"), Some(&Kept { here: vec![], personal_anywhere: true }));
        assert_eq!(said.first().map(String::as_str), Some(VAULT_POSTURE_LINE), "{said:?}");
        assert_eq!(said.len(), 2, "{said:?}");
    }

    /// **The line after `enrol` says what the vault keeps** (RFC 0002; kotton
    /// #124): the first vault keeps `personal`, which this device's files sync
    /// with; a vault enrolled after it holds nothing until a drive is made or
    /// moved there, and the line names both verbs at that vault; and a list
    /// that did not answer sends the person to `drive list`, claiming nothing.
    #[test]
    fn the_line_after_enrol_says_a_later_vault_holds_nothing_until_a_drive_is_put_there() {
        let kept = |here: &[&str], personal_anywhere: bool| Kept { here: here.iter().map(|n| n.to_string()).collect(), personal_anywhere };
        let first = vault_keeps_line(&joined("home"), Some(&kept(&["personal"], true)));
        assert!(first.contains("keeps `personal`") && first.contains("sync"), "{first}");
        let later = vault_keeps_line(&joined("office"), Some(&kept(&[], true)));
        assert!(later.starts_with("it holds nothing of yours until a drive is made or moved there"), "{later}");
        assert!(later.contains(&format!("`drive create <name> --on {DID}`")) && later.contains(&format!("`drive move <name> --to {DID}`")), "{later}");
        assert!(!later.contains("sync"), "a vault that holds nothing is offered a sync: {later}");
        let unknown = vault_keeps_line(&joined("office"), None);
        assert!(unknown.contains("`drive list`") && !unknown.contains("holds nothing"), "{unknown}");
        assert_eq!(vault_keeps_line(&joined("office"), Some(&kept(&["photos"], true))), "it keeps `photos`.");
        // The first enrolment could not make `personal`: what `status` says
        // of it, never that a drive made or moved there is all it lacks.
        let unmade = vault_keeps_line(&joined("home"), Some(&kept(&[], false)));
        assert!(unmade.starts_with("it holds nothing yet, and none of your vaults has listed 'personal'"), "{unmade}");
        assert!(unmade.contains("add or enrol that vault first") && unmade.contains("only if no vault of yours holds it"), "{unmade}");
        assert!(!unmade.contains("until a drive is made or moved there"), "{unmade}");
    }

    /// **An admit that offered the meeting relay says so, and names the one
    /// command that takes it** — `relay set` with the relay's line, so the
    /// relay is held to the key the invite named. Nothing is taken by the
    /// admit (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`,
    /// Done-when (3)).
    #[test]
    fn an_offered_relay_is_said_with_the_command_that_takes_it() {
        let line = format!("kotton-instance:relay:{}@http://relay.example:7700", "ab".repeat(32));
        let said = relay_offer_lines(&line);
        assert!(said[0].contains("stands at no relay") && said[0].contains("http://relay.example:7700"), "{said:?}");
        assert_eq!(said[1], format!("to stand this device there too: `relay set {line}`"));
    }

    /// **The issuer's line says bare `sync` and names the remote, and gives no command
    /// with it** (kottonllc/kotton#597, 51A): `sync` takes no word after it, so the line
    /// ends at the label, printed by `quoted`.
    #[test]
    fn the_pairing_line_says_bare_sync_and_names_the_remote() {
        let line = issuer_complete_line(&joined("my-vps"));
        assert_eq!(line, "run `sync` when you want to copy data to it — its remote is `my-vps`.");
    }

    /// The roles a join admits, each with a completion of its own.
    const ROLES: [Role; 6] = [Role::Issuer, Role::Box, Role::Vault, Role::OwnVault, Role::Joiner, Role::Browser];

    /// The label every other is held against: one plain word, in no fixed text.
    const PLAIN: &str = "laptop";

    /// Every string a join's completion hands the renderer for `role` and a node
    /// labelled `label`, in order: the greeting (first), then the lines under it for each
    /// answer `drive list` may give a vault, then the line for a drive the join did not
    /// hand.
    fn completion_said(role: Role, label: &str) -> Vec<String> {
        let kept = |here: &[&str], personal_anywhere: bool| Kept { here: here.iter().map(|n| n.to_string()).collect(), personal_anywhere };
        let node = joined(label);
        let (words, name) = super::greeting(role, Some(&node.id));
        let mut lines = vec![format!("{words} {name}")];
        for keeps in [None, Some(kept(&["personal"], true)), Some(kept(&[], true)), Some(kept(&[], false)), Some(kept(&["photos"], true))] {
            lines.extend(super::completion_lines(role, &node, keeps.as_ref()));
        }
        lines.extend(super::not_handed_lines(label, &[kotton_wire::note::RowNote::names_no_key("vps-1")]));
        lines
    }

    /// The backtick spans of `line`: the text between each opening backtick and its close.
    fn spans(line: &str) -> Vec<&str> {
        line.split('`').skip(1).step_by(2).collect()
    }

    /// **Every string a join's completion hands the renderer gives the joined device's
    /// label as data, and none puts it in a command** (kottonllc/kotton#643;
    /// kottonllc/kotton#597, 39A, 43A, 51A, 52C, 53A, 55B and 58A), for each role a join
    /// admits, the Browser's greeting among them, over labels that hold a character of
    /// each class `shown` escapes, labels that are not one plain word, and labels that
    /// begin with a verb's words, each on a node whose DID is not its label:
    ///
    /// - the greeting ends with the label by `quoted`, and every line, the greeting too,
    ///   is the plain-word label's line with that label's `quoted` print replaced by this
    ///   label's; so no line holds a character `shown` escapes;
    /// - every line holds as many backticks as the plain-word label's, in the same spans;
    /// - each command, with `<name>` filled by a plain word, reads back through the
    ///   shell's parser as one command with no redirect, and through `drive`'s own parser
    ///   with the joined node's DID after `--on` and `--to`.
    ///
    /// What is held here is the strings as handed to `ui::body` and `ui::greet`; that
    /// the renderer keeps each name's print and each command whole on one line is held by
    /// `a_wrapped_line_keeps_a_names_print_whole_and_a_command_on_one_line`
    /// (kottonllc/kotton#654).
    #[test]
    fn a_joins_completion_prints_the_label_as_data_and_in_no_command() {
        use kotton_wire::note::{quoted, shown};
        let verbs = names_beginning_with_a_verb();
        let labels: Vec<&str> =
            LABELS.iter().map(|(l, _)| *l).chain(NOT_ONE_WORD.iter().copied()).chain(verbs.iter().map(String::as_str)).collect();
        let mut commands = 0;
        for role in ROLES {
            let plain = completion_said(role, PLAIN);
            for label in &labels {
                let said = completion_said(role, label);
                assert_eq!(said.len(), plain.len(), "{role:?} {label:?}");
                let printed = shown(label);
                assert!(said[0].ends_with(&format!(" {}", quoted(label))), "{role:?}: the label is not last on its greeting: {}", said[0]);
                for (line, plain) in said.iter().zip(&plain) {
                    assert_eq!(*line, plain.replace(&quoted(PLAIN), &quoted(label)), "{role:?}: a label printed outside its quote");
                }
                for (line, plain) in said.iter().zip(&plain) {
                    for c in label.chars().filter(|c| !printed.contains(*c)) {
                        assert!(!line.contains(c), "{role:?}: {c:?} was printed as it is: {line}");
                    }
                    assert_eq!(line.matches('`').count(), plain.matches('`').count(), "{role:?}: {line}");
                    let inner = quoted(label);
                    let inner = &inner[1..inner.len() - 1];
                    let ours: Vec<&str> = spans(line).into_iter().map(|s| if s == inner { PLAIN } else { s }).collect();
                    assert_eq!(ours, spans(plain), "{role:?}: the spans are not the plain word's: {line}");
                }
            }
            for line in labels.iter().chain([&PLAIN]).flat_map(|l| completion_said(role, l)) {
                for span in spans(&line) {
                    // A command this line composes for the joined node; the fixed words
                    // `PinNotice` says, which name `<vault>` as usage, are not about it.
                    if !span.contains("<name>") {
                        continue;
                    }
                    let typed = span.replace("<name>", "photos");
                    let chain = crate::parser::parse_command_chain(&typed);
                    assert_eq!(chain.len(), 1, "`{typed}` is {} commands", chain.len());
                    let read = crate::utils::parse_command(&crate::utils::expand_vars(&chain[0].command, &Default::default()));
                    let (read, redirect) = crate::executor::parse_redirect(read);
                    assert!(redirect.is_none(), "`{typed}` redirects");
                    assert_eq!(read[0], "drive", "`{typed}`");
                    use crate::commands::drive::Line;
                    match crate::commands::drive::parse(&read[1..]) {
                        Ok(Line::Create { name: "photos", on: Some(on) }) => assert_eq!(on, DID, "`{typed}`"),
                        Ok(Line::Move { name: "photos", to, from: None }) => assert_eq!(to, DID, "`{typed}`"),
                        other => panic!("`{typed}` reads as {other:?}"),
                    }
                    commands += 1;
                }
            }
        }
        assert_eq!(commands, 4 * (labels.len() + 1), "a vault's two commands, for each of the two vault roles and each label");
    }

    /// **A completion's commands take the joined node's DID, not its label**
    /// (kottonllc/kotton#597, 52C; kottonllc/kotton#643): the lines are made from the
    /// node, and for a node whose label is a plain word that is not its DID, every
    /// command span in every role's lines carries the DID and not the label.
    #[test]
    fn a_completions_commands_take_the_nodes_did_and_not_its_label() {
        let kept = Kept { here: vec![], personal_anywhere: true };
        let node = joined("office");
        let mut commands = 0;
        for role in ROLES {
            for line in super::completion_lines(role, &node, Some(&kept)).iter().chain(&super::completion_lines(role, &node, None)) {
                for span in spans(line).into_iter().filter(|s| s.contains(" --on ") || s.contains(" --to ")) {
                    let words: Vec<&str> = span.split(' ').collect();
                    assert_eq!(words.last(), Some(&DID), "{role:?}: {span}");
                    assert!(!words.contains(&"office"), "{role:?}: the label is in a command: {span}");
                    commands += 1;
                }
            }
        }
        assert_eq!(commands, 4, "a vault's two commands, for each of the two vault roles");
    }

    /// **A browser that gave no name is greeted in the shell's own words** (kottonllc/kotton#597,
    /// 55B): "the phone is in — your browser", with no delimiter, since it is not a name.
    #[test]
    fn a_browser_with_no_name_is_greeted_in_the_shells_words() {
        let (words, name) = super::greeting(Role::Browser, None);
        assert_eq!(format!("{words} {name}"), "the phone is in — your browser");
        let (_, named) = super::greeting(Role::Browser, Some("your browser"));
        assert_eq!(named, "`your browser`");
    }

    /// `handed` as the renderer writes it at `width`, held: every rendered line, joined
    /// by one space, gives back `handed`; each line's backticks are even, and its spans,
    /// in order across the lines, are `handed`'s; a line wider than `width` is one word,
    /// with no space outside a span; and each of `names`' `quoted` print is in the
    /// rendered lines as often as in `handed`, each within one line. Returns the
    /// rendered lines, each with its spans.
    fn rendered(handed: &str, width: usize, names: &[&str]) -> Vec<(String, Vec<String>)> {
        let lines = crate::ui::wrap_to(handed, width);
        assert_eq!(lines.join(" "), handed, "at {width}: a character was changed or lost");
        let mut all = Vec::new();
        let mut out = Vec::new();
        for line in &lines {
            assert!(line.matches('`').count().is_multiple_of(2), "at {width}: a span is broken across lines: {lines:#?}");
            if line.chars().count() > width {
                let outside: Vec<&str> = line.split('`').step_by(2).collect();
                assert!(!outside.iter().any(|o| o.contains(' ')), "at {width}: a line wider than the column holds two words: {line}");
            }
            let spans: Vec<String> = spans(line).into_iter().map(str::to_owned).collect();
            all.extend(spans.iter().cloned());
            out.push((line.clone(), spans));
        }
        assert_eq!(all, spans(handed), "at {width}: the spans are not the line's: {lines:#?}");
        for name in names {
            let print = kotton_wire::note::quoted(name);
            let within: usize = lines.iter().map(|l| l.matches(&print).count()).sum();
            assert_eq!(within, handed.matches(&print).count(), "at {width}: {print} is not whole on one line: {lines:#?}");
        }
        out
    }

    /// `typed`, read as a typed line is, is one `verb` command handing it `name`: through
    /// `device revoke`'s own reading for that verb ([`read_as_typed`]), and for another
    /// verb through the chain's parser, the variables, the words and the redirect.
    fn reads_back(typed: &str, verb: &str, name: &str) {
        if verb == super::DEVICE_REVOKE {
            assert_eq!(read_as_typed(typed), super::Revoke::Node(Some(name.to_owned())), "`{typed}`");
            return;
        }
        let chain = crate::parser::parse_command_chain(typed);
        assert_eq!(chain.len(), 1, "`{typed}` is {} commands: {chain:?}", chain.len());
        let words = crate::utils::parse_command(&crate::utils::expand_vars(&chain[0].command, &Default::default()));
        let (words, redirect) = crate::executor::parse_redirect(words);
        assert!(redirect.is_none(), "`{typed}` redirects");
        let mut want: Vec<String> = verb.split(' ').map(str::to_owned).collect();
        want.push(name.to_owned());
        assert_eq!(words, want, "`{typed}`");
    }

    /// **A wrapped line keeps a name's print whole and a command on one line**
    /// (kottonllc/kotton#654; kottonllc/kotton#597, 56B and 57A). Rendered by `ui::wrap_to`,
    /// which `ui::body` and `Out::Note` print through, at the narrowest and the widest
    /// content width: each string a join's completion hands the renderer for each role,
    /// and each note's sentence for both kinds and each verb, over [`LABELS`],
    /// [`NOT_ONE_WORD`], the names that begin with a verb's words, a name with two spaces
    /// together, a plain word and a DID a join records (see [`rendered`] for what is held
    /// of each line):
    ///
    /// - each name's `quoted` print is in one rendered line, character for character;
    /// - each command span is in one rendered line, and read from it reads back through
    ///   the shell's parser: a vault's two commands as `drive`'s with the joined node's DID,
    ///   and a note's command as its verb's with the note's name.
    ///
    /// The greeting is written whole by `ui::greet`, and is rendered here too.
    #[test]
    fn a_wrapped_line_keeps_a_names_print_whole_and_a_command_on_one_line() {
        use kotton_wire::note::{one_plain_word, sentence, NoteKind, RowNote};
        let verbs = names_beginning_with_a_verb();
        let names: Vec<&str> = LABELS
            .iter()
            .map(|(l, _)| *l)
            .chain(NOT_ONE_WORD.iter().copied())
            .chain(verbs.iter().map(String::as_str))
            .chain([PLAIN, DID, "two  spaces"])
            .collect();
        let mut drive_commands = 0;
        let mut note_commands = 0;
        for width in [crate::ui::WIDTH_MIN, crate::ui::WIDTH_MAX] {
            for role in ROLES {
                for label in &names {
                    for handed in completion_said(role, label) {
                        for (_, spans) in rendered(&handed, width, &[label, "vps-1"]) {
                            for span in spans.iter().filter(|s| s.contains("<name>")) {
                                let typed = span.replace("<name>", "photos");
                                let chain = crate::parser::parse_command_chain(&typed);
                                assert_eq!(chain.len(), 1, "`{typed}` is {} commands", chain.len());
                                let read =
                                    crate::utils::parse_command(&crate::utils::expand_vars(&chain[0].command, &Default::default()));
                                let (read, redirect) = crate::executor::parse_redirect(read);
                                assert!(redirect.is_none(), "`{typed}` redirects");
                                assert_eq!(read[0], "drive", "`{typed}`");
                                use crate::commands::drive::Line;
                                match crate::commands::drive::parse(&read[1..]) {
                                    Ok(Line::Create { name: "photos", on: Some(on) }) => assert_eq!(on, DID, "`{typed}`"),
                                    Ok(Line::Move { name: "photos", to, from: None }) => assert_eq!(to, DID, "`{typed}`"),
                                    other => panic!("`{typed}` reads as {other:?}"),
                                }
                                drive_commands += 1;
                            }
                            for span in spans.iter().filter(|s| s.starts_with("device revoke vps-1")) {
                                reads_back(span, super::DEVICE_REVOKE, "vps-1");
                                note_commands += 1;
                            }
                        }
                    }
                }
            }
            for verb in VERBS {
                for name in &names {
                    let kinds = [
                        RowNote::names_no_key(*name),
                        RowNote { name: (*name).into(), is: NoteKind::StandsByBytes { did_key: DID.into(), stored: DID.into() } },
                        RowNote { name: (*name).into(), is: NoteKind::StandsByBytes { did_key: DID.into(), stored: (*name).into() } },
                    ];
                    for note in kinds {
                        let handed = sentence(&note, verb);
                        let lines = rendered(&handed, width, &[name, DID]);
                        let Some(typed) = command_for(&handed, verb) else {
                            assert!(!matches!(note.is, NoteKind::NamesNoKey) || !one_plain_word(name), "{handed}");
                            continue;
                        };
                        let at = spans(&handed).len() - 1;
                        let (line, spans) = lines
                            .iter()
                            .scan(0, |seen, (line, spans)| {
                                let first = *seen;
                                *seen += spans.len();
                                Some((first, line, spans))
                            })
                            .find(|(first, _, spans)| at < first + spans.len())
                            .map(|(first, line, spans)| (line, spans[at - first].clone()))
                            .unwrap_or_else(|| panic!("at {width}: no line holds the command of {handed}"));
                        assert_eq!(spans, typed, "at {width}: {line}");
                        reads_back(&spans, verb, name);
                        note_commands += 1;
                    }
                }
            }
        }
        assert_eq!(drive_commands, 2 * 4 * names.len(), "a vault's two commands, for each vault role, label and width");
        let plain = names.iter().filter(|n| one_plain_word(n)).count();
        assert_eq!(
            note_commands,
            2 * (ROLES.len() * names.len() + VERBS.len() * plain),
            "the not-handed line's command for each role and label, and each plain name's for each verb, at each width"
        );
    }

    #[test]
    fn sas_formats_zero_padded_and_grouped() {
        assert_eq!(format_sas(472913), "472 913");
        assert_eq!(format_sas(13), "000 013");
        assert_eq!(format_sas(0), "000 000");
        assert_eq!(format_sas(999999), "999 999");
    }

    #[test]
    fn transcribed_sas_ignores_spacing() {
        // What the human types must match the zero-padded six-digit SAS regardless of
        // how they group it — the issuer's confirm compares `digits_only` to `{sas:06}`.
        assert_eq!(digits_only("798 095"), "798095");
        assert_eq!(digits_only("798095"), "798095");
        assert_eq!(digits_only("798-095\n"), "798095");
        assert_eq!(digits_only("000 013"), format!("{:06}", 13));
    }

    #[test]
    fn consent_defaults_to_no() {
        assert!(is_yes("y"));
        assert!(is_yes("  YES "));
        assert!(!is_yes(""));
        assert!(!is_yes("n"));
        assert!(!is_yes("yeah"));
    }

    #[test]
    fn short_did_keeps_head_and_tail() {
        assert_eq!(
            short_did("did:key:9646e10858a341718ce233bc5bda1bb4fa90e363aa801755c519b0f72454350f"),
            "did:key:9646e108…350f"
        );
        // Already short → untouched.
        assert_eq!(short_did("did:key:abcd"), "did:key:abcd");
        assert_eq!(short_did("no-colon"), "no-colon");
    }

    #[test]
    fn human_since_buckets_by_magnitude() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(human_since(now), "just now");
        assert_eq!(human_since(now - 300), "5m ago");
        assert_eq!(human_since(now - 3 * 3600), "3h ago");
        assert_eq!(human_since(now - 2 * 86_400), "2d ago");
    }

    /// `device join` reads its code wherever it is typed, and `--as`'s value is never
    /// taken for the code.
    #[test]
    fn join_reads_the_code_and_the_announced_name_in_either_order() {
        let code = "0123abcd@127.0.0.1:7000";
        for line in [
            &["--as", "laptop", code][..],
            &[code, "--as", "laptop"],
        ] {
            assert_eq!(join_args(&args(line)), (code.to_string(), Some("laptop".to_string())), "{line:?}");
        }
        assert_eq!(join_args(&args(&["--as", "laptop"])), (String::new(), Some("laptop".to_string())));
        assert_eq!(join_args(&[]), (String::new(), None));
    }

    /// **Why `device join` may run with no session.** Every request it sends is one the
    /// daemon answers before anyone is signed in, read from `core/wire`'s
    /// `requires_session`, which is the definition. If either ever needs a session,
    /// the session-less form at a terminal would be refused at the daemon, and this
    /// goes red first.
    #[test]
    fn every_request_a_join_sends_is_answered_without_a_session() {
        use kotton_wire::ipc::{SecretText, UserRequest};
        for request in [
            UserRequest::DeviceJoin {
                user_id: "alice".into(),
                code: SecretText::new(""),
                as_name: None,
            },
            UserRequest::PairConfirmCode {
                user_id: "alice".into(),
                token: SecretText::new(""),
                matches: true,
            },
        ] {
            assert!(!request.requires_session(), "{} needs a session", request.variant_name());
        }
    }

    /// At a terminal, `device join` is the one `device` line that runs without a
    /// session; with no identity named it says how to name one, before it connects to
    /// anything, and every other line goes to the door's connected path.
    #[tokio::test]
    async fn only_join_runs_without_a_session_and_it_needs_a_name() {
        let refused = DeviceCommand
            .execute_without_session(&args(&["join", "some-code"]), None)
            .await
            .expect("join runs without a session")
            .expect("it answers rather than erring");
        assert_eq!(refused.exit_code, ExitCode::Code(1));
        let said = format!("{:?}", refused.out);
        assert!(said.contains("kotton id join <name>"), "{said}");
        for other in [&["add"][..], &["list"], &["name"], &[]] {
            assert!(
                DeviceCommand.execute_without_session(&args(other), Some("alice")).await.is_none(),
                "`device {other:?}` ran without a session"
            );
        }
    }

    /// **`device admit` is retired and says exactly this** before any session, with or
    /// without an invite: the gone line naming `drive enrol <invite>`, exit 2. The
    /// REPL's door (`execute`) is pinned by the suite's `repl_verbs`.
    #[tokio::test]
    async fn device_admit_is_the_retired_line_and_exit_two_before_any_session() {
        // The retired line is built by the helper the door answers with, so this holds
        // the sessionless door to exactly it; the REPL's door is held to the literal
        // words by the suite case.
        let want = crate::commands::retired("device admit", "drive enrol <invite>");
        for line in [&["admit"][..], &["admit", "CODE"], &["admit", "CODE", "extra"], &["admit", "--blind"]] {
            let words = args(line);
            let without = DeviceCommand
                .execute_without_session(&words, Some("alice"))
                .await
                .expect("the retired word is refused before a session")
                .expect("it answers rather than erring");
            assert_eq!(without.exit_code, ExitCode::Code(2), "{line:?}");
            assert_eq!(format!("{:?}", without.out), format!("{:?}", want.out), "{line:?}");
            // What a person reads: the gone line and the verb to type, in these words.
            let [crate::out::Out::Fail { what, try_: Some(try_) }] = without.out.as_slice() else {
                panic!("not one failure with a next step: {:?}", without.out)
            };
            assert_eq!(
                format!("{what} / try `{try_}`"),
                "`device admit` is gone / try `drive enrol <invite>`",
                "{line:?}"
            );
        }
    }
}
