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

#[derive(Clone, Copy, PartialEq)]
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

/// The usage refusal, exit 2: what `device` prints for a word it does not have: the
/// grammar ([`device_usage_grammar`]), and an aside that `reset` is the CLI's.
fn usage() -> CommandOutput {
    CommandOutput::usage(
        format!(
            "usage: {}   (`kotton device reset` starts this device fresh)",
            device_usage_grammar()
        ),
        None,
    )
}

/// `device`'s grammar, every line the shell runs, as both doors print it: the usage line
/// (`usage`) after its `usage: `, and the CLI door's argument help for `device`
/// (`kotton_cli`'s `device_args_help`), so there is one grammar and the CLI re-spells no word
/// of it (kotton #326). The posture bracket (its flags sorted) and each word with a value are
/// assembled by walking [`device_add_word`] over every posture, the vocabulary `parse_add`
/// reads, and the shell's own words are `DEVICE_AS_WORD` and `DEVICE_BROWSER_WORD`
/// (`kotton_schemas::membership`), the constants `parse_add`, `join_args` and `revoke` read,
/// so the printed grammar has no spelling of its own. `reset` is not in it: the shell does not run it, and each door says so its own way.
pub fn device_usage_grammar() -> String {
    let valued: String = valued_words()
        .map(|(word, _)| format!("device add {word} | "))
        .collect();
    format!(
        "device add [{AS_WORD} NAME] [{}] | device add {BROWSER_WORD} | \
         {valued}\
         device join [code] [{AS_WORD} NAME] | device list | \
         device revoke <id> | device revoke {BROWSER_WORD} <name> | \
         device name [NAME]",
        device_add_posture_bracket()
    )
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
/// [`device_usage_grammar`].
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
        let rows: Vec<Vec<String>> = nodes
            .iter()
            .map(|n| {
                vec![
                    n.id.clone(),
                    short_did(&n.device_did.to_string()),
                    human_since(n.paired_at),
                ]
            })
            .collect();
        let mut shapes = vec![Out::Table {
            columns: vec!["device".into(), "did".into(), "paired".into()],
            rows,
        }];
        // The browsers admitted with `device add --browser`, beside the devices:
        // a browser is paired like a device (DEC-0053), so what acts as you is
        // one list read in one place, and the revoke below takes either.
        let browsers = client
            .list_browsers(&user_id)
            .await
            .map_err(|e| anyhow::anyhow!("device list: {e}"))?;
        if !browsers.is_empty() {
            shapes.push(Out::Table {
                columns: vec!["browser".into(), "admitted".into(), "last seen".into()],
                rows: browsers
                    .iter()
                    .map(|b| {
                        vec![
                            b.name.clone(),
                            human_since(b.created_at),
                            b.last_used_at
                                .map(human_since)
                                .unwrap_or_else(|| "—".into()),
                        ]
                    })
                    .collect(),
            });
        }
        Ok(CommandOutput::shapes(shapes))
    }

    /// `device revoke <id>` — remove a device from the identity (drops it from the
    /// mTLS allowlist on the next handshake).
    ///
    /// `device revoke --browser <name>` revokes an admitted browser instead: its
    /// next visit needs a human again, and a channel it holds open now is ended
    /// rather than left to run out.
    async fn revoke(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.first().map(String::as_str) == Some(BROWSER_WORD) {
            let Some(name) = args.get(1).cloned() else {
                return Ok(CommandOutput::fail(revoke_browser_usage(), None));
            };
            let user_id = state.user_id.clone();
            let mut client = state.client.lock().await;
            client
                .revoke_browser(&user_id, &name)
                .await
                .map_err(|e| anyhow::anyhow!("device revoke: {e}"))?;
            return Ok(CommandOutput::shapes(vec![Out::Confirm {
                action: format!("revoked browser '{name}'"),
                subject: String::new(),
            }]));
        }
        let id = match args.first() {
            Some(i) => i.clone(),
            None => return Ok(CommandOutput::fail("usage: device revoke <id>", None)),
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
}

/// What a vault admitted by `drive enrol` is, said once it is in: the posture no
/// flag named.
const VAULT_POSTURE_LINE: &str =
    "it keeps what it cannot read: your data reaches it sealed, and no key to open it does.";

/// The line a pairing ends on when this side added the other. Bare `sync` already
/// reaches every paired node (`SyncCommand`'s no-argument branch), so that is what it
/// says to run; the named form is only for syncing this one peer, and it names the
/// peer by the word `sync`'s usage and `peer list`'s column both use.
fn issuer_complete_line(remote: &str) -> String {
    format!(
        "run `sync` when you want to copy data to it — its remote is `{remote}`, \
         and `sync {remote}` syncs with it alone."
    )
}

/// Drive a ceremony stream to completion: render each state, prompt the human on the
/// six-digit frame, and deliver the verdict via `pair_confirm_code`. Shared by the
/// `device` command and the first-run "join an identity" onboarding branch so both
/// use the identical committed-SAS flow (no drift).
/// What the ceremony says under the greeting when a vault is admitted: its
/// posture in words, then what to do next. One function, so the test holds
/// what `run_ceremony` prints and not a constant beside it.
fn vault_complete_lines(node_id: &str) -> Vec<String> {
    vec![VAULT_POSTURE_LINE.to_string(), issuer_complete_line(node_id)]
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
                        ui::greet("the phone is in —", peer_label.as_deref().unwrap_or("your browser"));
                        ui::body("it reaches home with no digits shown from now on.");
                        Ok((CommandOutput::success(), None, None))
                    } else {
                        Ok((CommandOutput::error(1, "the digits did not match".to_string()), None, None))
                    };
                }
            }
            UserResponse::PairAwaitingPeer => ui::body("waiting for the other device to confirm…"),
            UserResponse::PairTransferring => ui::body("setting things up…"),
            UserResponse::PairingComplete { node, relay_offer, .. } => {
                ui::blank();
                match role {
                    Role::Issuer | Role::Box => {
                        ui::greet("added to your identity,", &node.id);
                        ui::body(&issuer_complete_line(&node.id));
                    }
                    Role::Vault => {
                        ui::greet("added to your identity,", &node.id);
                        for line in vault_complete_lines(&node.id) {
                            ui::body(&line);
                        }
                    }
                    Role::OwnVault => {
                        ui::greet("you keep at your own vault now —", &node.id);
                        ui::body(&issuer_complete_line(&node.id));
                    }
                    Role::Joiner => {
                        ui::greet("you're in — paired with", &node.id);
                        ui::body("run `sync` to pull your data when you want it.");
                    }
                    Role::Browser => ui::greet("the phone is in —", &node.id),
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
        relay_offer_lines, short_did, vault_complete_lines, DeviceCommand, Role, ADMIT_ROLE,
        AS_WORD, BROWSER_WORD, VAULT_POSTURE_LINE,
    };
    use super::{parse_add, Add};
    use crate::commands::{Command, ExitCode};
    use kotton_schemas::membership::Posture;

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
        let said = vault_complete_lines("did:key:zV");
        assert_eq!(said.first().map(String::as_str), Some(VAULT_POSTURE_LINE), "{said:?}");
        assert_eq!(said.len(), 2, "{said:?}");
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

    /// The pairing screen says bare `sync`, which reaches every paired node, and
    /// names the peer by the word `peer list` heads it with for the one-peer form.
    #[test]
    fn the_pairing_line_names_the_remote_sync_takes() {
        let line = issuer_complete_line("my-vps");
        assert!(line.starts_with("run `sync` "), "{line}");
        assert!(line.contains("its remote is `my-vps`"), "{line}");
        assert!(line.contains("`sync my-vps` syncs with it alone"), "{line}");
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
