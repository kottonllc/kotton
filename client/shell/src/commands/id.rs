// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;

/// Identity commands, answered inside the runtime and — for `add-recovery` and
/// `rotate` — by `kotton id <sub> <name>` too, which runs this same command
/// through the bridge (terminal UX Pillar 4: one command, two doors). `id recover`
/// here is the piece for the identity the REPL runs as; `kotton id recover` at a
/// terminal claims the name, adds the vault, runs the same `Recover` and syncs, in
/// one command, because before it runs there is no identity for a REPL to run as.
///
/// `id use <name>` requests a switch; the REPL loop performs it after the command
/// returns (reconnecting the session and swapping to the new identity's history).
///
/// Every subcommand `kotton id` has is either answered here under the same words or
/// refused by a line naming the one-shot form — [`id_answer`] is that table, and
/// `kotton_cli::bridge`'s tests hold it against the clap tree so a subcommand added
/// there cannot go unaccounted for here.
pub struct IdCommand;

/// What the REPL's `id` does with a subcommand of `kotton id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdAnswer {
    /// Answered inside the shell, under the same words.
    Here,
    /// Refused inside the shell by a line naming `kotton id <sub> …`. `takes_name`
    /// says whether that form needs an identity, which the refusal fills in with the
    /// shell's own when none was typed.
    OneShot { takes_name: bool },
}

/// How the REPL answers `id <sub>` — `None` when `sub` is no subcommand of `kotton id`.
///
/// Aliases are listed beside their names (`add`, `recovery`, `set-pin`), because a
/// person types either.
///
/// **What is answered here, and why the rest is refused.** `rotate` and `recover`
/// are answered here, for this shell's identity: each asks for its secret at a
/// hidden prompt ([`ShellState::ask_hidden`], `crate::secret`), read from the
/// terminal with echo off and never through the line editor, which is the thing
/// that writes the history file. `kotton id rotate` runs the same verb through
/// the bridge, and `kotton id recover` asks at the same hidden prompt, so both
/// doors ask with one prompt.
///
/// `create`, `join` and `login` each *establish* a session — the REPL already runs
/// inside one, and before it exists the onboarding answers all three (`join` is the
/// shell's `device join` here, as the identity this shell runs as). `rm` removes an identity,
/// possibly the one this shell runs as. `set-passphrase`, `bind-device` and
/// `unlock` ask for the passphrase and are still the one-shot's: the hidden prompt
/// they would use is the same one, but what each does to the session this shell
/// runs on has not been worked through here, so the refusal names the form to run.
pub fn id_answer(sub: &str) -> Option<IdAnswer> {
    match sub {
        "list" | "use" | "lock" | "add-recovery" | "recovery" | "rotate" | "recover" => {
            Some(IdAnswer::Here)
        }
        "create" | "add" | "join" => Some(IdAnswer::OneShot { takes_name: false }),
        "rm" | "login" | "set-passphrase" | "set-pin" | "bind-device" | "unlock" => {
            Some(IdAnswer::OneShot { takes_name: true })
        }
        _ => None,
    }
}

const USAGE: &str = "usage: id list | id use <name> | id lock | id add-recovery | id rotate | id recover";

#[async_trait]
impl Command for IdCommand {
    fn help_text(&self) -> &'static str {
        "id — your identities: list, switch, lock your vault, set up recovery, rotate, recover\n\nUSAGE:\n  id list            list identities on this device (`*` marks current)\n  id use <name>      switch this session to another identity\n  id lock            close your vault now; your passphrase opens it again\n  id add-recovery    mint a 24-word recovery phrase for this identity, printed once\n                     with the line of each vault that keeps a copy\n  id rotate          retire this identity's key for a new one; asks for the phrase\n                     and your passphrase at hidden prompts\n  id recover         bring this identity back onto this device from a node that keeps\n                     your data; asks for the phrase and a new passphrase for this device\n                     at hidden prompts before it begins\n\nWhat you type at a hidden prompt is not shown and is not kept in the shell's history.\nThe other `kotton id` verbs (create, join, rm, login, set-passphrase, bind-device, unlock)\nare answered with the one-shot form to run outside the shell.\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let parts: Vec<&str> = args.iter().map(String::as_str).collect();
        match parts.as_slice() {
            [] | ["list"] => {
                let users = {
                    let mut client = state.client.lock().await;
                    client
                        .list_users()
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                };
                let rows: Vec<Vec<String>> = users
                    .iter()
                    .map(|u| {
                        let marker = if *u == state.user_id { "*" } else { "" };
                        vec![marker.to_string(), u.clone()]
                    })
                    .collect();
                Ok(CommandOutput::shapes(vec![Out::Table {
                    columns: vec![String::new(), "identity".to_string()],
                    rows,
                }]))
            }
            ["use", name] => {
                if *name == state.user_id {
                    return Ok(CommandOutput::shapes(vec![Out::Note(format!(
                        "already acting as '{name}'"
                    ))]));
                }
                // Only switch to an identity that exists on this device.
                let exists = {
                    let mut client = state.client.lock().await;
                    let users = client
                        .list_users()
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    users.iter().any(|u| u == name)
                };
                if !exists {
                    return Ok(CommandOutput::error(
                        1,
                        format!("no identity '{name}' on this device — run `id list` to see them"),
                    ));
                }
                // The choice is the device's, not this process's: write the file
                // the CLI reads, so `kotton id use` and this move the same thing
                // (`TASK-the-shell-does-not-initialise-the-active-identity`).
                if let Err(e) = kotton::active_identity::set(name) {
                    return Ok(CommandOutput::error(1, format!("could not record the active identity: {e}")));
                }
                // Signal the REPL loop to re-establish as this identity.
                state.pending_identity_switch = Some((*name).to_string());
                Ok(CommandOutput::shapes(vec![Out::Progress(format!(
                    "switching to '{name}'…"
                ))]))
            }
            ["lock"] => {
                // The vault, not the session: the shell stays signed in and its
                // next read of the person's own data refuses until they unlock.
                state
                    .client
                    .lock()
                    .await
                    .lock_custody(&state.user_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("id lock: {e}"))?;
                Ok(CommandOutput::shapes(vec![
                    Out::Confirm {
                        action: "locked the vault for".to_string(),
                        subject: state.user_id.clone(),
                    },
                    Out::Hint("it opens again with `kotton id unlock`; `whoami` shows the state".to_string()),
                ]))
            }
            ["add-recovery" | "recovery", rest @ ..] => add_recovery(rest, state).await,
            ["rotate", rest @ ..] => rotate(rest, state).await,
            ["recover", rest @ ..] => recover(rest, state).await,
            [sub, rest @ ..] => match id_answer(sub) {
                Some(IdAnswer::OneShot { takes_name }) => {
                    let mut form = format!("kotton id {sub}");
                    for a in rest {
                        form.push(' ');
                        form.push_str(a);
                    }
                    if takes_name && rest.is_empty() {
                        form.push(' ');
                        form.push_str(&state.user_id);
                    }
                    Ok(CommandOutput::error(
                        1,
                        format!("id {sub} is not answered inside the shell — run `{form}` outside it"),
                    ))
                }
                // A `Here` subcommand with the wrong arguments, or no subcommand at all.
                _ => Ok(CommandOutput::error(1, USAGE.to_string())),
            },
        }
    }
}

/// The identity an `id` verb acts for: this shell's, typed or not.
///
/// The session is the shell's, so the identity is too; naming another is refused
/// rather than sent, since the daemon would refuse it for a session that is not
/// that identity's and the person would learn less.
fn this_identity(verb: &str, rest: &[&str], state: &ShellState) -> Result<String, CommandOutput> {
    match rest {
        [] => Ok(state.user_id.clone()),
        [name] if *name == state.user_id => Ok(state.user_id.clone()),
        [name] => Err(CommandOutput::error(
            1,
            format!(
                "id {verb}: this shell acts as '{}' — `id use {name}` first, \
                 or run `kotton id {verb} {name}` outside it",
                state.user_id
            ),
        )),
        _ => Err(CommandOutput::error(1, format!("usage: id {verb} [<name>]"))),
    }
}

/// The refusal when a verb needs a secret and nobody is here to type it — a pipe,
/// a script. The secret is never read from stdin, so the line names where it is
/// asked for instead.
fn nobody_to_ask(verb: &str, what: &str, username: &str) -> CommandOutput {
    CommandOutput::error(
        1,
        format!(
            "id {verb} asks for {what} at a hidden prompt, and there is no terminal here to \
             ask at — run `kotton id {verb} {username}` at a terminal"
        ),
    )
}

/// `id add-recovery [<name>]`: mint a recovery phrase for this shell's identity,
/// commit it, and hand back the phrase and the line of each vault that keeps a copy.
async fn add_recovery(rest: &[&str], state: &mut ShellState) -> Result<CommandOutput> {
    let username = match this_identity("add-recovery", rest, state) {
        Ok(u) => u,
        Err(refused) => return Ok(refused),
    };
    let (phrase, copies) = state
        .client
        .lock()
        .await
        .add_recovery_phrase_with_copies(&username)
        .await
        .map_err(|e| anyhow::anyhow!("id add-recovery: {e}"))?;
    Ok(CommandOutput::shapes(recovery_card(&username, &phrase, &copies)))
}

/// `id rotate [<name>]`: retire this identity's key for a fresh one, by the
/// recovery phrase, and re-seal the vault around it with the passphrase. Both are
/// asked at hidden prompts.
///
/// **The session this shell runs on is not touched.** A session is the daemon's
/// token for an identity, not for a key, and the key is read from custody each time
/// it signs, so the next command here signs with the new key; the data key is not
/// rotated, so the vault stays open. Nothing is re-established, and there is no
/// line to say about this shell — only the other devices, whose shares of the
/// retired key the rotation clears.
async fn rotate(rest: &[&str], state: &mut ShellState) -> Result<CommandOutput> {
    let username = match this_identity("rotate", rest, state) {
        Ok(u) => u,
        Err(refused) => return Ok(refused),
    };
    let mut said = Vec::new();
    let Some(entered) = state.ask_hidden(&mut said, &crate::secret::recovery_phrase_question(&username))? else {
        return Ok(nobody_to_ask("rotate", "your recovery phrase", &username));
    };
    let phrase = crate::secret::require_phrase(&entered)?;
    // The vault on this device is re-sealed around the new key, and that takes
    // the passphrase that seals it.
    let Some(passphrase) = state.ask_hidden(&mut said, &format!("passphrase for '{username}' (hidden)"))? else {
        return Ok(nobody_to_ask("rotate", "your passphrase", &username));
    };
    let new_key = state
        .client
        .lock()
        .await
        .rotate_identity(&username, &phrase, Some(&passphrase))
        .await
        .map_err(|e| anyhow::anyhow!("id rotate: {e}"))?;
    Ok(CommandOutput::shapes(vec![
        Out::Confirm { action: "rotated the identity key for".to_string(), subject: username },
        Out::Record(vec![("new key".to_string(), new_key)]),
        Out::Note("Your identity is unchanged; the previous key no longer signs for it.".to_string()),
        Out::Hint("re-enrol your other devices so they rejoin under the new key".to_string()),
    ]))
}

/// `id recover [<name>]`: take this identity back onto this device from the
/// recovery phrase — fetched from a node this identity has as a peer, proved, and
/// rotated onto this device's key. The phrase is asked at a hidden prompt.
///
/// This is the piece the REPL runs, for the identity it runs as: on a new machine
/// the session is the one `kotton id login <name>` opened on the claim, and a
/// `peer add` has said where the data is. `kotton id recover` at a terminal is the
/// whole of it in one command — the claim, the vault its line names, this recovery
/// and the first sync (`kotton_cli`'s `id recover`).
///
/// **The session this shell runs on comes back with the keys.** It was opened on
/// the claim, which holds no data key; the daemon puts the keys back and tells
/// the connection that sent `Recover` it now holds one, as an unlock does, and
/// reopens the identity's store under them. This shell sends every command on that
/// connection, so the next one reads the person's data with nothing re-established.
///
/// **The passphrase is chosen before the recovery begins.** A recovery rotates the
/// identity onto this device's key, and on a device the person used before the copy
/// sealed under their old passphrase seals the key it replaces. So the phrase and
/// then a passphrase for this device are read here, both at the hidden prompt, the
/// passphrase offered and confirmed as every new one is
/// ([`crate::secret::choose_new_passphrase`]), before anything is sent; the daemon
/// seals the recovered roots under it and sets the lock policy to it in the same
/// act, replacing any old copy. A recovered device is never held without a sealed
/// copy, and the old passphrase opens nothing. With nobody to ask, or a passphrase
/// refused, nothing is sent and nothing changes.
async fn recover(rest: &[&str], state: &mut ShellState) -> Result<CommandOutput> {
    use crate::secret::{choose_new_passphrase, NewPassphrase};

    let username = match this_identity("recover", rest, state) {
        Ok(u) => u,
        Err(refused) => return Ok(refused),
    };
    let mut said = Vec::new();
    let Some(entered) = state.ask_hidden(&mut said, &crate::secret::recovery_phrase_question(&username))? else {
        return Ok(nobody_to_ask("recover", "your recovery phrase", &username));
    };
    let phrase = crate::secret::require_phrase(&entered)?;
    said.push(Out::Note(
        "Choose the passphrase that unlocks your keys on this device. It replaces any \
         passphrase this device knew for them."
            .to_string(),
    ));
    let question = format!("passphrase for '{username}' on this device (hidden, Enter to accept the suggestion)");
    let passphrase = match choose_new_passphrase(&mut state.asking, &mut said, &question)? {
        NewPassphrase::Chosen(passphrase) => passphrase,
        NewPassphrase::NobodyToAsk => {
            return Ok(nobody_to_ask("recover", "a passphrase for this device", &username))
        }
        NewPassphrase::Refused(why) => {
            return Ok(CommandOutput::error(1, format!("id recover: {why} — nothing was changed")))
        }
    };
    let recovered = state
        .client
        .lock()
        .await
        .recover(&username, &phrase, &passphrase)
        .await
        .map_err(|e| anyhow::anyhow!("id recover: {e}"))?;
    let mut said = vec![
        Out::Confirm { action: "recovered onto this device".to_string(), subject: username },
        Out::Record(vec![
            ("identity".to_string(), recovered.did),
            ("this device signs for it".to_string(), recovered.new_key_hex),
        ]),
    ];
    said.push(Out::Note(if recovered.sealed_copy_removed {
        "The copy sealed under your old passphrase is replaced.".to_string()
    } else {
        "The recovered key is sealed here under the passphrase you chose.".to_string()
    }));
    said.push(Out::Hint("`sync` from your node brings your files and records back".to_string()));
    Ok(CommandOutput::shapes(said))
}

/// The phrase, and beside it each vault's line, as shapes: the card.
///
/// Printed once and nowhere kept. The daemon does not store the phrase, and this is
/// the only moment it exists outside the person's hands — which is why it gets a
/// screen of its own rather than a line appended to some other command's output.
///
/// **Shapes, never `stdout`.** The phrase is an [`Out::Reveal`]: rendered verbatim,
/// and carried apart from `stdout`, which is the channel a pipe consumes and `>`
/// writes into a file in the person's store. `id add-recovery > notes` must not
/// leave the only copy of the key in a file that syncs.
///
/// **Recovery takes two things, and the card is both.** The phrase is the
/// *authority*; the line is the *locator*. A new machine has no peers at all, and
/// `kotton id recover` fetches the identity and the sealed keys *from a node*, so it
/// asks for the words and for the line of a vault that keeps a copy, and dials the
/// vault the line names. The line is the vault's own
/// (`kotton-instance:vault:<key>@<address>`, [`recovery_line`]): its key, which the
/// recovering machine holds the vault to, and the address it is dialled at. It is
/// printed for each node the sealed copy was delivered to, because only a node that
/// holds the copy can serve a recovery; a vault this desktop operates and keeps
/// nothing at would be a line that answers nothing.
///
/// **The address matters more than it looks.** A new machine reaches the vault only
/// by dialling it directly. Every fallback — hole punch, TURN, the relayed circuit —
/// names the node by a per-pair handle derived from the dialer's own device key, and
/// a new machine has a new key, so no handle it can derive is one the node holds
/// (RFC-0083 R4, working as designed). So the card says when a line names a private
/// address, rather than printing a line that will not answer.
///
/// A line is not a secret — it confers nothing and composes into nothing, since no
/// directory is keyed by the identity — and withholding it does not protect the
/// person, it strands them.
pub fn recovery_card(
    username: &str,
    phrase: &str,
    copies: &[kotton_wire::peer::PairedNode],
) -> Vec<Out> {
    let mut out = vec![Out::Note(format!("✓ Recovery is set up for '{username}'."))];
    if copies.is_empty() {
        out.push(Out::Note("Write these 24 words down. They are the only copy.".to_string()));
        out.push(Out::Reveal(phrase.to_string()));
        out.push(Out::Warn {
            what: "⚠ No node has a copy of your sealed keys.".to_string(),
            consequence: "a new device would have nowhere to recover from".to_string(),
        });
        out.push(Out::Note(
            "The phrase proves who you are. On a device that has never held this identity \
             it has nothing to prove it *to*: `id recover` asks a node for your key history \
             and the copy sealed under this phrase, and there is no node to ask. Rent or run \
             one, admit it (`device admit <code>`), then run this command again — \
             setting the phrase again re-delivers."
                .to_string(),
        ));
        return out;
    }
    out.push(Out::Note(
        "Write both on paper: the 24 words, and the line under them. They are shown this once.".to_string(),
    ));
    out.push(Out::Reveal(phrase.to_string()));
    for node in copies {
        match recovery_line(node) {
            Some((line, addr)) => {
                out.push(Out::Reveal(line));
                if !is_dialable_from_a_wiped_device(&addr) {
                    out.push(Out::Warn {
                        what: format!("⚠ {addr} is a private address."),
                        consequence: "a machine on another network cannot reach this vault to recover from it"
                            .to_string(),
                    });
                }
            }
            None => out.push(Out::Warn {
                what: format!("⚠ '{}' keeps a copy, and no address was recorded for it.", node.id),
                consequence: "it has no line a new machine can dial".to_string(),
            }),
        }
    }
    out.push(Out::Note(format!(
        "On any machine, `kotton id recover` asks for your name, '{username}', the words and the line."
    )));
    out
}

/// The vault's line for a node that keeps a copy, and the address in it:
/// `kotton-instance:vault:<its key>@<its address>`, printed by the one printer
/// ([`kotton_wire::line::InstanceLine::to_text`]) and read back by the one parser
/// `enrol` reads lines with. The key is the one the node presents and was paired
/// under, the address the first one recorded for it. `None` when none was.
pub fn recovery_line(node: &kotton_wire::peer::PairedNode) -> Option<(String, std::net::SocketAddr)> {
    let addr = *node.addresses.first()?;
    let line = kotton_wire::line::InstanceLine {
        kind: kotton_wire::ipc::OperatedService::Vault,
        hint: addr.to_string(),
        key: node.public_key,
    };
    Some((line.to_text(), addr))
}

/// Whether an address is one a device somewhere else could dial.
///
/// Deliberately crude and deliberately pessimistic: loopback, private ranges,
/// link-local and unspecified are *not* reachable, everything else is assumed to
/// be. Being wrong the optimistic way prints a warning nobody needed; being wrong
/// the other way is silence at the moment a person is deciding whether their
/// recovery plan is real.
fn is_dialable_from_a_wiped_device(addr: &std::net::SocketAddr) -> bool {
    use std::net::IpAddr;
    match addr.ip() {
        IpAddr::V4(v4) => {
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            // `is_unique_local`/`is_unicast_link_local` are unstable, so the two
            // prefixes are matched directly: fc00::/7 and fe80::/10.
            let o = v6.octets();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (o[0] & 0xfe) == 0xfc
                || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reveals(out: &[Out]) -> Vec<&str> {
        out.iter()
            .filter_map(|o| match o {
                Out::Reveal(r) => Some(r.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_card_carries_the_phrase_once_and_says_when_no_node_holds_a_copy() {
        let phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident \
                      account accuse achieve acid acoustic acquire across act action actor actress actual";
        let out = recovery_card("alice", phrase, &[]);
        assert_eq!(reveals(&out), vec![phrase]);
        assert!(out.iter().any(|o| matches!(o, Out::Warn { what, .. } if what.contains("No node"))));
    }

    fn node(id: &str, addr: &str) -> kotton_wire::peer::PairedNode {
        kotton_wire::peer::PairedNode {
            id: id.to_string(),
            device_did: kotton_wire::did::Did::new("key", "z6MktGLn5v9bCrdxWgRojExample"),
            public_key: [7; 32],
            paired_at: 0,
            addresses: vec![addr.parse().expect("a socket address")],
            relay_url: None,
            posture: None,
        }
    }

    /// The text of every shape on the card, trimmed.
    fn lines(out: &[Out]) -> Vec<String> {
        out.iter()
            .filter_map(|o| match o {
                Out::Note(t) | Out::Hint(t) | Out::Reveal(t) => Some(t.trim().to_string()),
                Out::Warn { what, .. } => Some(what.trim().to_string()),
                _ => None,
            })
            .collect()
    }

    /// **The card is the words and one line per vault, and no command.** A new
    /// machine runs `kotton id recover`, which asks for the words and the line; so
    /// the card carries the phrase once, then each node's line, and spells none of
    /// the pieces the one command runs. Every Reveal but the phrase is a line the
    /// one parser reads as a vault's.
    #[test]
    fn the_card_is_the_words_and_one_line_per_vault_and_no_command() {
        let out = recovery_card(
            "sam",
            "the phrase",
            &[node("blind-vps", "203.0.113.9:7710"), node("home", "192.168.1.4:7710")],
        );
        let card = lines(&out);
        let shown = reveals(&out);
        assert_eq!(shown[0], "the phrase", "the phrase comes first.\n{}", card.join("\n"));
        assert_eq!(shown.iter().filter(|r| **r == "the phrase").count(), 1, "the phrase is printed once");
        let vaults: Vec<&str> = shown[1..].to_vec();
        assert_eq!(vaults.len(), 2, "one line per node that keeps a copy.\n{}", card.join("\n"));
        for line in &vaults {
            let read = kotton_wire::line::InstanceLine::parse(line).unwrap_or_else(|e| panic!("`{line}`: {e}"));
            assert_eq!(read.kind, kotton_wire::ipc::OperatedService::Vault, "`{line}`");
        }
        assert!(
            !card.iter().any(|l| l.starts_with("kotton ") || l.contains("peer add") || l.contains("id login")),
            "the card spells a piece the one command runs.\n{}",
            card.join("\n")
        );
        assert!(card.iter().any(|l| l.contains("Write both on paper")), "{}", card.join("\n"));
        assert!(card.iter().any(|l| l.contains("`kotton id recover`") && l.contains("'sam'")), "{}", card.join("\n"));
        // The private one is said, the public one is not.
        assert!(card.iter().any(|l| l.contains("192.168.1.4:7710 is a private address")), "{}", card.join("\n"));
        assert!(!card.iter().any(|l| l.contains("203.0.113.9:7710 is a private")), "{}", card.join("\n"));
    }

    /// **A vault's line reads back as the node it was printed from.** The key is the
    /// key the node presents and was paired under, the address the one recorded for
    /// it: what `kotton id recover` dials, read by the parser `enrol` reads lines with.
    #[test]
    fn a_vaults_line_reads_back_as_its_key_and_address() {
        let n = node("blind-vps", "203.0.113.9:7710");
        let (line, addr) = recovery_line(&n).expect("a node with an address has a line");
        assert_eq!(line, format!("kotton-instance:vault:{}@203.0.113.9:7710", "07".repeat(32)));
        let read = kotton_wire::line::InstanceLine::parse(&line).expect("the line parses");
        assert_eq!(read.key, n.public_key);
        assert_eq!(read.hint.parse::<std::net::SocketAddr>().expect("an address"), addr);

        let nowhere = kotton_wire::peer::PairedNode { addresses: vec![], ..n };
        assert_eq!(recovery_line(&nowhere), None, "a node with no address has no line");
        let card = lines(&recovery_card("sam", "the phrase", &[nowhere]));
        assert!(card.iter().any(|l| l.contains("no address was recorded")), "{}", card.join("\n"));
    }

    #[test]
    fn a_private_address_is_not_dialable_and_a_public_one_is() {
        assert!(!is_dialable_from_a_wiped_device(&"192.168.1.4:7710".parse().unwrap()));
        assert!(!is_dialable_from_a_wiped_device(&"[fe80::1]:7710".parse().unwrap()));
        assert!(is_dialable_from_a_wiped_device(&"203.0.113.9:7710".parse().unwrap()));
    }

    /// `TASK-the-shells-id-usage-does-not-say-where-add-recovery-went`: the usage line
    /// the REPL answers with names the verb, and the refusals name the one-shot form.
    #[test]
    fn the_usage_line_names_add_recovery_and_every_refusal_is_a_one_shot() {
        assert!(USAGE.contains("id add-recovery"), "{USAGE}");
        assert_eq!(id_answer("add-recovery"), Some(IdAnswer::Here));
        assert_eq!(id_answer("recovery"), Some(IdAnswer::Here));
        assert_eq!(id_answer("login"), Some(IdAnswer::OneShot { takes_name: true }));
        assert_eq!(id_answer("recover"), Some(IdAnswer::Here));
        assert_eq!(id_answer("rotate"), Some(IdAnswer::Here));
        assert!(USAGE.contains("id rotate") && USAGE.contains("id recover"), "{USAGE}");
        assert_eq!(id_answer("frobnicate"), None);
    }
}
