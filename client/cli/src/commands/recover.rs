// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton id recover`: this machine yours again, from the words and the vault's line.
//!
//! What `kotton id add-recovery` printed is the twenty-four words and, under them, the
//! line of each vault that keeps a copy (`kotton_shell::commands::recovery_card`). This
//! asks for the name, unless it was given, then the card as the REPL's `id recover`
//! asks for it (`kotton_shell::recover::ask`): the words at the hidden prompt, one
//! line, and a passphrase for this machine, all before it sends anything. Then, on one
//! connection:
//!
//! 1. **Claim the name** (`LoginWithRecoveryKey`). On a machine that holds the name the
//!    phrase is proved against the name's log there, and a phrase that does not prove is
//!    refused with nothing opened or written. On a machine that holds nothing under it,
//!    the name is claimed locked: a name with no key.
//! 2. **Recover** (`Recover`, with the line), the one request both doors send
//!    (`kotton_shell::recover::send`). The daemon does the rest of what recovering is,
//!    in that one request (`kotton_device::users::recover`): it adds the vault the line
//!    names as the node to dial, unless a node with its key is paired for the name
//!    already; fetches the log and the sealed copy, proves the phrase, rotates onto
//!    this machine's key, seals under the passphrase and is admitted at the vault;
//!    and then, the phrase proved, **records the vault as the person's drive**
//!    (`kotton_peer::daemon::drives`), the record enrolling the vault writes. On a
//!    refusal it takes back the node it added. Neither door adds the vault or says it
//!    is a drive: that is where the proof is.
//! 3. **Make the name the identity this machine acts as.**
//! 4. **Sync** this machine's drives, as `kotton sync` does.
//!
//! **A recovery that is refused takes back what this command wrote.** On a machine that
//! held nothing under the name, the claim is written before the vault is asked,
//! because `Recover` runs for a claimed name on the session the claim opened. The vault
//! answers words that prove nothing by refusing the dial, and everything `Recover` can
//! fail on comes before it presents the rotation to the vault, so a refused recovery
//! has changed nothing anywhere but here; the daemon has removed the node it added,
//! and this command then removes the claim it made, and the machine holds nothing of
//! the name, as before. The claim is taken back only once the node is gone: `kotton
//! peer --user <name> revoke` runs on the claim's session, and removing a claim leaves
//! the name's node rows, so when the daemon says it could not remove the node, the
//! claim is kept and the refusal names the revoke and then `kotton id rm <name>`, in
//! the order they run.
//!
//! On a machine that held the name, the claim is the person's own and is never taken
//! back.
//!
//! **One thing a refusal does not put back: a vault paired here at another address.**
//! When the name already pairs a node with the line's key, at an address other than
//! the line's, the daemon re-addresses it as `peer add` does: the row keeps its posture
//! and relay route, and its addresses become the line's one and its pairing time now.
//! A refusal leaves it so. The line is the address the person wrote down for the vault,
//! so the node is left at the address the person says the vault is at, and a refusal
//! of the words says nothing against it. A refusal leaves no drive recorded that was
//! not recorded before.
//!
//! The name is asked for rather than read from the vault: the vault keeps a copy under
//! the name and serves it only to a dial that names it and proves the phrase, so there
//! is no answer to ask it for before the name is known.

use std::io;

use kotton::KottonClient;
use kotton_shell::out::Out;
use kotton_shell::recover::{Card, NotAsked};
use kotton_shell::Asking;
use kotton_wire::line::InstanceLine;

/// Everything `kotton id recover` asks for, all of it before anything is sent: the
/// name, and the card.
#[derive(Debug)]
pub(crate) struct Answers {
    pub(crate) name: String,
    pub(crate) card: Card,
}

/// The question the name is asked with.
const NAME_QUESTION: &str = "your name — the one recovery was set up for";

/// The refusal when there is nobody to answer: the words are read only at a terminal.
fn nobody_to_ask() -> String {
    "id recover asks for your words at a hidden prompt, and there is no terminal here to ask at — \
     run `kotton id recover` at a terminal; nothing was changed"
        .to_string()
}

/// Ask for everything, in order: the name unless `given`, then the card
/// ([`kotton_shell::recover::ask`]). Each is asked once. `Ok(Err(why))` is a refusal
/// before anything was sent, one sentence saying why.
pub(crate) fn ask(given: Option<&str>, asking: &mut Asking, said: &mut Vec<Out>) -> io::Result<Result<Answers, String>> {
    let name = match given {
        Some(name) => name.trim().to_string(),
        None => match asking.line_after(said, NAME_QUESTION)? {
            Some(typed) => typed.trim().to_string(),
            None => return Ok(Err(nobody_to_ask())),
        },
    };
    if name.is_empty() {
        return Ok(Err("a name is required — the one recovery was set up for; nothing was changed".into()));
    }
    Ok(match kotton_shell::recover::ask(&name, asking, said)? {
        Ok(card) => Ok(Answers { name, card }),
        Err(NotAsked::NobodyToAsk(_)) => Err(nobody_to_ask()),
        Err(NotAsked::Refused(why)) => Err(why),
    })
}

/// `kotton id recover [<name>]`.
pub(crate) async fn run(given: Option<&str>) -> io::Result<()> {
    let mut asking = Asking::here();
    let mut said = Vec::new();
    let asked = ask(given, &mut asking, &mut said)?;
    kotton_shell::out::render(&std::mem::take(&mut said), None);
    let answers = asked.map_err(|why| io::Error::new(io::ErrorKind::InvalidInput, format!("id recover: {why}")))?;

    let mut client = KottonClient::connect().await?;
    let pulled = recover_here(&mut client, &answers).await?;
    println!(
        "✓ '{}' is yours on this machine again: {pulled} thing(s) came back from the vault, and your \
         passphrase unlocks them here.",
        answers.name
    );
    Ok(())
}

/// The pieces, in order, on one connection; the number of things the sync brought
/// back. See the module doc.
async fn recover_here(client: &mut KottonClient, a: &Answers) -> io::Result<u32> {
    let name = a.name.as_str();
    let refused = |e: String| io::Error::other(format!("id recover: {e}"));
    let held_before = client.list_users().await?.iter().any(|u| u == name);
    let (vault_key, _) = InstanceLine::vault(&a.card.line).map_err(|why| refused(format!("{why}; nothing was changed")))?;

    // 1. Claim the name. A phrase that does not prove against a log this machine holds
    // is refused here, with nothing opened or written.
    client
        .login_with_recovery_key(&a.card.phrase, Some(name.to_string()), None)
        .await
        .map_err(|e| refused(e.to_string()))?;
    let paired_before = client.list_nodes(name).await?.iter().any(|n| n.public_key == vault_key);

    // 2. Recover, with the line: the vault added, the proof, the drive recorded after
    // it, or the node taken back — all in the daemon, as for the REPL's door.
    let recovered = match kotton_shell::recover::send(client, name, &a.card).await {
        Ok(recovered) => recovered,
        Err(e) => {
            return Err(refused(take_back(client, name, &vault_key, paired_before, !held_before, e.to_string()).await))
        }
    };

    // 3. The identity this machine acts as.
    kotton::active_identity::set(name)?;

    // 4. Your things, from your drives, as `kotton sync` brings them: a device
    // syncs to its person's drives and to nothing else, and the vault just
    // recorded is one.
    let mut pulled = 0;
    let mut unsynced = Vec::new();
    match client.sync_drives(name).await {
        Ok((job, _drives)) => match client.sync_await(name, job, 300).await {
            Ok(outcome) => pulled += outcome.files,
            Err(e) => unsynced.push(e.to_string()),
        },
        Err(e) => unsynced.push(e.to_string()),
    }
    if let Some(why) = recovered.drive_not_recorded {
        return Err(io::Error::other(format!(
            "'{name}' is yours on this machine again, but {why}, so this machine does not yet treat it \
             as one; do not recover again{}",
            if unsynced.is_empty() { String::new() } else { format!(", and the sync did not finish ({})", unsynced.join("; ")) }
        )));
    }
    if !unsynced.is_empty() {
        return Err(io::Error::other(format!(
            "'{name}' is yours on this machine again, and the sync did not finish ({}) — `kotton sync` \
             finishes it; do not recover again",
            unsynced.join("; ")
        )));
    }
    Ok(pulled)
}

/// Take back what this command wrote when the recovery is refused, and say so in the
/// refusal: when the machine held nothing under the name before, the claim, with the
/// session it cached. The daemon took back the node it added for the line, and says
/// in `why` when it could not; a node under the line's key that was not paired
/// before the recovery and is paired after is that node, and the claim is kept so
/// the revoke `why` names can run.
async fn take_back(
    client: &mut KottonClient,
    name: &str,
    vault_key: &[u8; 32],
    paired_before: bool,
    claimed: bool,
    why: String,
) -> String {
    let mut left = Vec::new();
    if claimed {
        let node_left = !paired_before
            && client.list_nodes(name).await.map_or(true, |nodes| nodes.iter().any(|n| n.public_key == *vault_key));
        if node_left {
            left.push(Left::ClaimKept);
        } else {
            match client.logout_user(name).await {
                Ok(()) => kotton::session_cache::clear(name),
                Err(e) => left.push(Left::Claim { why: e.to_string() }),
            }
        }
    }
    refusal(name, claimed, &left, why)
}

/// Something a refused recovery wrote and did not take back.
#[derive(Debug)]
enum Left {
    /// The claim this command made, which `logout_user` refused to remove.
    Claim { why: String },
    /// The claim this command made, kept on purpose because the node the daemon added
    /// for the line is left: the revoke that removes it, which the daemon's refusal
    /// names, runs on the claim's session.
    ClaimKept,
}

/// The refusal's one sentence. With nothing left, a machine that held nothing of the
/// name says so; a machine that held it says only what refused. Each thing left names
/// the line that removes it, after the line `why` names for a node left: a node is a
/// `peer revoke`, which needs the claim, and `id rm` is named only for a claim this
/// command made, never on a machine that held the name, where it would remove an
/// identity this command did not claim.
fn refusal(name: &str, claimed: bool, left: &[Left], why: String) -> String {
    if left.is_empty() {
        return if claimed {
            format!(
                "the vault did not give '{name}' back for these words ({why}), and nothing of '{name}' is left \
                 on this machine — check the name, the words and the line against what you wrote down"
            )
        } else {
            why
        };
    }
    let remedies: Vec<String> = left
        .iter()
        .map(|l| match l {
            Left::Claim { why } => format!("the name '{name}' ({why}) — `kotton id rm {name}` removes what it claimed"),
            Left::ClaimKept => format!("the name '{name}', kept so that line can run — then `kotton id rm {name}` removes what it claimed"),
        })
        .collect();
    format!("{why}; and this machine still holds {}", remedies.join(", and "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_wire::ipc::OperatedService;

    /// A refusal names, for each thing it did not take back, the line that removes it,
    /// after the revoke the daemon's refusal names for a node it could not remove. On a
    /// machine where this command made the claim, the claim is kept so that revoke can
    /// run, and `id rm` is named after it. `id rm` alone is named only when the claim
    /// itself could not be taken back, and never on a machine that held the name.
    #[test]
    fn a_refusal_names_the_line_that_removes_what_is_left_and_never_more() {
        let daemon_said = "refused; and the node 'vault' this recovery added for the line is still paired here (busy) \
                           — `kotton peer --user alice revoke vault` removes it";
        let held = refusal("alice", false, &[], daemon_said.into());
        assert_eq!(held, daemon_said);
        assert!(!held.contains("id rm"), "{held}");

        let fresh = refusal("alice", true, &[Left::ClaimKept], daemon_said.into());
        let revoke = fresh.find("`kotton peer --user alice revoke vault`").expect(&fresh);
        let rm = fresh.find("`kotton id rm alice`").expect(&fresh);
        assert!(revoke < rm, "{fresh}");

        let claim_only = refusal("alice", true, &[Left::Claim { why: "busy".into() }], "refused".into());
        assert!(claim_only.contains("`kotton id rm alice`") && !claim_only.contains("revoke"), "{claim_only}");

        assert_eq!(refusal("alice", false, &[], "refused".into()), "refused");
        assert!(refusal("alice", true, &[], "refused".into()).contains("nothing of 'alice' is left"));
    }

    /// Twenty-four words of the list, with the checksum right: the phrase every test
    /// vector of BIP-39 starts from.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon art";

    fn key() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()
    }

    fn line() -> String {
        InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: key() }.to_text()
    }

    fn asked(name: Option<&str>, answers: &[&str]) -> (Result<Answers, String>, usize) {
        let mut asking = Asking::Given(answers.iter().map(|a| a.to_string()).collect());
        let mut said = Vec::new();
        let got = ask(name, &mut asking, &mut said).expect("asking does not fail on given answers");
        let left = match asking {
            Asking::Given(left) => left.len(),
            _ => unreachable!("the tests answer in advance"),
        };
        (got, left)
    }

    /// **The name, then the card, each asked once.** Four answers, Enter taking the
    /// suggested passphrase, make one recovery of the vault the line names; a name
    /// given on the command line is not asked for.
    #[test]
    fn recover_asks_the_name_then_the_card_once_each() {
        let (got, left) = asked(None, &["sam\n", PHRASE, &format!("{}\n", line()), ""]);
        let a = got.expect("the four answers are a recovery");
        assert_eq!(left, 0, "an answer was left unasked");
        assert_eq!((a.name.as_str(), a.card.phrase.as_str(), a.card.line.as_str()), ("sam", PHRASE, line().as_str()));
        assert!(!format!("{a:?}").contains("abandon"), "the words print through Debug");

        let (got, left) = asked(Some("sam"), &[PHRASE, &line(), ""]);
        assert_eq!(got.expect("three answers with the name given").name, "sam");
        assert_eq!(left, 0);
    }

    /// With nobody at a terminal — a pipe, a script — nothing is asked and nothing sent,
    /// at whichever question nobody answers, and the refusal names the terminal form.
    /// An empty name is refused before the words.
    #[test]
    fn with_nobody_to_answer_recover_refuses_and_sends_nothing() {
        let mut said = Vec::new();
        let why = ask(None, &mut Asking::Nobody, &mut said).unwrap().expect_err("nobody answered");
        assert!(why.contains("at a terminal") && why.contains("nothing was changed"), "{why}");
        for answers in [&[][..], &["sam"][..], &["sam", PHRASE][..], &["sam", PHRASE, &line()][..]] {
            let (got, _) = asked(None, answers);
            assert!(got.expect_err("an answer was missing").contains("at a terminal"), "{answers:?}");
        }
        let (got, _) = asked(None, &["  \n"]);
        assert!(got.expect_err("an empty name").contains("a name is required"));
        let (got, _) = asked(Some("sam"), &["not the words", &line(), ""]);
        assert!(got.expect_err("words that are no phrase").contains("twenty-four words"));
    }

    /// **The card's line reads back as the node it was printed from.** The shell prints
    /// the line from the node a copy was delivered to; the daemon reads it back as the
    /// vault to dial, and the two agree on the key and the address.
    #[test]
    fn the_cards_line_reads_back_as_the_node_it_was_printed_from() {
        let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key()).unwrap();
        let node = kotton_wire::peer::PairedNode {
            id: "blind-vps".to_string(),
            device_did: did,
            public_key: key(),
            paired_at: 0,
            addresses: vec!["203.0.113.9:7710".parse().unwrap()],
            relay_url: None,
            posture: None,
        };
        let card = kotton_shell::commands::recovery_card("sam", PHRASE, std::slice::from_ref(&node));
        let lines: Vec<&str> = card
            .iter()
            .filter_map(|o| match o {
                Out::Reveal(r) if r.as_str() != PHRASE => Some(r.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(lines.len(), 1, "one line for the one node: {card:?}");
        assert_eq!(InstanceLine::vault(lines[0]).expect("the card's line reads"), (node.public_key, node.addresses[0]));
    }
}
