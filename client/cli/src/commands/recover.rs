// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton id recover`: this machine yours again, from the words and the vault's line.
//!
//! What `kotton id add-recovery` printed is the twenty-four words and, under them, the
//! line of each vault that keeps a copy (`kotton_shell::commands::recovery_card`). This
//! asks for the name, unless it was given, then the words at the hidden prompt, then
//! one line, then a passphrase for this machine, all before it sends anything; then it
//! runs the pieces in their order on one connection:
//!
//! 1. **Claim the name** (`LoginWithRecoveryKey`). On a machine that holds the name the
//!    phrase is proved against the name's log there, and a phrase that does not prove is
//!    refused with nothing opened or written. On a machine that holds nothing under it,
//!    the name is claimed locked: a name with no key.
//! 2. **Add the vault the line names** as the node to dial (`PeerAdd`), unless a node
//!    with its key is paired for the name already.
//! 3. **Recover** (`Recover`): fetch the log and the sealed copy from the vault, prove
//!    the phrase against the log, rotate onto this machine's key, seal under the
//!    passphrase, and be admitted at the vault.
//! 4. **Make the name the identity this machine acts as.**
//! 5. **Sync** with each node the name has here, as `kotton sync` does.
//!
//! **A recovery that is refused takes back what this command wrote.** On a machine that
//! held nothing under the name, the claim and the node are written before the vault is
//! asked, because `Recover` runs for a claimed name on the session the claim opened. The
//! vault answers words that prove nothing by refusing the dial, and everything `Recover`
//! can fail on comes before it presents the rotation to the vault, so a refused recovery
//! has changed nothing anywhere but here. This command then removes the node it added
//! and the claim it made, and the machine holds nothing of the name, as before. The
//! claim is taken back only once the node is gone: `kotton peer --user <name> revoke`
//! runs on the claim's session, and removing a claim leaves the name's node rows, so
//! when the node cannot be removed the claim is kept and the refusal names the revoke
//! and then `kotton id rm <name>`, in the order they run.
//!
//! On a machine that held the name, the claim is the person's own and is never taken
//! back; a node this command added for the line's key is, and nothing else was written
//! but the one thing below.
//!
//! **One thing a refusal does not put back: a vault paired here at another address.**
//! When the name already pairs a node with the line's key, at an address other than
//! the line's, step 2 re-addresses it as `peer add` does: the row keeps its posture
//! and relay route, and its addresses become the line's one and its pairing time now.
//! A refusal leaves it so, though the old addresses could be written back. The line
//! is the address the person wrote down for the vault, so the node is left at the
//! address the person says the vault is at, and a refusal of the words says nothing
//! against it.
//!
//! The name is asked for rather than read from the vault: the vault keeps a copy under
//! the name and serves it only to a dial that names it and proves the phrase, so there
//! is no answer to ask it for before the name is known.

use std::io;
use std::net::SocketAddr;

use kotton::KottonClient;
use kotton_shell::out::Out;
use kotton_shell::secret::{choose_new_passphrase, recovery_phrase_question, require_phrase, NewPassphrase};
use kotton_shell::Asking;
use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;

/// The vault a line names, as this machine dials it: the key it is held to, the
/// `did:key` spelling of that key a paired node is recorded under, and its address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Vault {
    pub(crate) key: [u8; 32],
    pub(crate) did: String,
    pub(crate) addr: SocketAddr,
}

/// Read a vault's line, `kotton-instance:vault:<key>@<address>`, with the one parser
/// `enrol` reads lines with ([`InstanceLine::parse`]), as the vault this machine dials.
///
/// Refused, with what is wrong, for anything that is not a line, a relay's line, and a
/// line whose address is not one this machine can dial.
pub(crate) fn vault_of_line(text: &str) -> Result<Vault, String> {
    let line = InstanceLine::parse(text)?;
    if line.kind != OperatedService::Vault {
        return Err("this is a relay's line; recovery asks for the line of the vault that keeps your things".into());
    }
    let addr: SocketAddr = line.hint.parse().map_err(|_| {
        if line.hint.is_empty() {
            "the line names no address to reach the vault at".to_string()
        } else {
            format!("the line's address, `{}`, is not one this machine can dial: it reads `<ip>:<port>`", line.hint)
        }
    })?;
    let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&line.key)
        .map_err(|e| format!("the line's key is not a vault's key: {e}"))?
        .to_string();
    Ok(Vault { key: line.key, did, addr })
}

/// Everything `kotton id recover` asks for, all of it before anything is sent.
pub(crate) struct Answers {
    pub(crate) name: String,
    pub(crate) phrase: String,
    pub(crate) vault: Vault,
    pub(crate) passphrase: String,
}

/// The name and the vault, and never the words or the passphrase: a debug print of
/// what was asked is somewhere a secret must not land.
impl std::fmt::Debug for Answers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answers")
            .field("name", &self.name)
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

/// The question the name is asked with.
const NAME_QUESTION: &str = "your name — the one recovery was set up for";
/// The question the line is asked with.
const LINE_QUESTION: &str = "the line under the words (kotton-instance:vault:…)";

/// The refusal when there is nobody to answer: the words are read only at a terminal.
fn nobody_to_ask() -> String {
    "id recover asks for your words at a hidden prompt, and there is no terminal here to ask at — \
     run `kotton id recover` at a terminal; nothing was changed"
        .to_string()
}

/// Ask for everything, in order: the name unless `given`, the words at the hidden
/// prompt, the vault's line, and a passphrase for this machine, offered and confirmed
/// as every new one is. Each is asked once. `Ok(Err(why))` is a refusal before anything
/// was sent, one sentence saying why.
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

    let Some(entered) = asking.hidden_after(said, &recovery_phrase_question(&name))? else {
        return Ok(Err(nobody_to_ask()));
    };
    let phrase = match require_phrase(&entered) {
        Ok(phrase) => phrase,
        Err(e) => return Ok(Err(format!("{e}; nothing was changed"))),
    };
    if let Err(e) = kotton_crypto::try_mnemonic_to_seed32(&phrase) {
        return Ok(Err(format!(
            "these are not the twenty-four words of a recovery phrase ({e}) — check them against what \
             you wrote down; nothing was changed"
        )));
    }

    let Some(typed) = asking.line_after(said, LINE_QUESTION)? else {
        return Ok(Err(nobody_to_ask()));
    };
    let vault = match vault_of_line(&typed) {
        Ok(vault) => vault,
        Err(why) => return Ok(Err(format!("{why}; nothing was changed"))),
    };

    said.push(Out::Note(
        "Choose the passphrase that unlocks your keys on this machine. It replaces any passphrase \
         this machine knew for them."
            .to_string(),
    ));
    let question = format!("passphrase for '{name}' on this machine (hidden, Enter to accept the suggestion)");
    let passphrase = match choose_new_passphrase(asking, said, &question)? {
        NewPassphrase::Chosen(passphrase) => passphrase,
        NewPassphrase::NobodyToAsk => return Ok(Err(nobody_to_ask())),
        NewPassphrase::Refused(why) => return Ok(Err(format!("{why}; nothing was changed"))),
    };
    Ok(Ok(Answers { name, phrase, vault, passphrase }))
}

/// The label a node the line names is added under: `vault`, or, when the name already
/// pairs a node under that label, `vault-` and the first eight hex of the key.
fn label_for(taken: &[kotton_wire::peer::PairedNode], vault: &Vault) -> String {
    if taken.iter().any(|n| n.id == "vault") {
        format!("vault-{}", &hex::encode(vault.key)[..8])
    } else {
        "vault".to_string()
    }
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

    // 1. Claim the name. A phrase that does not prove against a log this machine holds
    // is refused here, with nothing opened or written.
    client
        .login_with_recovery_key(&a.phrase, Some(name.to_string()), None)
        .await
        .map_err(|e| refused(e.to_string()))?;

    // 2. The vault the line names, as the node to dial.
    let nodes = client.list_nodes(name).await?;
    let added = match nodes.iter().find(|n| n.public_key == a.vault.key) {
        Some(n) if n.addresses.first() == Some(&a.vault.addr) => None,
        // Paired already under another address: the line says where it is now. A
        // refusal below leaves it there (the module doc says why).
        Some(n) => {
            let (id, key_hex) = (n.id.clone(), hex::encode(a.vault.key));
            if let Err(e) = client.peer_add(name, &id, &a.vault.did, &key_hex, a.vault.addr).await {
                return Err(refused(take_back(client, name, None, !held_before, e.to_string()).await));
            }
            None
        }
        None => {
            let label = label_for(&nodes, &a.vault);
            let key_hex = hex::encode(a.vault.key);
            if let Err(e) = client.peer_add(name, &label, &a.vault.did, &key_hex, a.vault.addr).await {
                return Err(refused(take_back(client, name, None, !held_before, e.to_string()).await));
            }
            Some(label)
        }
    };

    // 3. Recover against it.
    if let Err(e) = client.recover(name, &a.phrase, &a.passphrase).await {
        return Err(refused(take_back(client, name, added.as_deref(), !held_before, e.to_string()).await));
    }

    // 4. The identity this machine acts as.
    kotton::active_identity::set(name)?;

    // 5. Your things, from each node this name has here, as `kotton sync` brings them.
    let mut pulled = 0;
    let mut unsynced = Vec::new();
    for node in client.list_nodes(name).await? {
        match client.sync_mount(name, "local", &node.id, None).await {
            Ok(r) => pulled += r.pulled,
            Err(e) => unsynced.push(format!("{}: {e}", node.id)),
        }
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
/// refusal: the node it added, and — when the machine held nothing under the name
/// before — the claim, with the session it cached. `why` is what refused.
async fn take_back(client: &mut KottonClient, name: &str, added: Option<&str>, claimed: bool, why: String) -> String {
    let mut left = Vec::new();
    if let Some(label) = added {
        if let Err(e) = client.revoke_node(name, label).await {
            left.push(Left::Node { label: label.to_owned(), why: e.to_string() });
        }
    }
    // The claim is taken back only once nothing it scopes is left: `peer revoke` runs
    // on the claim's session, and removing the claim does not remove the name's node
    // rows, so a node left behind needs the claim kept until the person removes it.
    if claimed {
        if !left.is_empty() {
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
    /// The node this command added, which `revoke_node` refused to remove.
    Node { label: String, why: String },
    /// The claim this command made, which `logout_user` refused to remove.
    Claim { why: String },
    /// The claim this command made, kept on purpose because a node it scopes is left:
    /// the line that removes the node runs on the claim's session.
    ClaimKept,
}

/// The refusal's one sentence. With nothing left, a machine that held nothing of the
/// name says so; a machine that held it says only what refused. Each thing left names
/// the line that removes it, in the order they run: a node is a `peer revoke`, which
/// needs the claim, and `id rm` is named only for a claim this command made, never on
/// a machine that held the name, where it would remove an identity this command did
/// not claim.
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
            Left::Node { label, why } => {
                format!("the node '{label}' ({why}) — `kotton peer --user {name} revoke {label}` removes it")
            }
            Left::Claim { why } => format!("the name '{name}' ({why}) — `kotton id rm {name}` removes what it claimed"),
            Left::ClaimKept => format!("the name '{name}', kept so that line can run — then `kotton id rm {name}` removes what it claimed"),
        })
        .collect();
    format!("{why}; and this machine still holds {}", remedies.join(", and "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal names, for each thing it did not take back, the line that removes it,
    /// in the order they run. A node left on a machine that held the name is a `peer
    /// revoke` and nothing more; on a machine where this command made the claim, the
    /// claim is kept so that line can run, and `id rm` is named after it. `id rm` alone
    /// is named only when the claim itself could not be taken back.
    #[test]
    fn a_refusal_names_the_line_that_removes_what_is_left_and_never_more() {
        let node = Left::Node { label: "vault".into(), why: "busy".into() };
        let held = refusal("alice", false, std::slice::from_ref(&node), "refused".into());
        assert!(held.contains("`kotton peer --user alice revoke vault`"), "{held}");
        assert!(!held.contains("id rm"), "{held}");

        let fresh = refusal("alice", true, &[node, Left::ClaimKept], "refused".into());
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
    /// Five distinct words of the list, above the bar a passphrase is held to.
    const PASSPHRASE: &str = "abandon-ability-able-about-above";

    fn key() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()
    }

    fn line() -> String {
        InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: key() }.to_text()
    }

    fn given(answers: &[&str]) -> Asking {
        Asking::Given(answers.iter().map(|a| a.to_string()).collect())
    }

    fn asked(name: Option<&str>, answers: &[&str]) -> (Result<Answers, String>, Asking) {
        let mut asking = given(answers);
        let mut said = Vec::new();
        let got = ask(name, &mut asking, &mut said).expect("asking does not fail on given answers");
        (got, asking)
    }

    fn left(asking: &Asking) -> usize {
        match asking {
            Asking::Given(left) => left.len(),
            _ => unreachable!("the tests answer in advance"),
        }
    }

    /// **The name, the words, the line and the passphrase, in that order and each once.**
    /// Nothing is left unasked and nothing asked twice: four answers, Enter taking the
    /// suggested passphrase, make one recovery of the vault the line names.
    #[test]
    fn recover_asks_the_name_the_words_the_line_and_a_passphrase_once_each() {
        let (got, asking) = asked(None, &["sam\n", PHRASE, &format!("{}\n", line()), ""]);
        let a = got.expect("the four answers are a recovery");
        assert_eq!(left(&asking), 0, "an answer was left unasked");
        assert_eq!(a.name, "sam");
        assert_eq!(a.phrase, PHRASE);
        assert_eq!(a.vault, vault_of_line(&line()).unwrap());
        assert!(!a.passphrase.is_empty(), "Enter takes the suggested passphrase");

        // A typed passphrase is asked again to confirm.
        let (got, asking) = asked(None, &["sam", PHRASE, &line(), PASSPHRASE, PASSPHRASE]);
        assert_eq!(got.expect("a confirmed passphrase").passphrase, PASSPHRASE);
        assert_eq!(left(&asking), 0);
    }

    /// A name given on the command line is not asked for.
    #[test]
    fn a_name_given_is_not_asked() {
        let (got, asking) = asked(Some("sam"), &[PHRASE, &line(), ""]);
        assert_eq!(got.expect("three answers with the name given").name, "sam");
        assert_eq!(left(&asking), 0);
    }

    /// **What is not a recovery is refused before the passphrase, and nothing is sent.**
    /// Words that are not a phrase are refused before the line is asked; a line that
    /// is not a vault's before the passphrase. Every refusal says nothing was changed.
    #[test]
    fn words_or_a_line_that_are_not_a_recovery_are_refused_before_the_next_question() {
        let (got, asking) = asked(Some("sam"), &["not the words", &line(), ""]);
        let why = got.expect_err("words that are no phrase");
        assert!(why.contains("twenty-four words") && why.contains("nothing was changed"), "{why}");
        assert_eq!(left(&asking), 2, "the line was asked after words that are no phrase");

        let (got, _) = asked(Some("sam"), &["", &line(), ""]);
        assert!(got.expect_err("no words").contains("nothing was changed"));

        let relay = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: key() }.to_text();
        for (bad, says) in [
            (relay.as_str(), "relay's line"),
            ("kotton-instance:vault:abcd@203.0.113.9:7710", "cut short"),
            ("203.0.113.9:7710", "not a code"),
        ] {
            let (got, asking) = asked(Some("sam"), &[PHRASE, bad, ""]);
            let why = got.expect_err(bad);
            assert!(why.contains(says) && why.contains("nothing was changed"), "`{bad}`: {why}");
            assert_eq!(left(&asking), 1, "`{bad}`: the passphrase was asked after a line that is not a vault's");
        }
        let (got, _) = asked(None, &["  \n"]);
        assert!(got.expect_err("an empty name").contains("a name is required"));
    }

    /// With nobody at a terminal — a pipe, a script — nothing is asked and nothing sent,
    /// at whichever question nobody answers.
    #[test]
    fn with_nobody_to_answer_recover_refuses_and_sends_nothing() {
        let mut said = Vec::new();
        let why = ask(None, &mut Asking::Nobody, &mut said).unwrap().expect_err("nobody answered");
        assert!(why.contains("at a terminal") && why.contains("nothing was changed"), "{why}");
        for answers in [&[][..], &["sam"][..], &["sam", PHRASE][..], &["sam", PHRASE, &line()][..]] {
            let (got, _) = asked(None, answers);
            assert!(got.expect_err("an answer was missing").contains("at a terminal"), "{answers:?}");
        }
    }

    /// **The line names the node the recovery dials.** Its key is the key the node is
    /// held to, its DID the `did:key` spelling of that key a node is paired under, and
    /// its address the one dialled. An address that is not `<ip>:<port>` is refused.
    #[test]
    fn a_vaults_line_is_the_node_the_recovery_dials() {
        let v = vault_of_line(&format!("  {}\n", line())).expect("a vault's line");
        assert_eq!(v.key, key());
        assert_eq!(v.addr, "203.0.113.9:7710".parse::<SocketAddr>().unwrap());
        assert_eq!(v.did, kotton_crypto::DidKeyMethod::from_public_key_bytes(&key()).unwrap().to_string());
        assert!(v.did.starts_with("did:key:z"), "{}", v.did);

        let named = InstanceLine { kind: OperatedService::Vault, hint: "vault.example:7710".into(), key: key() }.to_text();
        assert!(vault_of_line(&named).unwrap_err().contains("<ip>:<port>"));
        let nowhere = InstanceLine { kind: OperatedService::Vault, hint: String::new(), key: key() }.to_text();
        assert!(vault_of_line(&nowhere).unwrap_err().contains("names no address"));
    }

    /// **The card's line reads back as the node it was printed from.** The shell prints
    /// the line from the node a copy was delivered to; this reads it back as the node to
    /// dial, and the two agree on the key, the address, and the DID the node was paired
    /// under.
    #[test]
    fn the_cards_line_reads_back_as_the_node_it_was_printed_from() {
        let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key()).unwrap();
        let node = kotton_wire::peer::PairedNode {
            id: "blind-vps".to_string(),
            device_did: did.clone(),
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
        let v = vault_of_line(lines[0]).expect("the card's line reads");
        assert_eq!((v.key, v.addr, v.did), (node.public_key, node.addresses[0], did.to_string()));
    }

    /// The node is added as `vault`, or beside a `vault` already there under its key.
    #[test]
    fn the_vault_is_added_as_vault_unless_that_label_is_taken() {
        let v = vault_of_line(&line()).unwrap();
        assert_eq!(label_for(&[], &v), "vault");
        let taken = kotton_wire::peer::PairedNode {
            id: "vault".to_string(),
            device_did: kotton_wire::did::Did::new("key", "z6MktGLn5v9bCrdxWgRojExample"),
            public_key: [9; 32],
            paired_at: 0,
            addresses: vec![],
            relay_url: None,
            posture: None,
        };
        assert_eq!(label_for(&[taken], &v), format!("vault-{}", &hex::encode(key())[..8]));
    }
}
