// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery, as both doors run it: the card asked for, and the one `Recover` sent.
//!
//! What `id add-recovery` printed is the twenty-four words and, under them, the line
//! of each vault that keeps a copy ([`crate::commands::recovery_card`]). Recovering is
//! giving both back: the words are the authority, and the line says which vault holds
//! what they open. [`ask`] asks for the words at the hidden prompt, then one line,
//! then a passphrase for this device, all before anything is sent; [`send`] sends
//! them as one `Recover`, in which the daemon adds the line's vault, proves the words,
//! rotates onto this device's key, records the vault as the person's drive after the
//! proof, and takes the node back on a refusal (`kotton_device::users::recover`).
//!
//! **One path, two doors.** `kotton id recover` at a terminal (`kotton_cli`'s
//! `commands::recover`) claims the name first, then runs these two, then makes the
//! name the identity the machine acts as and syncs. The REPL's `id recover`
//! ([`crate::commands::id`]) runs these two for the identity it runs as, on the
//! session `kotton id login` opened on the claim. Neither door adds the vault
//! itself, and neither says what a drive is: until #80 the one-shot added the vault
//! and then marked it a drive with a flag any local session could set, and the REPL's
//! door, which added the vault with `peer add`, never marked it (#76).

use std::io;

use crate::out::Out;
use crate::secret::{choose_new_passphrase, recovery_phrase_question, require_phrase, NewPassphrase};
use crate::Asking;

/// The question the line is asked with, by either door.
pub const LINE_QUESTION: &str = "the line under the words (kotton-instance:vault:…)";

/// What the card gives back: the words, the vault's line, and the passphrase chosen
/// for this device.
pub struct Card {
    /// The twenty-four words, checked to be a phrase.
    pub phrase: String,
    /// The vault's line, as given and read as a vault's
    /// ([`kotton_wire::line::InstanceLine::vault`]).
    pub line: String,
    /// The passphrase chosen for this device, offered and confirmed as every new one is.
    pub passphrase: String,
}

/// The line, and never the words or the passphrase: a debug print of what was
/// asked is somewhere a secret must not land.
impl std::fmt::Debug for Card {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Card").field("line", &self.line).finish_non_exhaustive()
    }
}

/// Why nothing was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAsked {
    /// Nobody is here to answer `what`; each door names where to run it instead.
    NobodyToAsk(&'static str),
    /// What was given is not a recovery: one sentence saying why, ending with
    /// "nothing was changed".
    Refused(String),
}

/// Ask for the card, in order: the words at the hidden prompt, the vault's line, and
/// a passphrase for this device. Each is asked once, and each is refused before the
/// next is asked when it is not what recovery takes. `Ok(Err(_))` is nothing sent.
pub fn ask(name: &str, asking: &mut Asking, said: &mut Vec<Out>) -> io::Result<Result<Card, NotAsked>> {
    let Some(entered) = asking.hidden_after(said, &recovery_phrase_question(name))? else {
        return Ok(Err(NotAsked::NobodyToAsk("your recovery phrase")));
    };
    let phrase = match require_phrase(&entered) {
        Ok(phrase) => phrase,
        Err(e) => return Ok(Err(NotAsked::Refused(format!("{e}; nothing was changed")))),
    };
    if let Err(e) = kotton_crypto::try_mnemonic_to_seed32(&phrase) {
        return Ok(Err(NotAsked::Refused(format!(
            "these are not the twenty-four words of a recovery phrase ({e}) — check them against what \
             you wrote down; nothing was changed"
        ))));
    }

    let Some(typed) = asking.line_after(said, LINE_QUESTION)? else {
        return Ok(Err(NotAsked::NobodyToAsk("the vault's line")));
    };
    let line = typed.trim().to_string();
    if let Err(why) = kotton_wire::line::InstanceLine::vault(&line) {
        return Ok(Err(NotAsked::Refused(format!("{why}; nothing was changed"))));
    }

    said.push(Out::Note(
        "Choose the passphrase that unlocks your keys on this device. It replaces any passphrase \
         this device knew for them."
            .to_string(),
    ));
    let question = format!("passphrase for '{name}' on this device (hidden, Enter to accept the suggestion)");
    let passphrase = match choose_new_passphrase(asking, said, &question)? {
        NewPassphrase::Chosen(passphrase) => passphrase,
        NewPassphrase::NobodyToAsk => return Ok(Err(NotAsked::NobodyToAsk("a passphrase for this device"))),
        NewPassphrase::Refused(why) => return Ok(Err(NotAsked::Refused(format!("{why}; nothing was changed")))),
    };
    Ok(Ok(Card { phrase, line, passphrase }))
}

/// Send the card as one `Recover` for `name`, on the session `client` holds — the
/// claim's, or the identity's own. The one place either door sends it.
pub async fn send(client: &mut kotton::KottonClient, name: &str, card: &Card) -> io::Result<kotton::Recovery> {
    client.recover(name, &card.phrase, &card.passphrase, &card.line).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_wire::ipc::OperatedService;
    use kotton_wire::line::InstanceLine;

    /// Twenty-four words of the list, with the checksum right: the phrase every test
    /// vector of BIP-39 starts from.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon art";
    /// Five distinct words of the list, above the bar a passphrase is held to.
    const PASSPHRASE: &str = "abandon-ability-able-about-above";

    fn line() -> String {
        let key = [7u8; 32];
        InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key }.to_text()
    }

    fn asked(answers: &[&str]) -> (Result<Card, NotAsked>, usize) {
        let mut asking = Asking::Given(answers.iter().map(|a| a.to_string()).collect());
        let mut said = Vec::new();
        let got = ask("sam", &mut asking, &mut said).expect("asking does not fail on given answers");
        let left = match asking {
            Asking::Given(left) => left.len(),
            _ => unreachable!("the tests answer in advance"),
        };
        (got, left)
    }

    /// **The words, the line and the passphrase, in that order and each once.**
    /// Enter takes the suggested passphrase; a typed one is asked again to confirm.
    /// The line is kept as given, trimmed.
    #[test]
    fn the_card_is_the_words_the_line_and_a_passphrase_once_each() {
        let (got, left) = asked(&[PHRASE, &format!("{}\n", line()), ""]);
        let card = got.expect("three answers are a card");
        assert_eq!(left, 0, "an answer was left unasked");
        assert_eq!((card.phrase.as_str(), card.line.as_str()), (PHRASE, line().as_str()));
        assert!(!card.passphrase.is_empty(), "Enter takes the suggested passphrase");
        assert!(!format!("{card:?}").contains("abandon"), "the words print through Debug");

        let (got, left) = asked(&[PHRASE, &line(), PASSPHRASE, PASSPHRASE]);
        assert_eq!(got.expect("a confirmed passphrase").passphrase, PASSPHRASE);
        assert_eq!(left, 0);
    }

    /// **What is not a recovery is refused before the next question, and nothing is
    /// sent.** Words that are not a phrase are refused before the line is asked; a line
    /// that is not a vault's before the passphrase. Each refusal says nothing was changed.
    #[test]
    fn words_or_a_line_that_are_not_a_recovery_are_refused_before_the_next_question() {
        let (got, left) = asked(&["not the words", &line(), ""]);
        let Err(NotAsked::Refused(why)) = got else { panic!("words that are no phrase: {got:?}") };
        assert!(why.contains("twenty-four words") && why.contains("nothing was changed"), "{why}");
        assert_eq!(left, 2, "the line was asked after words that are no phrase");

        let relay = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [7; 32] }.to_text();
        for (bad, says) in [
            (relay.as_str(), "relay's line"),
            ("kotton-instance:vault:abcd@203.0.113.9:7710", "cut short"),
            ("203.0.113.9:7710", "not a code"),
        ] {
            let (got, left) = asked(&[PHRASE, bad, ""]);
            let Err(NotAsked::Refused(why)) = got else { panic!("`{bad}`: {got:?}") };
            assert!(why.contains(says) && why.contains("nothing was changed"), "`{bad}`: {why}");
            assert_eq!(left, 1, "`{bad}`: the passphrase was asked after a line that is not a vault's");
        }
    }

    /// With nobody to answer, nothing is asked past the question nobody answers, and
    /// each refusal says which it was.
    #[test]
    fn with_nobody_to_answer_nothing_is_sent() {
        let line = line();
        for (answers, what) in [
            (vec![], "your recovery phrase"),
            (vec![PHRASE], "the vault's line"),
            (vec![PHRASE, line.as_str()], "a passphrase for this device"),
        ] {
            let (got, _) = asked(&answers);
            assert_eq!(got.expect_err("an answer was missing"), NotAsked::NobodyToAsk(what), "{answers:?}");
        }
    }
}
