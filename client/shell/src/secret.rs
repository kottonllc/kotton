// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hidden prompt: where a secret is read at a terminal, for both doors.
//!
//! A recovery phrase or a passphrase is read here and nowhere else in this crate:
//! from the terminal device with echo off, by [`read_hidden`], never through the
//! REPL's line editor. The line editor is what keeps the history file, so a secret
//! that never passes through it is one the history cannot hold. It is never taken
//! on argv either, where the OS shell's history and the process list would hold it.
//!
//! One prompt, two doors. `kotton id login`, `kotton id unlock` and the other
//! one-shot verbs that ask for a secret call [`prompt_recovery_phrase`] and
//! [`prompt_passphrase`]; `kotton id recover` and `kotton id rotate` run the
//! shell's own `id recover` and `id rotate` through the bridge, and those ask by
//! [`crate::ShellState::ask_hidden`], whose terminal path is [`read_hidden`].

use std::io;

/// Read one line at the terminal with echo off, trimmed.
///
/// `question` is the words only; the margin and the `$` are added here, as
/// [`crate::ui::ask`] adds them to every question the shell puts.
pub fn read_hidden(question: &str) -> io::Result<String> {
    let entered = rpassword::prompt_password(crate::ui::ask(question))?;
    Ok(entered.trim().to_string())
}

/// The question the recovery phrase is asked with, by either door.
pub fn recovery_phrase_question(username: &str) -> String {
    format!("recovery phrase for '{username}' (24 words, hidden)")
}

/// A recovery phrase as entered, or the refusal for none.
///
/// Trimmed here as well as at the read, because an answer given in advance
/// ([`crate::Asking::Given`]) reaches a verb without passing [`read_hidden`].
pub fn require_phrase(entered: &str) -> io::Result<String> {
    let phrase = entered.trim();
    if phrase.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a recovery phrase is required",
        ));
    }
    Ok(phrase.to_string())
}

/// Ask for the 24-word recovery phrase at a hidden prompt.
pub fn prompt_recovery_phrase(username: &str) -> io::Result<String> {
    require_phrase(&read_hidden(&recovery_phrase_question(username))?)
}

/// Ask for the daily passphrase at a hidden prompt.
///
/// Hidden, and with no positional or flag form, for the same reason the recovery
/// phrase has none: this credential unseals the vault holding the operational
/// roots, so argv (visible in the process list and the shell's history) is not
/// somewhere it may appear.
pub fn prompt_passphrase(question: &str) -> io::Result<String> {
    read_hidden(question)
}

/// What [`choose_new_passphrase`] came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewPassphrase {
    /// The passphrase chosen: the suggestion taken, or one typed twice that
    /// clears the bar.
    Chosen(String),
    /// Nobody is here to answer, so nothing was chosen.
    NobodyToAsk,
    /// What was typed is not a passphrase to seal keys under, and why.
    Refused(String),
}

/// Choose a new passphrase at the hidden prompt, offering a generated one: Enter
/// takes the suggestion, and a typed one is asked again and held to
/// [`required_entropy_bits`](kotton_crypto::daily_credential::required_entropy_bits).
/// One flow for every place a passphrase is chosen — creating an identity, setting
/// one, recovering one — so the bar and the confirmation cannot drift apart.
///
/// The suggestion is the point rather than a courtesy: a generated phrase clears
/// the bar by construction, because its entropy is drawn rather than estimated.
/// `generate` and `assess` are `core/crypto`'s; the daemon judges by the same.
///
/// The offer is pushed onto `said`, which is rendered before the question at a
/// terminal ([`crate::Asking::hidden_after`]). When nobody answers — the first
/// question or the confirmation — it is taken back out, so no passphrase nobody
/// chose is left printed.
pub fn choose_new_passphrase(
    asking: &mut crate::Asking,
    said: &mut Vec<crate::out::Out>,
    question: &str,
) -> io::Result<NewPassphrase> {
    use crate::out::Out;
    use kotton_crypto::daily_credential::{self, required_entropy_bits};

    let suggestion = daily_credential::generate();
    let offered = said.len();
    said.push(Out::Note("Suggested passphrase — press Enter to use it, or type your own:".to_string()));
    said.push(Out::Reveal(suggestion.clone()));
    let Some(typed) = asking.hidden_after(said, question)? else {
        said.truncate(offered);
        return Ok(NewPassphrase::NobodyToAsk);
    };
    if typed.is_empty() {
        return Ok(NewPassphrase::Chosen(suggestion));
    }
    let Some(again) = asking.hidden_after(said, "again, to confirm")? else {
        said.truncate(offered);
        return Ok(NewPassphrase::NobodyToAsk);
    };
    if again != typed {
        return Ok(NewPassphrase::Refused("those did not match".to_string()));
    }
    if let Err(weak) = daily_credential::assess(&typed, required_entropy_bits()) {
        return Ok(NewPassphrase::Refused(weak.to_string()));
    }
    Ok(NewPassphrase::Chosen(typed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phrase_is_trimmed_and_an_empty_one_is_refused() {
        assert_eq!(require_phrase("  abandon ability able \n").unwrap(), "abandon ability able");
        for empty in ["", "   ", "\n"] {
            let refused = require_phrase(empty).expect_err("an empty phrase is refused");
            assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
        }
    }

    fn choose(answers: &[&str]) -> (NewPassphrase, Vec<crate::out::Out>) {
        let mut asking = crate::Asking::Given(answers.iter().map(|a| a.to_string()).collect());
        let mut said = Vec::new();
        let chosen = choose_new_passphrase(&mut asking, &mut said, "passphrase").unwrap();
        (chosen, said)
    }

    /// Enter takes the suggestion, which is the one offered; a typed passphrase is
    /// taken only when confirmed and above the bar.
    #[test]
    fn a_new_passphrase_is_the_offer_or_one_typed_twice_above_the_bar() {
        let (chosen, said) = choose(&[""]);
        let offered = said.iter().find_map(|o| match o {
            crate::out::Out::Reveal(r) => Some(r.clone()),
            _ => None,
        });
        assert_eq!(Some(chosen), offered.map(NewPassphrase::Chosen), "Enter takes the offer");

        let typed = "abandon-ability-able-about-above";
        assert_eq!(choose(&[typed, typed]).0, NewPassphrase::Chosen(typed.to_string()));
        assert!(matches!(choose(&[typed, "something else"]).0, NewPassphrase::Refused(_)));
        assert!(matches!(choose(&["hunter2", "hunter2"]).0, NewPassphrase::Refused(_)));
    }

    /// With nobody to answer, at either question, nothing is chosen and the offer is
    /// taken back out of what is said.
    #[test]
    fn with_nobody_to_answer_the_offer_is_not_left_printed() {
        for answers in [&[][..], &["abandon-ability-able-about-above"][..]] {
            let (chosen, said) = choose(answers);
            assert_eq!(chosen, NewPassphrase::NobodyToAsk, "{answers:?}");
            assert!(said.is_empty(), "the offer was left in what is said: {said:?}");
        }
    }

    /// The question names the identity and says the answer is hidden, so a person
    /// knows which phrase is wanted and that nothing they type will show.
    #[test]
    fn the_question_names_the_identity_and_says_it_is_hidden() {
        let q = recovery_phrase_question("sam");
        assert!(q.contains("'sam'") && q.contains("hidden"), "{q}");
    }
}
