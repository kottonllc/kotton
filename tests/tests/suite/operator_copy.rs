// SPDX-License-Identifier: AGPL-3.0-or-later
//! The daemon's sentences about making an operator credential name only verbs
//! the shell has.
//!
//! The daemon tells a person, in words, which commands to type to make or
//! re-make the credential for a vault or a relay: after a credential stopped
//! reading, after a verb named one it keeps none for, after a credential of
//! the form it no longer reads. The daemon cannot depend on the shell, so
//! nothing held that copy to the verbs the shell dispatches on, and a verb the
//! shell retired (`vault enrol <name> <line>`, `relay mint`) stayed in the
//! sentences until a person typed it and was refused.
//!
//! This test renders every such sentence in the daemon's operator file for
//! both words ([`kuserd::agent::commands_the_copy_tells_a_person_to_type`]),
//! takes every backticked command out of it, and holds it to the registry the
//! REPL dispatches on: its first word is a command the shell lists, and does
//! not list as retired; its second — when it is a subcommand and not a
//! placeholder, a flag or a name — is a word in that command's own usage.
//! Retiring `mint` or `enrol` in the shell, or a subcommand from `vault` or
//! `relay`, fails here.
//!
//! It renders strings and reads a registry: no daemon, no process, no network.

use kotton_peer::operator::{Operates, OperatorCredential};
use kotton_shell::CommandRegistry;
use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;

/// The credentials a desktop keeps for a kind, and the line an instance of it
/// printed, to render the copy with: two credentials under fixed keys, so the
/// sentences name a key and a revoke, and a line that is none of theirs.
fn kept_and_line(kind: OperatedService) -> (Vec<OperatorCredential>, InstanceLine) {
    let kept = |name: &str, seed: u8| OperatorCredential {
        name: name.to_string(),
        key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
        operates: match kind {
            OperatedService::Vault => Operates::Vault { vault: [seed; 32], addr: None },
            OperatedService::Relay => {
                Operates::Relay { url: "http://203.0.113.9:7700".to_string(), key: Some([seed; 32]), rule: None }
            }
        },
    };
    let hint = match kind {
        OperatedService::Vault => "203.0.113.9:7710",
        OperatedService::Relay => "http://203.0.113.9:7700",
    };
    (vec![kept("home", 5), kept("cabin", 6)], InstanceLine { kind, hint: hint.to_string(), key: [9u8; 32] })
}

/// Programs typed at an instance's host, not in the shell. The copy names them
/// beside the shell's verbs (`kvaultd operator enrol <key>`), and they are the
/// instance's own, so the shell's registry says nothing of them.
const AT_THE_HOST: [&str; 3] = ["kvaultd", "runuser", "kotton-relay"];

/// The shell's verbs as a person is shown them: each with its help, hidden
/// ones left out (a command the registry hides is one that does not work yet).
struct Verbs(Vec<(String, String)>);

impl Verbs {
    fn of(registry: &CommandRegistry) -> Self {
        Self(registry.command_docs().into_iter().map(|(name, help)| (name, help.to_string())).collect())
    }

    fn help(&self, verb: &str) -> Option<&str> {
        self.0.iter().find(|(name, _)| name == verb).map(|(_, help)| help.as_str())
    }
}

/// Whether a command's help reads as the entry of a verb that was retired and
/// kept as a stub: the shell says so with "`<old>` is now `<new>`" (`gone` and
/// `gone_enrol` in `client/shell/src/commands/operated.rs`), and a live
/// command's usage begins with its own name.
fn reads_as_gone(verb: &str, help: &str) -> bool {
    !help.starts_with(verb) || help.contains(" is now `") || help.contains("has been retired")
}

/// The text between the backticks of `said`, in order.
fn backticked(said: &str) -> Vec<&str> {
    said.split('`').skip(1).step_by(2).collect()
}

/// A command's usage, less its placeholders: its help up to the dash that
/// begins the prose, with every `<…>` taken out, so a placeholder's own words
/// (`<r>`, `<name>`) are not words a second word can match.
fn words_of_usage(help: &str) -> Vec<String> {
    let usage = help.split(" — ").next().unwrap_or(help);
    let mut bare = String::new();
    let mut inside = false;
    for c in usage.chars() {
        match c {
            '<' => inside = true,
            '>' => inside = false,
            _ if !inside => bare.push(c),
            _ => {}
        }
    }
    bare.split(|c: char| !(c.is_alphanumeric() || c == '-')).filter(|w| !w.is_empty()).map(str::to_string).collect()
}

/// Every command in `said` the shell does not have, as it is written. Those
/// typed at the host, and the credential form's own name, are not the shell's
/// to have.
fn commands_the_shell_lacks(verbs: &Verbs, said: &str) -> Vec<String> {
    let mut lacks = Vec::new();
    for span in backticked(said) {
        let mut words = span.split_whitespace();
        let Some(first) = words.next() else { continue };
        if AT_THE_HOST.contains(&first) || span == kotton_peer::operator::FIRST_FORM {
            continue;
        }
        let Some(help) = verbs.help(first).filter(|help| !reads_as_gone(first, help)) else {
            lacks.push(span.to_string());
            continue;
        };
        let Some(second) = words.next() else { continue };
        if second.starts_with(['<', '-']) {
            continue;
        }
        if !words_of_usage(help).iter().any(|word| word == second) {
            lacks.push(span.to_string());
        }
    }
    lacks
}

/// **Every command the daemon's operator copy tells a person to type is one the
/// shell has**, for a vault and for a relay. Also held: that every rendered
/// sentence says a command and is not empty (a builder that rendered nothing
/// would pass by saying nothing), and that the copy names the two verbs that
/// make an instance.
#[test]
fn every_command_the_daemons_operator_copy_tells_a_person_to_type_is_one_the_shell_has() {
    let executor = kotton_cli::bridge::repl_executor();
    let verbs = Verbs::of(&executor.registry());
    let mut seen: Vec<String> = Vec::new();
    for service in [OperatedService::Vault, OperatedService::Relay] {
        let (kept, line) = kept_and_line(service);
        let sentences = kuserd::agent::commands_the_copy_tells_a_person_to_type("attic", &kept, &line);
        // Sixteen for a vault, twenty-two for a relay: a sentence that stopped
        // being rendered is a sentence no longer held to the shell.
        let rendered = match service {
            OperatedService::Vault => 16,
            OperatedService::Relay => 22,
        };
        assert_eq!(sentences.len(), rendered, "the copy rendered for the {} changed in number", service.word());
        for (which, said) in &sentences {
            assert!(!backticked(said).is_empty(), "{which}, for the {}, rendered no command:\n{said:?}", service.word());
            let lacks = commands_the_shell_lacks(&verbs, said);
            assert!(
                lacks.is_empty(),
                "{which}, for the {}, tells a person to type {lacks:?}, which the shell does not have:\n{said}",
                service.word()
            );
            seen.extend(backticked(said).into_iter().map(str::to_string));
        }
    }
    for verb in ["mint vault attic", "mint relay attic", "relay rule attic people_i_invite"] {
        assert!(seen.iter().any(|s| s == verb), "the copy no longer says `{verb}`: {seen:?}");
    }
    assert!(seen.iter().any(|s| s.starts_with("enrol ")), "the copy no longer says `enrol <line>`: {seen:?}");
}

/// **The check sees a retired verb.** The sentences the daemon said before
/// `mint <word>` and `enrol <line>` replaced the per-service forms, a
/// top-level verb listed only as a retirement stub, a placeholder's own word
/// used as a subcommand, and an unknown word are all caught, so the test above
/// is red for them and not vacuous.
#[test]
fn a_verb_the_shell_retired_is_seen_in_a_sentence() {
    let executor = kotton_cli::bridge::repl_executor();
    let verbs = Verbs::of(&executor.registry());
    let old = "re-make it: `mint vault home`, enrol the key, and `vault enrol home <the vault's line>`; \
               or `relay mint gate`, then `relay enrol gate <the relay's URL>`, or `frobnicate home`; \
               `relay name gate`, `mint r gate`";
    assert_eq!(
        commands_the_shell_lacks(&verbs, old),
        [
            "vault enrol home <the vault's line>",
            "relay mint gate",
            "relay enrol gate <the relay's URL>",
            "frobnicate home",
            // `name` and `r` are the words of placeholders (`<name>`, `<r>`), not subcommands.
            "relay name gate",
            "mint r gate",
        ]
    );
    let today = "`mint vault home`, then `enrol <the vault's line>`, and `kvaultd operator enrol <the new key>`";
    assert!(commands_the_shell_lacks(&verbs, today).is_empty());

    // A retired top-level verb is listed as a stub that says what replaced it:
    // registered, and so found by a lookup, and still refused.
    let stubs = Verbs(vec![
        ("sync-all".to_string(), "`sync-all` is now `sync` — one verb syncs every peer.".to_string()),
        ("enrol".to_string(), "enrol <line> — complete the key minted for it".to_string()),
        ("mint".to_string(), "mint has been retired".to_string()),
    ]);
    assert_eq!(
        commands_the_shell_lacks(&stubs, "`sync-all` then `enrol <line>` then `mint vault`"),
        ["sync-all", "mint vault"]
    );
}
