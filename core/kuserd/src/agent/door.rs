// SPDX-License-Identifier: AGPL-3.0-or-later
//! Settings' one door: *Paste a code*.
//!
//! **The code says what it is, so nothing asks whose it is.** Every code is
//! the one grammar (`kotton_wire::line::Code`): an instance's
//! line names a vault or a relay, its whole key and where it is reached; a
//! vault's invite names the vault's key, its words, and the relay it meets its
//! tenant at by key and hint. The door reads which, shows it, and
//! does that — a line completes the key this desktop minted for its instance
//! ([`super::operator::complete`], the terminal's `enrol` of one line); an
//! invite runs the joining ceremony, held to both keys its code
//! names. There is no chooser and no second verb behind either.
//!
//! **A line completes a key this desktop minted, or nothing.** The line
//! confers nothing: the instance was created for a key the person minted here
//! first, and the line is how the desktop learns where it is
//! and which key to hold it to. So a line is resolved as the completion of a
//! key waiting here ([`super::operator::completes`]) — and a line for which
//! none waits is refused at resolve, naming the mint.
//!
//! **Resolving writes nothing and dials nothing.** [`resolve`] parses, and
//! reads which keys wait here and which services this person already runs. The
//! dial is the completion's: it holds the instance to the line's key before it
//! keeps anything (`operator::complete`). An invite's relay is dialled by
//! `joining.admit`, and only once it has proved the key the code names.
//!
//! **The reach test.** The door is reachable only as `interface landlord` in
//! `world occupant`: the host adds it to the linker for the app the person
//! designated `shell` and no other, so an ordinary guest has no function to
//! call and nothing to guard. The code crosses the runner wire as
//! `SecretText`, which prints `<redacted>`, and nothing here logs it.

use kotton_peer::operator::OperatorCredential;
use kotton_wire::ipc::{OperatedService, Unstood, UnstoodRelayState, UnstoodWhy, UserResponse};
use kotton_wire::line::{Code, InstanceLine, InviteCode, INVITE_PREFIX, LINE_PREFIX};
use kotton_wire::runner::{RunnerAct, RunnerCodeKind, RunnerEnrolled, RunnerRelayChoice, RunnerResolved};

/// What the door says of a line that is no code.
pub(crate) const NOT_A_CODE: &str = "This isn't a code Kotton reads. A code is the line a vault or a relay \
     printed when it was created — it begins kotton-instance: — or an invite, which begins \
     kotton-invite:. Paste the whole line, as it was given to you.";

/// What was pasted, read.
enum Pasted {
    Line(InstanceLine),
    Invite(InviteCode),
}

fn read(pasted: &str) -> Result<Pasted, String> {
    let pasted = pasted.trim();
    if pasted.starts_with(LINE_PREFIX) || pasted.starts_with(INVITE_PREFIX) {
        // A code that does not parse is said as the parser says it: a code
        // cut short is the likely cause, and its sentence names it.
        return Code::parse(pasted).map(|code| match code {
            Code::Line(line) => Pasted::Line(line),
            Code::Invite(invite) => Pasted::Invite(invite),
        });
    }
    if pasted.contains('#') {
        return Err(KEYLESS_INVITE.to_string());
    }
    Err(NOT_A_CODE.to_string())
}

/// What the door says of an invite in the form that named no key
/// (`relay#words`): it is not admitted, because nothing could hold its relay or
/// its vault to anything.
pub(crate) const KEYLESS_INVITE: &str = "This invite is in the form that names no key, so neither the relay it \
     meets at nor the vault could be held to anything. Ask for the invite again: an invite now begins \
     kotton-invite:.";

/// Read a pasted code and say what it names, writing nothing and dialling
/// nothing. `kept` is the credentials this person keeps and `minted` the keys
/// minted here and waiting, read by the caller from their store; a line is
/// resolved as the completion of one of those keys, or refused.
pub(crate) fn resolve(kept: &[OperatorCredential], minted: &[String], pasted: &str) -> Result<RunnerResolved, String> {
    match read(pasted)? {
        Pasted::Line(line) => {
            // Said here, before the sheet offers *Enrol*: a line that names no
            // address completes nothing (`complete_from_line` refuses it too).
            if line.hint.is_empty() {
                return Err(format!(
                    "This {word}'s line names no address to reach it at: it announces none. Give it its address, \
                     and paste the line it prints then.",
                    word = line.kind.word()
                ));
            }
            let name = match super::operator::completes(kept, minted, None, &line)? {
                super::operator::Completes::Key { name, .. } => name,
                super::operator::Completes::Which(names) => {
                    return Err(super::operator::which_at_the_door(Some(line.kind), &names))
                }
            };
            Ok(RunnerResolved {
                kind: match line.kind {
                    OperatedService::Relay => RunnerCodeKind::RelayLine,
                    OperatedService::Vault => RunnerCodeKind::VaultLine,
                },
                key: Some(hex::encode(line.key)),
                hint: line.hint,
                reached: false,
                completes: Some(name),
            })
        }
        // The vault's key is the one the admit pins; the hint is the relay it
        // meets at, which the admit holds to the relay's key before it dials.
        Pasted::Invite(InviteCode::Vault { key, relay_hint, .. }) => Ok(RunnerResolved {
            kind: RunnerCodeKind::VaultInvite,
            key: Some(hex::encode(key)),
            hint: relay_hint,
            reached: false,
            completes: None,
        }),
        // The relay's key is the one standing there holds it to; the admit
        // proves it before anything is written.
        Pasted::Invite(InviteCode::Relay { key, hint, .. }) => Ok(RunnerResolved {
            kind: RunnerCodeKind::RelayInvite,
            key: Some(hex::encode(key)),
            hint,
            reached: false,
            completes: None,
        }),
    }
}

/// The line a pasted code is, for the completion — which is told no name, and
/// finds the key it completes as [`resolve`] did. An invite is refused here in
/// the door's words: it is joined, not enrolled.
pub(crate) fn line_of(pasted: &str) -> Result<String, String> {
    match read(pasted)? {
        Pasted::Line(line) => Ok(line.to_text()),
        Pasted::Invite(_) => Err("This is an invite, not a vault's or a relay's line: it is joined, not enrolled.".into()),
    }
}

/// The completion's answer, as the door draws it: kept, and, for a vault not
/// told where to stand, the reason and the acts — each worded by
/// `Unstood::acts`, the one place the terminal's lines come from too — and,
/// when the desktop asks where the vault stands, the relays to choose among.
pub(crate) fn enrolled(answer: UserResponse) -> Result<RunnerEnrolled, String> {
    match answer {
        UserResponse::OperatorEnrolled { name, service, unstood } => {
            let (not_standing, acts, choose) = match &unstood {
                Some(u) => (Some(u.reason.clone()), acts(u, &name), choices(u)),
                None => (None, Vec::new(), Vec::new()),
            };
            Ok(RunnerEnrolled { relay: service == OperatedService::Relay, name, not_standing, acts, choose })
        }
        UserResponse::Error { message } => Err(message),
        other => Err(format!("the line was answered with something the door does not read: {other:?}")),
    }
}

fn acts(u: &Unstood, vault: &str) -> Vec<RunnerAct> {
    u.acts(vault).into_iter().map(|(at, act)| RunnerAct { at, act }).collect()
}

fn choices(u: &Unstood) -> Vec<RunnerRelayChoice> {
    if u.why != UnstoodWhy::Several {
        return Vec::new();
    }
    u.relays
        .iter()
        .filter(|r| r.state == UnstoodRelayState::Operated)
        .filter_map(|r| r.name.clone().map(|name| RunnerRelayChoice { name, address: r.hint.clone() }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const RELAY: &str = "http://203.0.113.9:7700";

    fn minted(service: OperatedService, name: &str, seed: u8) -> String {
        kotton_peer::operator::minted_text(service, name, &SigningKey::from_bytes(&[seed; 32]), None).unwrap()
    }

    fn line(kind: OperatedService, key: u8) -> String {
        let hint = match kind {
            OperatedService::Relay => RELAY.to_string(),
            OperatedService::Vault => "203.0.113.9:7710".to_string(),
        };
        InstanceLine { kind, hint, key: [key; 32] }.to_text()
    }

    fn vault_invite() -> String {
        InviteCode::Vault { key: [0xcd; 32], words: "fame-cheap-unfold".into(), relay_key: [0xab; 32], relay_hint: RELAY.into(), invited: None }
            .to_text()
    }

    /// **A vault's invite resolves to the vault's key and the relay it meets
    /// at, dialling nothing; an invite that names no key, and a line that is no
    /// code, are refused in the door's words.**
    #[test]
    fn an_invite_resolves_to_its_vaults_key_and_anything_else_is_not_a_code() {
        let got = resolve(&[], &[], &format!("  {}\n", vault_invite())).unwrap();
        assert_eq!(
            (got.kind, got.key.clone(), got.hint.clone(), got.reached, got.completes.clone()),
            (RunnerCodeKind::VaultInvite, Some("cd".repeat(32)), RELAY.to_string(), false, None)
        );
        assert_eq!(resolve(&[], &[], "relay.example:7700#fame-cheap-unfold"), Err(KEYLESS_INVITE.to_string()));
        assert_eq!(resolve(&[], &[], "hello there"), Err(NOT_A_CODE.to_string()));
        let cut = line(OperatedService::Relay, 0xab).replacen(&"ab".repeat(32), &"ab".repeat(31), 1);
        assert!(resolve(&[], &[], &cut).unwrap_err().contains("64 hex"), "a line cut short is said as the parser says it");
        let cut = vault_invite().replace("fame-cheap-unfold", "fame-cheap");
        assert!(resolve(&[], &[], &cut).unwrap_err().contains("spoken words"), "an invite cut short likewise");
    }

    /// **The door resolves a service's line as the completion of a key this
    /// desktop minted, and refuses a line for which it minted none, naming the
    /// mint.** The key it completes is the one waiting for that kind;
    /// with several waiting, the line does not say which, and the refusal
    /// names each and sends the person to the terminal's `enrol`, which asks
    /// which, rather than trying each key at the instance.
    #[test]
    fn a_line_resolves_as_the_completion_of_a_key_minted_here_and_none_is_refused() {
        for (kind, word, code) in
            [(OperatedService::Vault, "vault", RunnerCodeKind::VaultLine), (OperatedService::Relay, "relay", RunnerCodeKind::RelayLine)]
        {
            let pasted = line(kind, 0xab);
            let none = resolve(&[], &[], &pasted).unwrap_err();
            assert!(none.contains(&format!("`mint {word}`")), "{none}");
            let other = if kind == OperatedService::Vault { OperatedService::Relay } else { OperatedService::Vault };
            let wrong_kind = resolve(&[], &[minted(other, "kotton", 1)], &pasted).unwrap_err();
            assert!(wrong_kind.contains(&format!("`mint {word}`")), "a key of the other kind completes nothing: {wrong_kind}");

            let got = resolve(&[], &[minted(kind, "kotton", 1)], &pasted).unwrap();
            assert_eq!(got.kind, code);
            assert_eq!(got.key.as_deref(), Some("ab".repeat(32).as_str()));
            assert_eq!(got.completes.as_deref(), Some("kotton"));
            assert!(!got.reached, "resolving dials nothing");

            let nowhere = InstanceLine { kind, hint: String::new(), key: [0xab; 32] }.to_text();
            let said = resolve(&[], &[minted(kind, "kotton", 1)], &nowhere).unwrap_err();
            assert!(said.contains("names no address"), "a line with no address is refused at resolve: {said}");

            let several = resolve(&[], &[minted(kind, "kotton", 1), minted(kind, "attic", 2)], &pasted).unwrap_err();
            assert!(several.contains("the terminal's `enrol <line>`, which asks which") && several.contains("'kotton', 'attic'"), "{several}");
            assert!(!several.contains(&format!("{word} enrol")), "a verb that is gone: {several}");
        }
    }

    /// The door's completion is told the line, and an invite is not a line.
    #[test]
    fn the_completion_takes_a_line_and_never_an_invite() {
        let pasted = line(OperatedService::Vault, 7);
        assert_eq!(line_of(&format!("  {pasted}\n")).unwrap(), pasted);
        assert!(line_of(&vault_invite()).unwrap_err().contains("joined, not enrolled"));
        assert_eq!(line_of("hello"), Err(NOT_A_CODE.to_string()));
    }
}
