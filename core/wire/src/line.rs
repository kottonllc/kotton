// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one code grammar (RFC-0084 V15, V20): the instance's line, and beside it
//! the invite.
//!
//! ```text
//! kotton-instance:<relay|vault>:<its public key, 64 hex>@<where it is reached>
//! kotton-invite:relay:<the relay's key>:<its invited admission key>@<where it is reached>
//! kotton-invite:vault:<the vault's key>:<three-spoken-words>:<its meeting relay's key>[:<that relay's invited admission key>]@<where that relay is reached>
//! ```
//!
//! Every code says, in its first word, what its holder becomes: nothing (an
//! instance's *line*) or a member (an *invite*). Then the kind, the whole key,
//! what the holder becomes there, and last a hint — last so whatever it
//! contains is read as it, and never compared to decide what anything is: the
//! key is.
//!
//! **The line confers nothing, so it is no secret.** An instance is created for
//! its operator's public key (V18), and the key that operates it was the
//! person's before the instance existed. The line says which kind of instance
//! it is, which key to expect there, and where it says it is reached. It can be
//! printed to a journal, a log, a provider's answer, anywhere.
//!
//! **An invite is a bearer at member level** (RFC-0084, *The invite is not
//! changed here*). A relay's carries the *invited* admission key its operator's
//! rule reads; a vault's carries the three words its ceremony meets under
//! (DEC-0068), the vault's key the admitting device pins, and its meeting
//! relay's key, which the admitting device holds the relay to before it dials;
//! and, when the vault holds one, that relay's *invited* admission key, which the
//! admitting device presents on the ceremony's one dial — so the invite that
//! admits a person to the vault also admits their first contact at a relay whose
//! rule is *the people I invite*
//! (`TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`).
//! The six digits stay the standing check on a vault's ceremony.
//!
//! One printer ([`Code::to_text`]) and one parser ([`Code::parse`]), held to
//! each other by the golden codes below; [`InstanceLine`] and [`InviteCode`]
//! read and print through them. The module exports the codes, their printer,
//! their parser and their prefixes, and nothing else
//! (`the_code_module_exports_the_codes_and_nothing_else`).

use crate::ipc::OperatedService;

/// A line's first word: the holder becomes nothing.
pub const LINE_PREFIX: &str = "kotton-instance";

/// An invite's first word: the holder becomes a member.
pub const INVITE_PREFIX: &str = "kotton-invite";

/// How many spoken words a vault's invite carries (DEC-0068, RFC-0022's code).
const WORDS: usize = 3;

/// An instance's line: its kind, the address it announces, and its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceLine {
    pub kind: OperatedService,
    /// Where the instance is reached: a relay's URL, a vault's address and
    /// peer port. A hint; empty when the instance announces none.
    pub hint: String,
    /// The instance's public key.
    pub key: [u8; 32],
}

/// An invite: what an operator hands a person to make them a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteCode {
    /// A relay's: stand there holding the key its rule reads for the people
    /// its operator invites.
    Relay {
        /// The relay's key.
        key: [u8; 32],
        /// Where the relay is reached, its URL.
        hint: String,
        /// The *invited* admission key, 32 bytes.
        invited: [u8; 32],
    },
    /// A vault's: meet it at its relay under three words, and keep your things
    /// there.
    Vault {
        /// The vault's key, which the admitting device pins.
        key: [u8; 32],
        /// The three spoken words, lowercase, joined by `-`.
        words: String,
        /// The key of the relay the vault meets its tenant at.
        relay_key: [u8; 32],
        /// Where that relay is reached, its URL.
        relay_hint: String,
        /// That relay's *invited* admission key, 32 bytes, when the vault
        /// minting the invite holds one to hand on: what the admitting device
        /// presents on the ceremony's dial. Absent when the vault holds none —
        /// a relay that reads no key, or a vault told none.
        invited: Option<[u8; 32]>,
    },
}

/// A code: a line or an invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Code {
    Line(InstanceLine),
    Invite(InviteCode),
}

impl Code {
    /// The code as it is printed.
    pub fn to_text(&self) -> String {
        let (prefix, kind, fields, hint) = match self {
            Code::Line(l) => (LINE_PREFIX, l.kind, vec![hex::encode(l.key)], l.hint.as_str()),
            Code::Invite(InviteCode::Relay { key, hint, invited }) => {
                (INVITE_PREFIX, OperatedService::Relay, vec![hex::encode(key), hex::encode(invited)], hint.as_str())
            }
            Code::Invite(InviteCode::Vault { key, words, relay_key, relay_hint, invited }) => (
                INVITE_PREFIX,
                OperatedService::Vault,
                [hex::encode(key), words.clone(), hex::encode(relay_key)]
                    .into_iter()
                    .chain(invited.map(hex::encode))
                    .collect(),
                relay_hint.as_str(),
            ),
        };
        format!("{prefix}:{}:{}@{hint}", kind.word(), fields.join(":"))
    }

    /// Read a pasted code. Whitespace around it is a paste's and is dropped.
    pub fn parse(text: &str) -> Result<Self, String> {
        let not = || {
            format!(
                "this is not a code Kotton reads — a line reads `{LINE_PREFIX}:<relay|vault>:<key>@<address>`, \
                 an invite `{INVITE_PREFIX}:<relay|vault>:<key>:…@<address>`, as it was given"
            )
        };
        let cut = |what: &str| format!("{what} is 64 hex characters — was the code cut short?");
        let text = text.trim();
        let (head, hint) = text.split_once('@').ok_or_else(not)?;
        if hint.chars().any(char::is_whitespace) {
            return Err(not());
        }
        let hint = hint.to_string();
        let mut parts = head.split(':');
        let prefix = parts.next();
        let kind = match parts.next() {
            Some("relay") => OperatedService::Relay,
            Some("vault") => OperatedService::Vault,
            _ => return Err(not()),
        };
        let fields: Vec<&str> = parts.collect();
        match (prefix, kind, fields.as_slice()) {
            (Some(LINE_PREFIX), kind, [key]) => {
                let key = key32(key).ok_or_else(|| cut("an instance's key"))?;
                Ok(Code::Line(InstanceLine { kind, hint, key }))
            }
            (Some(LINE_PREFIX), ..) => Err(not()),
            (Some(INVITE_PREFIX), OperatedService::Relay, [key, invited]) => Ok(Code::Invite(InviteCode::Relay {
                key: key32(key).ok_or_else(|| cut("a relay's key"))?,
                hint,
                invited: key32(invited).ok_or_else(|| cut("an invite's admission key"))?,
            })),
            (Some(INVITE_PREFIX), OperatedService::Vault, [key, words, relay_key, invited @ ..]) if invited.len() <= 1 => {
                let key = key32(key).ok_or_else(|| cut("a vault's key"))?;
                if !spoken(words) {
                    return Err(format!(
                        "an invite's words are {WORDS} spoken words joined by `-` — was the code cut short?"
                    ));
                }
                Ok(Code::Invite(InviteCode::Vault {
                    key,
                    words: (*words).to_string(),
                    relay_key: key32(relay_key).ok_or_else(|| cut("the meeting relay's key"))?,
                    relay_hint: hint,
                    invited: match invited {
                        [invited] => Some(key32(invited).ok_or_else(|| cut("an invite's admission key"))?),
                        _ => None,
                    },
                }))
            }
            _ => Err(not()),
        }
    }
}

/// 32 bytes as 64 hex, or `None`.
fn key32(text: &str) -> Option<[u8; 32]> {
    (text.len() == 64).then(|| hex::decode(text).ok()).flatten()?.try_into().ok()
}

/// Whether `words` is the spoken words as a code carries them: lowercase,
/// joined by `-`, and [`WORDS`] of them.
fn spoken(words: &str) -> bool {
    let parts: Vec<&str> = words.split('-').collect();
    parts.len() == WORDS && parts.iter().all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
}

impl InstanceLine {
    /// The line an instance prints.
    pub fn to_text(&self) -> String {
        Code::Line(self.clone()).to_text()
    }

    /// Read a pasted line. An invite is a code, and not a line.
    pub fn parse(text: &str) -> Result<Self, String> {
        match Code::parse(text)? {
            Code::Line(line) => Ok(line),
            Code::Invite(_) => Err("this is an invite, not an instance's line: it is admitted, not enrolled".into()),
        }
    }

    /// Read pasted lines, each on its own, in the order given — the one parser
    /// for `enrol <line> <line>…` at the terminal and for a block pasted one
    /// line per row (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`).
    /// A line holds no whitespace, so any run of it — a space, a row's end —
    /// is between two lines, and either way of giving them reads the same.
    /// Each is what was given and what it reads as: one that is no line is
    /// said, and the rest are read all the same.
    pub fn block(text: &str) -> Vec<(String, Result<Self, String>)> {
        text.split_whitespace().map(|given| (given.to_string(), Self::parse(given))).collect()
    }
}

impl InviteCode {
    /// The invite as it is printed and handed over.
    pub fn to_text(&self) -> String {
        Code::Invite(self.clone()).to_text()
    }

    /// Read a pasted invite. A line is a code, and not an invite.
    pub fn parse(text: &str) -> Result<Self, String> {
        match Code::parse(text)? {
            Code::Invite(invite) => Ok(invite),
            Code::Line(_) => Err("this is an instance's line, not an invite: it is enrolled, not admitted".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden line: the printer writes it, and the parser reads it back
    /// field for field. A hint with `@` and `:` in it stays the hint.
    #[test]
    fn an_instances_line_is_one_line_and_reads_back() {
        let line = InstanceLine {
            kind: OperatedService::Relay,
            hint: "http://relay.example:7700".into(),
            key: [0xab; 32],
        };
        let text = line.to_text();
        assert_eq!(
            text,
            format!("kotton-instance:relay:{}@http://relay.example:7700", "ab".repeat(32))
        );
        assert_eq!(InstanceLine::parse(&format!("  {text}\n")).unwrap(), line);
        let odd = InstanceLine { hint: "x@y:1".into(), kind: OperatedService::Vault, ..line.clone() };
        assert_eq!(InstanceLine::parse(&odd.to_text()).unwrap(), odd);
        let bare = InstanceLine { hint: String::new(), ..line };
        assert_eq!(InstanceLine::parse(&bare.to_text()).unwrap(), bare, "a line with no hint");
    }

    /// **One parser for lines given space-separated and one per row**
    /// (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`,
    /// Done-when (1)): the terminal's `enrol a b` and a block pasted as `a⏎b`
    /// read as the same lines, in the same order; a word that is no line is
    /// said beside them and does not stop them; nothing given is nothing read.
    #[test]
    fn lines_given_on_one_row_or_one_per_row_read_the_same() {
        let relay = InstanceLine { kind: OperatedService::Relay, hint: "http://203.0.113.9:7700".into(), key: [5; 32] };
        let vault = InstanceLine { kind: OperatedService::Vault, hint: "203.0.113.9:7710".into(), key: [7; 32] };
        let (r, v) = (relay.to_text(), vault.to_text());
        let read = |text: &str| -> Vec<(String, Result<InstanceLine, String>)> { InstanceLine::block(text) };
        let spaced = read(&format!("{v} {r}"));
        assert_eq!(spaced, vec![(v.clone(), Ok(vault.clone())), (r.clone(), Ok(relay.clone()))]);
        assert_eq!(read(&format!("{v}\n{r}\n")), spaced, "one per row");
        assert_eq!(read(&format!("  {v}\r\n\t{r}  ")), spaced, "a paste's own whitespace");
        let with_a_word = read(&format!("kotton {v}"));
        assert_eq!(with_a_word.len(), 2);
        assert!(with_a_word[0].1.is_err() && with_a_word[0].0 == "kotton", "{with_a_word:?}");
        assert_eq!(with_a_word[1], (v.clone(), Ok(vault)));
        assert!(read(" \n ").is_empty());
    }

    /// **The golden invites, one of each kind, beside the line** — the same
    /// printer writes them and the same parser reads them back field for field
    /// (`TASK-an-invite-is-the-codes-other-clause-and-its-relay-is-offered`,
    /// Done-when (1)). A relay's carries its key, hint and *invited* admission
    /// key; a vault's its key, its words, and its meeting relay's key and hint.
    #[test]
    fn an_invite_is_the_codes_other_clause_and_reads_back() {
        let relay = InviteCode::Relay { key: [0xab; 32], hint: "http://relay.example:7700".into(), invited: [0x01; 32] };
        let text = relay.to_text();
        assert_eq!(
            text,
            format!("kotton-invite:relay:{}:{}@http://relay.example:7700", "ab".repeat(32), "01".repeat(32))
        );
        assert_eq!(InviteCode::parse(&format!("  {text}\n")).unwrap(), relay);
        assert_eq!(Code::parse(&text).unwrap(), Code::Invite(relay));

        let vault = InviteCode::Vault {
            key: [0xcd; 32],
            words: "fame-cheap-unfold".into(),
            relay_key: [0xab; 32],
            relay_hint: "http://relay.example:7700".into(),
            invited: None,
        };
        let text = vault.to_text();
        assert_eq!(
            text,
            format!(
                "kotton-invite:vault:{}:fame-cheap-unfold:{}@http://relay.example:7700",
                "cd".repeat(32),
                "ab".repeat(32)
            )
        );
        assert_eq!(InviteCode::parse(&text).unwrap(), vault);
        assert_eq!(Code::parse(&text).unwrap(), Code::Invite(vault.clone()));

        // A vault's invite carrying its meeting relay's invited key, after that
        // relay's key and before the hint
        // (`TASK-a-first-contact-ceremony-meets-at-a-relay-whose-rule-refuses-a-stranger`).
        let InviteCode::Vault { key, words, relay_key, relay_hint, .. } = vault else { unreachable!() };
        let carrying = InviteCode::Vault { key, words, relay_key, relay_hint, invited: Some([0x01; 32]) };
        let text = carrying.to_text();
        assert_eq!(
            text,
            format!(
                "kotton-invite:vault:{}:fame-cheap-unfold:{}:{}@http://relay.example:7700",
                "cd".repeat(32),
                "ab".repeat(32),
                "01".repeat(32)
            )
        );
        assert_eq!(InviteCode::parse(&text).unwrap(), carrying);
        assert_eq!(Code::parse(&text).unwrap(), Code::Invite(carrying));

        // The two clauses are told apart by their first word, and each refuses
        // the other's.
        let line = InstanceLine { kind: OperatedService::Relay, hint: "http://relay.example:7700".into(), key: [0xab; 32] };
        assert!(InviteCode::parse(&line.to_text()).unwrap_err().contains("enrolled, not admitted"));
        assert!(InstanceLine::parse(&text).unwrap_err().contains("admitted, not enrolled"));
    }

    #[test]
    fn a_text_that_is_not_a_line_is_refused() {
        let good = InstanceLine {
            kind: OperatedService::Vault,
            hint: "vault.example:7710".into(),
            key: [7; 32],
        }
        .to_text();
        for bad in [
            "",
            "kotton-instance:vault",
            &good.replace("kotton-instance", "kotton-invite"),
            &good.replace(":vault:", ":box:"),
            &good.replacen(&"07".repeat(32), &"07".repeat(31), 1),
            &good.replacen('@', &format!(":{}@", "01".repeat(16)), 1),
            &format!("{good} and more"),
        ] {
            assert!(InstanceLine::parse(bad).is_err(), "read {bad:?}");
        }
    }

    /// An invite cut short, with a word too few, a key too short (the invited
    /// key's too), a field too many, an address with a space in it, or the old
    /// `relay#words` is no invite.
    #[test]
    fn a_text_that_is_not_an_invite_is_refused() {
        let vault = InviteCode::Vault {
            key: [7; 32],
            words: "fame-cheap-unfold".into(),
            relay_key: [8; 32],
            relay_hint: "http://relay.example:7700".into(),
            invited: Some([6; 32]),
        }
        .to_text();
        let relay = InviteCode::Relay { key: [7; 32], hint: "http://relay.example:7700".into(), invited: [9; 32] }.to_text();
        for bad in [
            "http://relay.example:7700#fame-cheap-unfold",
            &vault.replace("fame-cheap-unfold", "fame-cheap"),
            &vault.replace("fame-cheap-unfold", "Fame-Cheap-Unfold"),
            &vault.replacen(&"08".repeat(32), &"08".repeat(31), 1),
            &vault.replacen(&"06".repeat(32), &"06".repeat(31), 1),
            &vault.replacen('@', &format!(":{}@", "05".repeat(32)), 1),
            &vault.replace(":vault:", ":relay:"),
            &relay.replacen(&"09".repeat(32), &"09".repeat(31), 1),
            &relay.replace(":relay:", ":vault:"),
            &format!("{relay} and more"),
        ] {
            assert!(InviteCode::parse(bad).is_err(), "read {bad:?}");
        }
    }

    /// **The module exports the codes, their printer, their parser and their
    /// prefixes, and nothing else `pub`** — no secret, no seal, no lifetime, no
    /// refusal (unit 1's Done-when (1)(g), with the invite beside the line).
    /// Read from this file's own source, so an item added `pub` here fails this
    /// test until the list says it.
    #[test]
    fn the_code_module_exports_the_codes_and_nothing_else() {
        let source = include_str!("line.rs");
        let body = source.split("#[cfg(test)]").next().unwrap();
        let public: Vec<&str> = body
            .lines()
            .map(str::trim_start)
            .filter(|l| l.starts_with("pub ") || l.starts_with("pub("))
            .map(|l| {
                let mut words = l.trim_start_matches("pub ").split_whitespace();
                let first = words.next().unwrap_or("");
                let name = match first {
                    "const" | "static" | "struct" | "enum" | "fn" | "mod" | "use" | "type" | "trait" => {
                        words.next().unwrap_or("")
                    }
                    field => field,
                };
                name.split(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap()
            })
            .collect();
        assert_eq!(
            public,
            [
                "LINE_PREFIX", "INVITE_PREFIX", "InstanceLine", "kind", "hint", "key", "InviteCode", "Code", "to_text",
                "parse", "to_text", "parse", "block", "to_text", "parse"
            ]
        );
    }
}
