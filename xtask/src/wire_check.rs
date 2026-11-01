// SPDX-License-Identifier: AGPL-3.0-or-later
//! `wire-check`: the JSON surface of the IPC request enum, pinned to a golden file.
//!
//! ## Why this exists
//!
//! [`RFC-0080`]'s last criterion splits `UserRequest` into per-domain enums. The
//! enum derives `Serialize`/`Deserialize` with no container attribute, so it is
//! externally tagged: the variant name **is** the JSON key, and the field names
//! **are** the object's keys. Nesting domain enums inside it preserves that only
//! under `#[serde(untagged)]` — which is a container attribute, so it applies to
//! every variant or none.
//!
//! That makes the flip **atomic across all fifteen domains**: measured
//! 2026-08-23, a partially split enum serializes an unsplit `ReadFile { path }`
//! as `{"path":"/x"}` with the variant name gone, and legacy JSON stops
//! deserializing entirely.
//!
//! One commit that touches 151 variants is not reviewable by reading it. It is
//! checkable by *measuring* it, and this is the instrument: the wire surface is
//! recorded here before the move, and must be identical after. A reviewer reads
//! the diff of this file — which should be empty — rather than 151 relocated
//! arms.
//!
//! ## What it compares
//!
//! For every variant: its name, and in declaration order every field's name,
//! type, and `#[serde(...)]` attributes. All three change the bytes on the wire.
//! `skip_serializing_if` and `with = "crate::base64_bytes"` are as load-bearing
//! as the field name, and are the half a name-only check would miss.
//!
//! Variants are sorted by name so that regrouping them into fifteen enums is not
//! itself a diff. Fields are **not** sorted: serde emits them in declaration
//! order, so their order is part of the wire.
//!
//! ## After the split
//!
//! `SOURCES` grows from one entry to fifteen — the per-domain enums — and the
//! golden file does not change at all. That is the whole point: this file is the
//! evidence that the move was a move.
//!
//! ## The twin rule, between the recordings
//!
//! Two peer wires mirror the door. A device sends the sealed, recovery and relay
//! verbs as `UserRequest` to both kuserd's `PeerRequest` decoder and kvaultd's
//! `VaultPeerRequest` decoder, and that works only because each peer wire spells
//! those verbs byte for byte as the door does. Pinning each surface to its own
//! recording does not hold that: a field renamed on `UserRequest::ReadSealed`
//! fails this check once, passes after `cargo xtask wire-surface` re-records
//! `wire-surface.txt`, and is then refused at every vault and every device.
//!
//! So [`twin_report`] reads the three recorded files as text, with no
//! compile, beside each channel's own comparison, and every variant named in
//! `peer-request-surface.txt` or `vault-peer-request-surface.txt` must have a
//! block in `wire-surface.txt` identical to its own, line for line. Re-recording
//! one side of a twin alone is a finding naming the variant and both files.
//!
//! The type-level proof stays where the types are: `kotton-wire`'s
//! `each_peer_verb_records_the_fields_of_its_door_twin` and
//! `each_vault_verb_records_the_fields_of_its_door_twin` hold the same fact,
//! and the mirror tests beside them hold that the door's bytes decode and
//! re-encode on each peer wire. This rule holds the same fact in the gate
//! `just lint` runs, which does not run those tests.
//!
//! The rule reads text, so it holds the reader to the printer: each recording's
//! `# variants: N` header, which [`render`] writes, must equal the number of
//! variants [`recorded_surface::read`] parses back, and both indent with
//! [`INDENT`]. A printer change the reader does not follow is a finding, not a
//! rule that quietly compares the wrong lines. A differing block is listed as a
//! line diff, by each line's own number in its file, each line printed raw
//! between `|` marks, so a dropped repeated attribute is named as the missing
//! line, a whitespace-only difference is visible, and a line both blocks hold
//! at different places is printed once as moved.
//!
//! ## One reader of the format
//!
//! [`render`] is the one printer of a recording and
//! `core/wire/src/recorded_surface.rs` is the one reader, compiled here by
//! `#[path]` as [`recorded_surface`] and in kotton-wire for the tests that read
//! the recordings. Every reader is therefore held to the `# variants: N` header
//! in one place. A crate dependency on kotton-wire was the other seam and is
//! not taken: it would build kotton-wire's closure into every `cargo xtask`,
//! and this check reads the wire as text so that it needs no compile of the
//! crate it checks. The reader names nothing but `std`, which is what lets both
//! crates compile it (kotton #297).
//!
//! ## The channel diff
//!
//! When a channel's recording and its source disagree, [`channel_diff`] lists
//! the differing lines through the same positional [`line_diff`] the twin rule
//! uses, by line number on each side and raw between `|` marks, so a dropped
//! repeated `#[serde(...)]` line is printed as the one missing line rather than
//! as no line at all (kotton #296).
//!
//! `cargo xtask wire-surface` re-records every channel and then prints the
//! rule's findings, exiting 0: a change to the door and both peer types is
//! re-recorded in one command, and a door-only re-record is told in that same
//! command that the next `wire-check` fails.
//!
//! Both text rules, this one and the kotton-wire tests, hold a naming agreement
//! between three types. The type-level seam past both is a shared sealed-verbs
//! sub-type on the sender side (#254): one type for the six verbs both peer
//! wires share. Once it lands, the twin rule holds the recordings and the type
//! holds the sender; while each peer wire is its own flat enum, the recordings
//! still restate those verbs, and this rule is what holds the restatement in the
//! gate.
//!
//! ## The answer rule, between the docs and the response recording
//!
//! A verb's doc says what it is answered with ("Answered with `Drives`"), and the
//! answer's doc says which verbs it answers ("Answer to `DriveCreate`, `DriveList` and
//! `DriveShow`"). Nothing compiles either, so they drift: a move that came to answer
//! `DriveMoved` kept a doc saying `Drives` until a reviewer read it (kotton #341).
//! `Drives` is still a recorded answer, so a rule that only asked whether the name is
//! recorded would pass that drift; the rule holds the two docs to each other.
//!
//! [`answer_report`] reads every doc comment (`///`, `//!`) under [`ANSWER_DOCS`] with
//! one reader, [`doc_blocks`]: each block's lines are joined so a phrase wrapped onto
//! the next doc line reads as one, and a block on a variant of a top-level `pub enum`
//! knows its item as `Enum::Variant`.
//!
//! - **A verb's claim.** "Answered with" (any case) and the list opening at the first
//!   backticked span after it in the same clause, or "Answered" and a list opening right
//!   after it. A list's spans are joined by `,`, "and", "or" or "then", so a verb with
//!   several answers says so in one claim ("Answered with `AppRole` or `AppNotFound`",
//!   "Answered with `VfsWatchReady`, then `VfsChanged`, then `VfsWatchEnd`" for a
//!   stream); each name in it is a claim. A name is a `UserResponse` path or a bare
//!   name, alone or as a struct literal (`Decrypted { plaintext }`). Prose ("Answered
//!   with what the service answered.") reaches a `.`, `,`, `;` or `:` before any
//!   backtick and is not a claim, and a span that is not a name (`kvaultd tenants`) or
//!   names another enum's variant (`DeviceResponse::AppRole`) is not one either.
//! - **An answer's list.** "Answer to" on a `UserResponse` variant in
//!   [`RESPONSE_SOURCE`], then the backticked verbs, joined the same way. A bare verb is
//!   a `UserRequest` verb; `VaultRequest::Tenants` and `UserRequest::Tenants` are two
//!   verbs, and an answer to both names both.
//!
//! **One form per side, keyed on what a span names.** The tree also stated the claim as
//! "Returns `UserResponse::AppGrants`" (as a link), "always returned as `ChannelKeyGrantCreated {
//! grant }`" and "Streaming: opens with" on verbs, and "Response to `OrgFrostNew`",
//! "Returned by `SyncAwait`", "the reply to `DeviceName`" and "Result of `AppVerify`" on
//! answers. A reader of one form passes every other form unread, so a drifted doc could
//! hide behind a synonym (kotton #369), and a list of words cannot close that: the next
//! doc finds the next word. What made a check necessary was a second way of stating the
//! claim, so the rule takes away every other way rather than learning them.
//! [`stray_spans`] keys on the span, not on the words around it ([`Kind::Spelling`]):
//!
//! - in a verb's doc (a variant of an enum named `…Request`, or `OperatorVerb`), a span
//!   naming a `UserResponse` variant by path (`UserResponse::X`, any prefix, link
//!   brackets or not), or a bare recorded answer written as a struct literal
//!   (`SyncStarted { job_id }`), that is not in the doc's "Answered with" list;
//! - in a `UserResponse` variant's doc in [`RESPONSE_SOURCE`], a span naming a verb (a
//!   bare variant of [`DOOR_RECORDING`], or a `…Request::`/`OperatorVerb::` path) that is
//!   not in the doc's "Answer to" list.
//!
//! Each is refused, naming the line and the one form. A mention that is a
//! cross-reference and not the claim has one escape, which the writer spells out: the
//! word "see" before it, and the list it opens ("(see `DeviceAdd` and `DeviceJoin`)").
//! The tree had such mentions (`NotInScope`'s "declared at `Authenticate` time",
//! `PairShowCode`'s "via `PairConfirmCode { token, matches }`"), so the escape is needed;
//! one word a reviewer reads is the cost of it.
//!
//! **What it does not hold.** A bare answer name without a struct literal in a verb's doc
//! ("Answers `ChannelSent`", a stream drawn as "`PairAdvertising` → `PairShowCode`"),
//! since `Ok`, `Status` and `OrgList` are words, verbs and answers at once; docs that are
//! on neither a verb nor a `UserResponse` variant (a struct's, a pairing payload's, like
//! `PairingPayload::BlindRelay`'s "returns `UserResponse::Error { message }`"); and the
//! other response enums (below). The bare-name residue is kotton #385.
//!
//! Each claimed name must be a variant in [`RESPONSE_RECORDING`], read through
//! [`recorded_surface::read`], the one reader ([`Kind::Answer`]). A verb claiming `X`
//! must be in `X`'s list, and each verb in `X`'s list must claim `X`
//! ([`Kind::Pair`]). Every finding names the file and line on each side.
//!
//! **Both sides are required only where one is written.** A claim whose other side is
//! missing is [`Kind::Unwritten`], but a verb and an answer with neither doc are not a
//! finding: the tree writes few lists (28 "Answer to" docs over 192 answers when this
//! rule landed, 24 of them written before it), and asking for every pair at once would
//! be a wall of findings no one change can clear. A pair joins the rule when either side is written. The generic
//! answers in [`GENERIC_ANSWERS`] (`Ok`) need no list, since one would grow with every
//! verb that answers with it and be the doc most likely to drift; a claim of `Ok` is
//! still held to the recording.
//!
//! **Two docs, not the handler.** The rule holds the two docs to each other, not to the
//! code that answers, so a change that edits both wrongly passes. A handler-derived map was
//! weighed and not built (kotton #369). The arms are not where a reader would want them:
//! `UserRequest` is dispatched in `core/kuserd/src/agent/dispatch.rs`, and most arms call a
//! function in a domain crate (`kotton_org::daemon::frost_orgs::org_frost_new`,
//! `kotton_app::daemon::apps::app_get_role`) returning `io::Result<UserResponse>`, often
//! more than one variant (`AppRole` or `AppNotFound`, and `Error` everywhere). Deriving the
//! map by text means following calls across a dozen crates; deriving it from types means a
//! parser in `xtask` and a cold build it does not pay today. The two-doc rule is enough
//! for now because the drift it was built for (#341) is one doc moved and the other not,
//! and a drift in both needs two wrong edits in two files in one change, both in front of
//! a reviewer. What would change that: a drift found with both docs agreeing and the
//! handler not, or a per-verb answer type (a domain split whose handlers return their own
//! answer enum), at which point the compiler holds the pair and this rule can retire
//! rather than grow. The handler-derived check is kotton #382, with that design.
//!
//! **One answer type of five.** `core/wire/src` declares five response enums:
//! `KuidResponse` (`kuid_ipc.rs`), `ContactResponse` (`ipc/contact_request.rs`),
//! `DeviceResponse` (`sys_ipc.rs`), `RelayOperatorResponse` (`rendezvous.rs`) and
//! `UserResponse` (`ipc/response.rs`). The rule reads `UserResponse` alone: every claim
//! is held to `response-surface.txt`, and only `UserResponse`'s "Answer to" lists are
//! read. A bare claimed name that is not a `UserResponse` variant is a finding, and
//! another enum's path is not read as a claim. Holding another enum
//! needs its recording (`RelayOperatorResponse` shares `relay-operator-surface.txt`
//! with its request; the other three have none) and its lists read here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The one reader of a recorded surface, compiled here from kotton-wire's source rather
/// than linked: see that file's module doc, and "One reader of the format" above.
#[path = "../../core/wire/src/recorded_surface.rs"]
mod recorded_surface;

use recorded_surface::{Block, INDENT};

/// The enums making up the **user channel's** wire surface.
///
/// Scoped to one channel deliberately (RFC-0082): each channel owns its own
/// wire, and `KuidRequest` is pinned by its own round-trip tests beside the type.
///
/// One entry today. After RFC-0080 criterion 7 this is the fifteen per-domain
/// enums and `wire-surface.txt` is expected **byte-identical** — a split within
/// a channel must not move a byte.
///
/// A variant *leaving* for another channel is the opposite case and should show
/// as a diff: it is a deliberate change to what this channel accepts, and the
/// diff is how it gets reviewed. The four compositor variants left this way on
/// 2026-08-23.
const SOURCES: &[(&str, &str)] = &[("core/wire/src/ipc/request.rs", "UserRequest")];

/// Where the recorded surface lives — beside the type it describes.
const GOLDEN: &str = "core/wire/wire-surface.txt";

/// A channel pinned by this check: the enums on its wire and the golden file
/// that records them. Each channel owns its own wire (RFC-0082), so each has its
/// own file and a change to one is never read as a change to another.
struct Channel {
    what: &'static str,
    sources: &'static [(&'static str, &'static str)],
    golden: &'static str,
}

/// Every channel pinned. The user channel is the first; the second is what a
/// relay's operator says to it and the rule it sets
/// (`TASK-a-relays-admission-rule-is-set-by-its-operator-over-the-wire`) — the
/// relay is its own binary on its own host, so a desktop and a relay of different
/// releases meet on this wire, and a renamed variant is a relay that no longer
/// understands its operator.
const CHANNELS: &[Channel] = &[
    Channel {
        what: "IPC request",
        sources: SOURCES,
        golden: GOLDEN,
    },
    Channel {
        what: "relay operator",
        sources: &[
            ("core/wire/src/rendezvous.rs", "RelayOperatorRequest"),
            ("core/wire/src/rendezvous.rs", "RelayOperatorResponse"),
            ("core/wire/src/rendezvous.rs", "AdmissionRule"),
        ],
        golden: "core/wire/relay-operator-surface.txt",
    },
    // `OperatorVerb` rides inside `UserRequest::AsOperator`: what a desktop may
    // say under an instance's operator credential. It was unpinned until it gained
    // `ReadRule` and `SetRule`
    // (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`).
    // A channel of its own because its names repeat `UserRequest`'s
    // (`SetQuota`), which one channel's untagged surface must not.
    Channel {
        what: "operator verb",
        sources: &[("core/wire/src/ipc/vault_request.rs", "OperatorVerb")],
        golden: "core/wire/operator-verb-surface.txt",
    },
    // What a paired peer may ask a device's daemon on its own standing: the
    // type `kuserd`'s peer acceptor decodes (kotton #231). A channel of its own
    // because its names repeat `UserRequest`'s byte for byte, which is the
    // point: a device's client and a gateway send the door's spelling, and
    // `PeerRequest`'s tests hold the mirror against `wire-surface.txt`. A verb
    // joining this file is a verb a peer can newly say.
    Channel {
        what: "peer request",
        sources: &[("core/wire/src/ipc/peer_request.rs", "PeerRequest")],
        golden: "core/wire/peer-request-surface.txt",
    },
    // What a tenant's device, or the vault's operator key, may ask a vault on
    // the peer transport: the type `kvaultd`'s peer acceptor decodes (kotton
    // #239). A channel of its own for the reason the peer request has one:
    // its names repeat `UserRequest`'s byte for byte, and
    // `VaultPeerRequest`'s tests hold the mirror against `wire-surface.txt`.
    // A verb joining this file is a verb a vault can newly be asked.
    Channel {
        what: "vault peer request",
        sources: &[("core/wire/src/ipc/vault_peer_request.rs", "VaultPeerRequest")],
        golden: "core/wire/vault-peer-request-surface.txt",
    },
    // What the daemon answers on the user channel. Its bytes reach the CLI,
    // the shell and the gateways, and its fields are held to the same rule as
    // the requests' by `secret_debug_tests` (`core/wire/src/ipc/request.rs`):
    // one named for a secret prints `<redacted>`. That test reads this file,
    // so an answer that grows a secret field is caught where a request is.
    Channel {
        what: "IPC response",
        sources: &[("core/wire/src/ipc/response.rs", "UserResponse")],
        golden: RESPONSE_RECORDING,
    },
];

/// A field, in declaration order, with everything about it that reaches the wire.
pub struct Field {
    pub attrs: Vec<String>,
    pub name: String,
    pub ty: String,
}

pub struct Variant {
    pub name: String,
    pub fields: Vec<Field>,
}

/// Same parse, for callers that need the variants rather than the surface.
///
/// `remote-request` generates from this so the two cannot disagree about what a
/// variant's fields are.
pub fn parse_enum_public(src: &str, enum_name: &str) -> Vec<Variant> {
    parse_enum(src, enum_name)
}

pub fn wire_check(bless: bool) {
    if bless {
        for channel in CHANNELS {
            check_channel(channel, true);
        }
        // Reporting only: a change to the door and both peer types is
        // re-recorded by this one command, so the rule cannot refuse it here.
        // A door-only re-record is told now rather than at the next check.
        let findings = twin_report(Path::new("."));
        if findings.is_empty() {
            println!(
                "wire-surface: every verb in {} and {} records its door twin's block in \
                 {DOOR_RECORDING}.",
                TWIN_RECORDINGS[0], TWIN_RECORDINGS[1]
            );
        } else {
            print_twin_findings("wire-surface", &findings);
            eprintln!(
                "wire-surface wrote every recording and exits 0, but the next \
                 `cargo xtask wire-check` fails until the peer recordings agree with the door's: \
                 change the peer type (or the door's variant) to match and re-record with \
                 `cargo xtask wire-surface` again."
            );
        }
        // Reporting only, as the twin rule is: a response variant renamed and
        // re-recorded here is told now that a doc still names the old answer.
        let answers = answer_report(Path::new("."));
        if answers.findings.is_empty() {
            println!("{}", answers_ok("wire-surface", &answers));
        } else {
            eprint!("{}", answer_findings_text("wire-surface", &answers.findings));
            eprintln!(
                "wire-surface wrote every recording and exits 0, but the next \
                 `cargo xtask wire-check` fails until each doc above names an answer the \
                 daemon gives."
            );
        }
        return;
    }
    // The twin rule and the answer rule read only text, so they run first: a
    // recording edited by hand fails its channel below and is named here as well.
    let findings = twin_report(Path::new("."));
    if !findings.is_empty() {
        print_twin_findings("wire-check", &findings);
    }
    let answers = answer_report(Path::new("."));
    if !answers.findings.is_empty() {
        eprint!("{}", answer_findings_text("wire-check", &answers.findings));
    }
    for channel in CHANNELS {
        check_channel(channel, false);
    }
    if !findings.is_empty() || !answers.findings.is_empty() {
        std::process::exit(1);
    }
    println!(
        "wire-check: OK — every verb in {} and {} records its door twin's block in {DOOR_RECORDING}.",
        TWIN_RECORDINGS[0], TWIN_RECORDINGS[1]
    );
    println!("{}", answers_ok("wire-check", &answers));
}

/// The line a command prints when every answer a doc names is a recorded variant and
/// every pair of docs agrees.
fn answers_ok(command: &str, report: &AnswerReport) -> String {
    format!(
        "{command}: OK — each of the {} \"Answered with `X`\" docs under {ANSWER_DOCS} names a \
         variant in {RESPONSE_RECORDING}, and each of the {} verbs an \"Answer to\" doc in \
         {RESPONSE_SOURCE} names says it is answered with that variant; no doc spells either \
         side another way.",
        report.claims, report.answered_verbs
    )
}

/// The recording of what the daemon answers on the user channel: the names a doc's
/// "Answered with `X`" may give.
const RESPONSE_RECORDING: &str = "core/wire/response-surface.txt";

/// The source of those answers. Each variant's doc says which verbs it answers
/// ("Answer to `DriveMove`"), and the rule holds that list against the verbs' own docs.
const RESPONSE_SOURCE: &str = "core/wire/src/ipc/response.rs";

/// The one answer type the rule holds. A second answer type (the relay operator's,
/// say) would need its own recording and its own "Answer to" docs held here.
const RESPONSE_ENUM: &str = "UserResponse";

/// The request enum a verb named bare in an "Answer to" doc belongs to.
const BARE_VERB_ENUM: &str = "UserRequest";

/// Answers many verbs give, which need no "Answer to" list: such a list would grow with
/// every verb that answers with it, and would be the doc most likely to drift. A verb
/// naming one is still held to the recording, and one that is given a list is held to it.
const GENERIC_ANSWERS: &[&str] = &["Ok"];

/// The tree whose doc comments the answer rule reads.
const ANSWER_DOCS: &str = "core/wire/src";

/// One doc comment block: its lines trimmed and joined by one space, where each line's
/// text starts in that string with its 1-based file line, and the enum variant it
/// documents as `Enum::Variant`, when it documents one.
#[derive(Debug)]
struct DocBlock {
    text: String,
    starts: Vec<(usize, usize)>,
    item: Option<String>,
}

impl DocBlock {
    /// The file line the joined text's byte `offset` came from.
    fn line_of(&self, offset: usize) -> usize {
        self.starts[self.starts.partition_point(|&(s, _)| s <= offset) - 1].1
    }
}

/// The doc comment blocks (`///`, `//!`; not `////`) of `src`, in order. Lines are joined
/// so a phrase wrapped onto the next doc line reads as one. Inside a top-level
/// `pub enum`, a block's item is the next line at the variant indent that is not an
/// attribute or a comment, read as `Enum::Variant` when it starts with a variant name.
fn doc_blocks(src: &str) -> Vec<DocBlock> {
    const VARIANT_INDENT: &str = "    ";
    let mut out = Vec::new();
    let mut open: Option<DocBlock> = None;
    let mut in_enum: Option<&str> = None;
    for (i, line) in src.lines().enumerate() {
        if let Some(rest) = line.strip_prefix("pub enum ") {
            in_enum = rest.split(|c: char| !(c.is_alphanumeric() || c == '_')).next();
        } else if line.starts_with('}') {
            in_enum = None;
        }
        let t = line.trim_start();
        let doc = t
            .strip_prefix("///")
            .or_else(|| t.strip_prefix("//!"))
            .filter(|rest| !rest.starts_with('/'));
        if let Some(rest) = doc {
            let block = open.get_or_insert_with(|| DocBlock {
                text: String::new(),
                starts: Vec::new(),
                item: None,
            });
            if !block.text.is_empty() {
                block.text.push(' ');
            }
            block.starts.push((block.text.len(), i + 1));
            block.text.push_str(rest.trim());
            continue;
        }
        let Some(block) = open.as_mut() else { continue };
        if t.is_empty() || t.starts_with("#[") || t.starts_with("//") {
            continue;
        }
        if let Some(enum_name) = in_enum {
            let indent = line.len() - t.len();
            // A multi-line attribute's continuation sits under the variant, and its close
            // at the variant's indent.
            if indent > VARIANT_INDENT.len()
                || (indent == VARIANT_INDENT.len() && t.starts_with([')', ']']))
            {
                continue;
            }
            if indent == VARIANT_INDENT.len() {
                let name: String =
                    t.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                if is_ident(&name) {
                    block.item = Some(format!("{enum_name}::{name}"));
                }
            }
        }
        out.extend(open.take());
    }
    out.extend(open);
    out
}

/// Each offset in `lower` where `word` starts at a word boundary and a space follows it.
fn word_at(lower: &str, word: &str) -> Vec<usize> {
    lower
        .match_indices(word)
        .map(|(i, _)| i)
        .filter(|&i| {
            let before = lower[..i].chars().next_back();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                && lower[i + word.len()..].starts_with([' ', '\t'])
        })
        .collect()
}

/// The backticked span opening at `text[open]`: its content, and the offset just past
/// its closing backtick.
fn span_at(text: &str, open: usize) -> Option<(&str, usize)> {
    let rest = &text[open + 1..];
    let close = rest.find('`')?;
    Some((&rest[..close], open + 1 + close + 1))
}

/// The offset of the first backtick in `text[from..]`, unless the clause ends first at a
/// `.`, `,`, `;` or `:`: prose with no name in it.
fn first_span_in_clause(text: &str, from: usize) -> Option<usize> {
    let at = from + text[from..].find(['`', '.', ',', ';', ':'])?;
    text[at..].starts_with('`').then_some(at)
}

/// The backticked spans of a list opening at `text[open]`, each with its offset: each
/// next span joins only when nothing but `,`, `[`, `]`, "and", "or" or "then" stands
/// between, so "`X` or `Y`" and "`X`, then `Y`" are lists and "`X` when `Y`" is not.
fn list_from(text: &str, open: usize) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut at = Some(open);
    while let Some(o) = at {
        let Some((written, past)) = span_at(text, o) else { break };
        out.push((o, written));
        at = text[past..].find('`').map(|n| past + n).filter(|&next| {
            text[past..next]
                .replace([',', '[', ']'], " ")
                .split_whitespace()
                .all(|w| matches!(w, "and" | "or" | "then"))
        });
    }
    out
}

/// Every backticked span of `text`, with the offset of its opening backtick.
fn spans(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(open) = text[from..].find('`').map(|n| from + n) {
        let Some((written, past)) = span_at(text, open) else { break };
        out.push((open, written));
        from = past;
    }
    out
}

/// The path a span opens with, and what follows it: `UserResponse::Error { message }` is
/// `UserResponse::Error` and `{ message }`.
fn span_head(written: &str) -> (&str, &str) {
    let end = written
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .unwrap_or(written.len());
    (&written[..end], written[end..].trim_start())
}

/// The variant `head` names when it is a `UserResponse` path (`UserResponse::X`, with
/// `crate::` or a module path before it); `None` for a bare name or another enum's.
fn response_variant(head: &str) -> Option<&str> {
    let parts: Vec<&str> = head.split("::").collect();
    match parts[..] {
        [.., enum_name, variant] if enum_name == RESPONSE_ENUM && is_ident(variant) => Some(variant),
        _ => None,
    }
}

/// The answer a span in a claim's list names: a `UserResponse` path or a bare name,
/// alone or as a struct literal (`Decrypted { plaintext }`). Another enum's path, or a
/// span that is not a name (`kvaultd tenants`), is `None`: prose, not a claim.
fn claimed_name(written: &str) -> Option<&str> {
    let (head, rest) = span_head(written);
    if !(rest.is_empty() || rest.starts_with(['{', '('])) {
        return None;
    }
    if head.contains("::") {
        response_variant(head)
    } else {
        is_ident(head).then_some(head)
    }
}

/// The spans of `block`'s claims, with their offsets: after "answered with" (any case),
/// the list opening at the first backticked span in the same clause; after "answered",
/// the list opening right after it. Spans that name no answer are left out.
fn claim_spans(block: &DocBlock) -> Vec<(usize, &str)> {
    let (text, lower) = (&block.text, block.text.to_ascii_lowercase());
    let mut out = Vec::new();
    for found in word_at(&lower, "answered") {
        let after = found + "answered".len();
        let next = after + (text[after..].len() - text[after..].trim_start().len());
        let open = if lower[next..].starts_with("with ") || lower[next..].starts_with("with\t") {
            first_span_in_clause(text, next + "with".len())
        } else {
            text[next..].starts_with('`').then_some(next)
        };
        let Some(open) = open else { continue };
        out.extend(list_from(text, open).into_iter().filter(|(_, w)| claimed_name(w).is_some()));
    }
    out
}

/// One answer a doc's "Answered with" names: the line the name is on, the name as
/// written, and the verb whose doc says it, as `Enum::Variant`, when the doc is a
/// variant's. "Answered with `X` or `Y`" is two claims.
#[derive(Debug, PartialEq)]
struct AnswerClaim {
    at: usize,
    name: String,
    verb: Option<String>,
}

/// The answer claims of `src`'s docs, one per name in each claim's list.
fn answer_claims(src: &str) -> Vec<AnswerClaim> {
    let mut out = Vec::new();
    for block in doc_blocks(src) {
        for (open, written) in claim_spans(&block) {
            out.push(AnswerClaim {
                at: block.line_of(open),
                name: written.to_string(),
                verb: block.item.clone(),
            });
        }
    }
    out
}

/// A claimed answer's variant name: `Drives` for `Drives`, `UserResponse::Drives`,
/// `crate::ipc::UserResponse::Drives` and `Drives { drives }`.
fn answer_name(written: &str) -> &str {
    claimed_name(written).unwrap_or(written)
}

/// The `UserResponse` variant a backticked span names outside a claim's list: by path
/// (`UserResponse::X`, any prefix, a struct literal after it or not), or a bare recorded
/// answer written as a struct literal (`SyncStarted { job_id }`). A bare `X` alone is not
/// read: `Ok`, `Status` and `Error` are words before they are answers.
fn answer_named<'a>(written: &'a str, answers: &BTreeSet<&str>) -> Option<&'a str> {
    let (head, rest) = span_head(written);
    if head.contains("::") {
        return response_variant(head);
    }
    (answers.contains(head) && rest.starts_with('{')).then_some(head)
}

/// One "Answer to `V`" doc on an answer: the line it is on, the answer it documents,
/// and the verbs it names, each as `Enum::Variant` with its line.
#[derive(Debug, PartialEq)]
struct AnswerTo {
    at: usize,
    answer: String,
    verbs: Vec<(usize, String)>,
}

/// The answer `block` documents, when it is on a `UserResponse` variant.
fn answer_of(block: &DocBlock) -> Option<&str> {
    block
        .item
        .as_deref()
        .and_then(|item| item.strip_prefix(RESPONSE_ENUM))
        .and_then(|rest| rest.strip_prefix("::"))
}

/// The spans of `block`'s "Answer to" lists, each opening a list at the first backticked
/// span in the clause after "answer to" (any case), grouped by the "answer to" each
/// follows.
fn list_spans(block: &DocBlock) -> Vec<(usize, Vec<(usize, &str)>)> {
    let (text, lower) = (&block.text, block.text.to_ascii_lowercase());
    word_at(&lower, "answer to")
        .into_iter()
        .filter_map(|found| {
            let open = first_span_in_clause(text, found + "answer to".len())?;
            Some((found, list_from(text, open)))
        })
        .collect()
}

/// The "answer to" docs on `src`'s `UserResponse` variants. A verb named bare is a
/// `UserRequest` verb; `crate::` and an enum path before it are read.
fn answer_to_docs(src: &str) -> Vec<AnswerTo> {
    let mut out = Vec::new();
    for block in doc_blocks(src) {
        let Some(answer) = answer_of(&block) else { continue };
        for (found, list) in list_spans(&block) {
            let verbs: Vec<(usize, String)> = list
                .into_iter()
                .filter_map(|(o, written)| verb_key(written).map(|v| (block.line_of(o), v)))
                .collect();
            if !verbs.is_empty() {
                out.push(AnswerTo { at: block.line_of(found), answer: answer.to_string(), verbs });
            }
        }
    }
    out
}

/// A verb as an "Answer to" doc writes it, as `Enum::Variant`: `DriveMove` is
/// `UserRequest::DriveMove`, and `crate::UserRequest::NodeRelay` and
/// `OperatorVerb::ReadRule` keep their enum. A span that is not a verb is `None`.
fn verb_key(written: &str) -> Option<String> {
    let written = written.strip_prefix("crate::").unwrap_or(written);
    let parts: Vec<&str> = written.split("::").collect();
    let (enum_name, variant) = match parts[..] {
        [variant] => (BARE_VERB_ENUM, variant),
        [.., enum_name, variant] => (enum_name, variant),
        [] => return None,
    };
    (is_ident(enum_name) && is_ident(variant)).then(|| format!("{enum_name}::{variant}"))
}

/// Whether `enum_name` is an enum of verbs: a request enum (`UserRequest`,
/// `DeviceRequest`, `VaultRequest`, ...) or `OperatorVerb`. A verb's doc is where an
/// answer is claimed.
fn is_verb_enum(enum_name: &str) -> bool {
    enum_name.ends_with("Request") || enum_name == "OperatorVerb"
}

/// The verb a backticked span on an answer names outside its "Answer to" list: a bare
/// verb recorded in the door's surface, or a verb enum's path (`UserRequest::X`,
/// `DeviceRequest::X`, `crate::` before it), alone or as a struct literal. Shown as an
/// "Answer to" list would write it.
fn verb_named<'a>(written: &'a str, door_verbs: &BTreeSet<&str>) -> Option<&'a str> {
    let (head, rest) = span_head(written);
    if !(rest.is_empty() || rest.starts_with('{')) {
        return None;
    }
    let path = head.strip_prefix("crate::").unwrap_or(head);
    match path.rsplit_once("::") {
        Some((enum_path, variant)) => {
            let enum_name = enum_path.rsplit("::").next().unwrap_or(enum_path);
            (is_verb_enum(enum_name) && is_ident(variant)).then_some(path)
        }
        None => door_verbs.contains(path).then_some(path),
    }
}

/// The spans of `text` the writer marked as cross-references: each list (as
/// [`list_from`] reads one) whose first span follows the word "see", link brackets and
/// a parenthesis allowed between. The rule's one escape, for an answer or a verb named
/// in a doc that is not its claim: "(see `DeviceAdd` and `DeviceJoin`)".
fn seen(text: &str) -> BTreeSet<usize> {
    spans(text)
        .into_iter()
        .filter(|&(open, _)| {
            let before = text[..open].trim_end_matches(['[', '(', ' ']).to_ascii_lowercase();
            before.strip_suffix("see").is_some_and(|b| !b.ends_with(|c: char| c.is_alphanumeric() || c == '_'))
        })
        .flat_map(|(open, _)| list_from(text, open))
        .map(|(o, _)| o)
        .collect()
}

/// A span naming an answer, or a verb, outside the one form that claims it: the line it
/// is on, the span as written, and the claim in the one form the rule reads.
#[derive(Debug, PartialEq)]
struct Stray {
    at: usize,
    written: String,
    one_form: String,
}

/// The spans of `src`'s docs that state the claim another way, each refused rather than
/// read. Keyed on what the span names, not on the words around it:
///
/// - **On a verb** (a variant of a verb enum, [`is_verb_enum`]): each span naming a
///   `UserResponse` variant ([`answer_named`]) that is not in the doc's "Answered with"
///   list. "Returns [`UserResponse::X`]", "Returned as `X { .. }`", "Responds with" and
///   any wording after them are all this one finding. `DeviceResponse::AppRole` and a
///   bare `true` name no `UserResponse` variant and are not read.
/// - **On an answer** (a `UserResponse` variant in [`RESPONSE_SOURCE`], read only when
///   `response_source`): each span naming a verb ([`verb_named`]) that is not in the
///   doc's "Answer to" list: "Returned by `V`", "Response to `V`", "the reply to `V`".
///
/// A span after the word "see", and the list it opens, is a cross-reference the writer
/// spelled out ([`seen`]), and is not read.
fn stray_spans(
    src: &str,
    response_source: bool,
    answers: &BTreeSet<&str>,
    door_verbs: &BTreeSet<&str>,
) -> Vec<Stray> {
    let mut out = Vec::new();
    for block in doc_blocks(src) {
        let Some((enum_name, _)) = block.item.as_deref().and_then(|i| i.split_once("::")) else {
            continue;
        };
        let text = &block.text;
        if is_verb_enum(enum_name) {
            let mut claimed: BTreeSet<usize> = claim_spans(&block).into_iter().map(|(o, _)| o).collect();
            claimed.extend(seen(text));
            for (open, written) in spans(text) {
                if claimed.contains(&open) {
                    continue;
                }
                if let Some(answer) = answer_named(written, answers) {
                    out.push(Stray {
                        at: block.line_of(open),
                        written: written.to_string(),
                        one_form: format!("Answered with `{answer}`"),
                    });
                }
            }
        } else if response_source && enum_name == RESPONSE_ENUM {
            let mut listed: BTreeSet<usize> =
                list_spans(&block).into_iter().flat_map(|(_, l)| l).map(|(o, _)| o).collect();
            listed.extend(seen(text));
            for (open, written) in spans(text) {
                if listed.contains(&open) {
                    continue;
                }
                if let Some(verb) = verb_named(written, door_verbs).and_then(verb_key) {
                    out.push(Stray {
                        at: block.line_of(open),
                        written: written.to_string(),
                        one_form: format!("Answer to `{}`", verb_shown(&verb)),
                    });
                }
            }
        }
    }
    out
}

/// A verb as a finding prints it: bare for the user channel's, with its enum otherwise.
fn verb_shown(key: &str) -> &str {
    key.strip_prefix(BARE_VERB_ENUM).and_then(|k| k.strip_prefix("::")).unwrap_or(key)
}

/// The `.rs` files under `dir`, recursively, sorted, so findings print in one order.
fn rust_files(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// What the answer rule read and found.
#[derive(Debug, Default, PartialEq)]
struct AnswerReport {
    /// "Answered with `X`" claims read under [`ANSWER_DOCS`].
    claims: usize,
    /// Verbs named by an "Answer to" doc in [`RESPONSE_SOURCE`].
    answered_verbs: usize,
    findings: Vec<(Kind, String)>,
}

/// The answer rule over the tree under `root`.
///
/// - Every "Answered with `X`" under [`ANSWER_DOCS`] must name a variant in
///   [`RESPONSE_RECORDING`] ([`Kind::Answer`]).
/// - A verb's doc naming `X` and `X`'s "Answer to" doc in [`RESPONSE_SOURCE`] must agree
///   both ways: `X`'s doc names the verb, and each verb `X`'s doc names says it is
///   answered with `X` ([`Kind::Pair`]).
/// - A claim on either side whose other side is not written is [`Kind::Unwritten`]: the
///   pair cannot be held with one side missing.
fn answer_report(root: &Path) -> AnswerReport {
    let fail = |kind, what: String| AnswerReport { findings: vec![(kind, what)], ..Default::default() };
    let recording = match std::fs::read_to_string(root.join(RESPONSE_RECORDING)) {
        Ok(t) => t,
        Err(e) => return fail(Kind::Unread, format!("  {RESPONSE_RECORDING} could not be read: {e}")),
    };
    let variants: BTreeSet<&str> = match recorded_surface::read(&recording) {
        Ok(blocks) => blocks.into_iter().map(|b| b.name).collect(),
        Err(why) => {
            return fail(Kind::Format, format!("  {RESPONSE_RECORDING} cannot be read as a recording: {why}."))
        }
    };
    let door = match std::fs::read_to_string(root.join(DOOR_RECORDING)) {
        Ok(t) => t,
        Err(e) => return fail(Kind::Unread, format!("  {DOOR_RECORDING} could not be read: {e}")),
    };
    let door_verbs: BTreeSet<&str> = match recorded_surface::read(&door) {
        Ok(blocks) => blocks.into_iter().map(|b| b.name).collect(),
        Err(why) => {
            return fail(Kind::Format, format!("  {DOOR_RECORDING} cannot be read as a recording: {why}."))
        }
    };
    let files = match rust_files(&root.join(ANSWER_DOCS)) {
        Ok(f) => f,
        Err(e) => return fail(Kind::Unread, format!("  {ANSWER_DOCS} could not be read: {e}")),
    };
    let mut report = AnswerReport::default();
    // Each verb's claims, by `Enum::Variant`: where, and the answer named.
    let mut by_verb: BTreeMap<String, Vec<(String, usize, String)>> = BTreeMap::new();
    let mut answer_tos: Vec<AnswerTo> = Vec::new();
    let mut response_read = false;
    for path in files {
        let file = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                report.findings.push((Kind::Unread, format!("  {file} could not be read: {e}")));
                continue;
            }
        };
        if file == RESPONSE_SOURCE {
            response_read = true;
            answer_tos = answer_to_docs(&src);
        }
        for stray in stray_spans(&src, file == RESPONSE_SOURCE, &variants, &door_verbs) {
            report.findings.push((
                Kind::Spelling,
                format!(
                    "  {file}:{}: `{}` states the answer claim outside its one form, which this \
                     rule does not read; write it \"{}\", or \"see `{}`\" when it is a \
                     cross-reference and not the claim.",
                    stray.at, stray.written, stray.one_form, stray.written
                ),
            ));
        }
        for claim in answer_claims(&src) {
            report.claims += 1;
            let name = answer_name(&claim.name).to_string();
            if !variants.contains(name.as_str()) {
                report.findings.push((
                    Kind::Answer,
                    format!(
                        "  {file}:{}: a doc says it is answered with `{}`, which is not a \
                         variant in {RESPONSE_RECORDING}.",
                        claim.at, claim.name
                    ),
                ));
            }
            if let Some(verb) = claim.verb {
                by_verb.entry(verb).or_default().push((file.clone(), claim.at, name));
            }
        }
    }
    if !response_read {
        report.findings.push((Kind::Unread, format!("  {RESPONSE_SOURCE} could not be read.")));
        return report;
    }
    // Each answer's "Answer to" docs, by name: where, and every verb named.
    let mut by_answer: BTreeMap<&str, Vec<&AnswerTo>> = BTreeMap::new();
    for doc in &answer_tos {
        by_answer.entry(doc.answer.as_str()).or_default().push(doc);
    }
    let names_verb = |doc: &&AnswerTo, verb: &str| doc.verbs.iter().any(|(_, v)| v == verb);
    let list = |docs: &[&AnswerTo]| {
        docs.iter()
            .flat_map(|d| d.verbs.iter().map(|(_, v)| format!("`{}`", verb_shown(v))))
            .collect::<Vec<_>>()
            .join(", ")
    };
    // The verb's side: the answer it names must name it back.
    for (verb, claims) in &by_verb {
        for (file, at, name) in claims {
            let shown = verb_shown(verb);
            // A name not recorded is its own finding above.
            if !variants.contains(name.as_str()) {
                continue;
            }
            match by_answer.get(name.as_str()) {
                // A generic answer is said by many verbs; its list is not asked for.
                None if GENERIC_ANSWERS.contains(&name.as_str()) => {}
                None => report.findings.push((
                    Kind::Unwritten,
                    format!(
                        "  {file}:{at}: `{shown}` is answered with `{name}`, and `{name}`'s doc in \
                         {RESPONSE_SOURCE} names no verb it is the answer to, so this claim has no \
                         other side to hold it to."
                    ),
                )),
                Some(docs) if !docs.iter().any(|d| names_verb(d, verb)) => {
                    let mut f = format!(
                        "  {file}:{at}: `{shown}` is answered with `{name}`, but `{name}` is the \
                         answer to {} ({RESPONSE_SOURCE}:{})",
                        list(docs),
                        docs[0].at
                    );
                    for other in answer_tos.iter().filter(|d| d.answer != *name && names_verb(d, verb)) {
                        f.push_str(&format!(
                            "; `{}`'s doc ({RESPONSE_SOURCE}:{}) names `{shown}`",
                            other.answer, other.at
                        ));
                    }
                    f.push('.');
                    report.findings.push((Kind::Pair, f));
                }
                Some(_) => {}
            }
        }
    }
    // The answer's side: every verb it names must say it is answered with it.
    for doc in &answer_tos {
        for (at, verb) in &doc.verbs {
            report.answered_verbs += 1;
            let shown = verb_shown(verb);
            let answer = &doc.answer;
            match by_verb.get(verb) {
                None => report.findings.push((
                    Kind::Unwritten,
                    format!(
                        "  {RESPONSE_SOURCE}:{at}: `{answer}` is the answer to `{shown}`, and no \
                         doc of `{shown}` under {ANSWER_DOCS} says what it is answered with."
                    ),
                )),
                Some(claims) if !claims.iter().any(|(_, _, n)| n == answer) => {
                    let (file, cat, name) = &claims[0];
                    report.findings.push((
                        Kind::Pair,
                        format!(
                            "  {RESPONSE_SOURCE}:{at}: `{answer}` is the answer to `{shown}`, but \
                             `{shown}`'s doc ({file}:{cat}) says it is answered with `{name}`."
                        ),
                    ));
                }
                Some(_) => {}
            }
        }
    }
    report
}

/// The answer rule's findings, with one sentence of advice per kind present.
fn answer_findings_text(command: &str, findings: &[(Kind, String)]) -> String {
    let mut out = format!(
        "{command}: a doc names an answer the daemon does not give, a verb's doc and its \
         answer's doc disagree, one of the two is not written, or a doc spells the claim \
         another way.\n\n"
    );
    for (_, finding) in findings {
        out.push_str(&format!("{finding}\n\n"));
    }
    let has = |kind: Kind| findings.iter().any(|(k, _)| *k == kind);
    if has(Kind::Unread) {
        out.push_str(
            "A file that could not be read is missing or out of reach from here: run from the \
             workspace root, or re-record the response surface with `cargo xtask wire-surface`.\n\n",
        );
    }
    if has(Kind::Format) {
        out.push_str(
            "The response recording cannot be read as one (no `# variants:` header, a header \
             that disagrees with what was read, or no variant at all): it was edited by hand, or \
             the printer (`render`) and the reader (core/wire/src/recorded_surface.rs) no longer \
             agree. Re-record with `cargo xtask wire-surface`; no doc needs to change for this.\n\n",
        );
    }
    if has(Kind::Answer) {
        out.push_str(
            "A name in backticks after \"Answered with\" is the variant of `UserResponse` the verb \
             is answered with, and a reader takes it at its word: change the doc to the variant \
             the verb's handler returns, or, when the answer was renamed, rename it in the doc in \
             the same commit. Prose there (\"what the service answered\") is not held.\n\n",
        );
    }
    if has(Kind::Pair) {
        out.push_str(
            "A verb's \"Answered with `X`\" and `X`'s \"Answer to\" list are one fact written \
             twice, and here they disagree: read the verb's handler for the variant it returns, \
             and correct whichever doc is wrong, in the same commit as the change that moved it.\n\n",
        );
    }
    if has(Kind::Unwritten) {
        out.push_str(
            "One side of a verb and its answer is written and the other is not, so the two cannot \
             be held together: write the missing side, \"Answered with `X`\" on the verb or \
             \"Answer to `V`\" on the answer.\n\n",
        );
    }
    if has(Kind::Spelling) {
        out.push_str(
            "Each side of the claim has one form, \"Answered with `X`\" on a verb and \"Answer \
             to `V`\" on an answer, and the rule holds only that one: an answer named anywhere \
             else in a verb's doc, or a verb anywhere else in an answer's, is a claim the rule \
             cannot hold, so it is refused rather than read. Reword it to the form named, in the \
             same commit, and the rule then holds it both ways; a name that is a cross-reference \
             and not the claim is written after \"see\".\n\n",
        );
    }
    out
}

/// The recording every peer wire's verbs must match: the door's.
const DOOR_RECORDING: &str = "core/wire/wire-surface.txt";

/// The recordings whose every variant mirrors its door twin.
const TWIN_RECORDINGS: [&str; 2] = [
    "core/wire/peer-request-surface.txt",
    "core/wire/vault-peer-request-surface.txt",
];

/// One line of a block, as a finding prints it: raw, between `|` marks, so an
/// indent or a trailing space is visible, with a tab spelled `\t`.
fn shown(line: &str) -> String {
    format!("|{}|", line.replace('\t', "\\t"))
}

/// Which side of a line diff a line is on, by its index in that side.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Only {
    Left(usize),
    Right(usize),
}

/// The lines of `left` and `right` outside their longest common subsequence, in
/// order, by index. A dropped line is one entry naming it, not a shift of every
/// line after it, and a repeated line counts once per occurrence. The common
/// prefix and suffix are set aside first, so a whole recording with one change
/// in it costs a table the size of the change.
fn line_diff(left: &[&str], right: &[&str]) -> Vec<Only> {
    let pre = left.iter().zip(right).take_while(|(a, b)| a == b).count();
    let suf = left[pre..]
        .iter()
        .rev()
        .zip(right[pre..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let (l, r) = (&left[pre..left.len() - suf], &right[pre..right.len() - suf]);
    let (n, m) = (l.len(), r.len());
    // lcs[i][j]: the common subsequence of l[i..] and r[j..].
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if l[i] == r[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n || j < m {
        if i < n && j < m && l[i] == r[j] {
            i += 1;
            j += 1;
        } else if j == m || (i < n && lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push(Only::Left(pre + i));
            i += 1;
        } else {
            out.push(Only::Right(pre + j));
            j += 1;
        }
    }
    out
}

/// One line of a twin block's diff against its door block.
#[derive(Debug, PartialEq)]
enum Edit {
    /// On one side only.
    Only(Only),
    /// On both sides, at different places: by its index in the twin's block and the door's.
    Moved { twin: usize, door: usize },
}

/// [`line_diff`] of a twin block (left) against its door block (right), with each line
/// that is on both sides but at different places paired into one [`Edit::Moved`], at the
/// place in the diff of whichever side comes first, rather than printed as "only in" each
/// file.
///
/// Pairing is nearest first: of every twin-only and door-only line of equal text, the
/// two whose offsets in their blocks are closest pair before any farther apart. A block
/// that repeats a line (`BrowserFrame`'s `skip_serializing_if` attribute) can leave one
/// occurrence outside the common subsequence on both sides at the same offset, when the
/// subsequence holds a line that crossed it; such a pair is a line in its own place on
/// both sides, so it pairs at distance zero and is no edit at all (kotton #305).
fn block_diff(twin: &[&str], door: &[&str]) -> Vec<Edit> {
    let diff = line_diff(twin, door);
    // Every pair of a twin-only and a door-only line of equal text, nearest first.
    let mut candidates = Vec::new();
    for (k, left) in diff.iter().enumerate() {
        let Only::Left(i) = *left else { continue };
        for (q, right) in diff.iter().enumerate() {
            let Only::Right(j) = *right else { continue };
            if door[j] == twin[i] {
                candidates.push((i.abs_diff(j), k, q));
            }
        }
    }
    candidates.sort_unstable();
    let mut partner: Vec<Option<usize>> = vec![None; diff.len()];
    for (_, k, q) in candidates {
        if partner[k].is_none() && partner[q].is_none() {
            partner[k] = Some(q);
            partner[q] = Some(k);
        }
    }
    let mut out = Vec::new();
    for (k, &entry) in diff.iter().enumerate() {
        match partner[k] {
            None => out.push(Edit::Only(entry)),
            // A pair is printed once, where its first side falls in the diff.
            Some(q) if q < k => {}
            Some(q) => {
                let (i, j) = match (entry, diff[q]) {
                    (Only::Left(i), Only::Right(j)) | (Only::Right(j), Only::Left(i)) => (i, j),
                    _ => unreachable!("a pair is one line from each side"),
                };
                if i != j {
                    out.push(Edit::Moved { twin: i, door: j });
                }
            }
        }
    }
    out
}

/// The finding for a twin block that differs from its door block: each line
/// on one side only, by file and its own line number, each line on both sides
/// at different places once as moved, then a note when the two hold the same
/// lines (counted with repeats) in another order.
fn block_finding(twin: &str, block: &Block<'_>, door_block: &Block<'_>) -> String {
    let mut f = format!(
        "  `{}` in {twin} differs from its block in {DOOR_RECORDING}:\n",
        block.name
    );
    let (t, d) = (block.texts(), door_block.texts());
    for edit in block_diff(&t, &d) {
        let line = match edit {
            Edit::Only(Only::Left(i)) => {
                format!("only in {twin}:{}: {}", block.lines[i].at, shown(t[i]))
            }
            Edit::Only(Only::Right(j)) => {
                format!("only in {DOOR_RECORDING}:{}: {}", door_block.lines[j].at, shown(d[j]))
            }
            Edit::Moved { twin: i, door: j } => format!(
                "moved: {twin}:{}, {DOOR_RECORDING}:{}: {}",
                block.lines[i].at,
                door_block.lines[j].at,
                shown(t[i])
            ),
        };
        f.push_str(&format!("    {line}\n"));
    }
    let (mut a, mut b) = (t, d);
    a.sort_unstable();
    b.sort_unstable();
    if a == b {
        f.push_str("    the same lines in another order, which is another order on the wire\n");
    }
    f.trim_end().to_string()
}

/// What a twin finding is about, so the advice printed after it fits it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    /// A recording could not be read from disk at all.
    Unread,
    /// A recording was read but the reader refuses it (no header, a header that
    /// disagrees with what it parsed, a line before any variant, or no variant):
    /// the printer and the reader disagree, or the file was edited by hand.
    Format,
    /// A peer verb's block differs from, or is missing in, the door's.
    Mirror,
    /// A doc says a verb is answered with a backticked name that is not a variant in
    /// the response recording.
    Answer,
    /// A verb's "Answered with `X`" and `X`'s "Answer to" doc disagree.
    Pair,
    /// One side of that pair is written and the other is not.
    Unwritten,
    /// A verb's doc names a `UserResponse` variant outside its "Answered with" list, or an
    /// answer's doc names a verb outside its "Answer to" list: the claim stated in a form
    /// the rule does not read.
    Spelling,
}

/// The twin rule over the recorded files under `root`, as text: one finding
/// per variant of a peer recording whose block differs from, or is missing
/// in, the door's recording, and one per recording that cannot be read or
/// held to its header, each with its [`Kind`].
fn twin_report(root: &Path) -> Vec<(Kind, String)> {
    let read = |rel: &str| std::fs::read_to_string(root.join(rel));
    let door_text = match read(DOOR_RECORDING) {
        Ok(t) => t,
        Err(e) => return vec![(Kind::Unread, format!("  {DOOR_RECORDING} could not be read: {e}"))],
    };
    let door_blocks = match recorded_surface::read(&door_text) {
        Ok(b) => b,
        Err(why) => {
            return vec![(
                Kind::Format,
                format!("  {DOOR_RECORDING} cannot be read as a recording: {why}."),
            )]
        }
    };
    let door: BTreeMap<&str, Block<'_>> = door_blocks.into_iter().map(|b| (b.name, b)).collect();
    let mut findings = Vec::new();
    for twin in TWIN_RECORDINGS {
        let text = match read(twin) {
            Ok(t) => t,
            Err(e) => {
                findings.push((Kind::Unread, format!("  {twin} could not be read: {e}")));
                continue;
            }
        };
        let blocks = match recorded_surface::read(&text) {
            Ok(b) => b,
            Err(why) => {
                findings.push((
                    Kind::Format,
                    format!("  {twin} cannot be read as a recording: {why}."),
                ));
                continue;
            }
        };
        for block in blocks {
            match door.get(block.name) {
                None => findings.push((
                    Kind::Mirror,
                    format!(
                        "  `{}` is in {twin} (line {}) and not in {DOOR_RECORDING}: the door no \
                         longer has the verb the peer wire mirrors.",
                        block.name, block.at
                    ),
                )),
                Some(door_block) if door_block.texts() != block.texts() => {
                    findings.push((Kind::Mirror, block_finding(twin, &block, door_block)));
                }
                Some(_) => {}
            }
        }
    }
    findings
}

/// The twin findings, with one sentence of advice per kind present, as
/// `wire-check` and `wire-surface` print them.
fn print_twin_findings(command: &str, findings: &[(Kind, String)]) {
    eprint!("{}", twin_findings_text(command, findings));
}

fn twin_findings_text(command: &str, findings: &[(Kind, String)]) -> String {
    let mut out = format!(
        "{command}: a peer wire no longer mirrors the door, or a recording cannot be read to tell.\n\n"
    );
    for (_, finding) in findings {
        out.push_str(&format!("{finding}\n\n"));
    }
    let has = |kind: Kind| findings.iter().any(|(k, _)| *k == kind);
    if has(Kind::Unread) {
        out.push_str(
            "A recording that could not be read is missing or out of reach from here: run from \
             the workspace root, or re-record it with `cargo xtask wire-surface`.\n\n",
        );
    }
    if has(Kind::Format) {
        out.push_str(
            "A recording the rule cannot read as one (no `# variants:` header, a header that \
             disagrees with what was read, or no variant at all) was edited by hand, or the \
             printer (`render`) and the reader (core/wire/src/recorded_surface.rs) no longer \
             agree: re-record with `cargo xtask wire-surface`, or change the printer and the \
             reader together; no peer type needs to change for this.\n\n",
        );
    }
    if has(Kind::Mirror) {
        out.push_str(
            "A device sends these verbs as `UserRequest` to both peer decoders, so each peer wire \
             must spell them as the door does: change the peer type and the door's variant \
             together and re-record both with `cargo xtask wire-surface` in the same commit, \
             or every vault or device refuses what the sync pass sends.\n\n",
        );
    }
    out
}

fn check_channel(channel: &Channel, bless: bool) {
    let root = Path::new(".");
    if bless {
        let (variants, rendered) = channel_surface(root, channel).unwrap_or_else(|why| {
            eprintln!("wire-check: {why}");
            std::process::exit(1);
        });
        if let Err(e) = std::fs::write(channel.golden, &rendered) {
            eprintln!("wire-check: could not write {}: {e}", channel.golden);
            std::process::exit(1);
        }
        println!("Wrote {} — {} variants.", channel.golden, variants.len());
        return;
    }
    match compare_channel(root, channel) {
        Ok(Compared::Same(ok)) => println!("{ok}"),
        Ok(Compared::Changed(diff)) => {
            eprintln!("{diff}");
            std::process::exit(1);
        }
        Err(why) => {
            eprintln!("wire-check: {why}");
            std::process::exit(1);
        }
    }
}

/// A channel's variants under `root`, parsed from its sources, and the recording
/// [`render`] makes of them; or why the sources cannot be read as that channel.
fn channel_surface(
    root: &Path,
    channel: &Channel,
) -> Result<(BTreeMap<String, Variant>, String), String> {
    let mut variants: BTreeMap<String, Variant> = BTreeMap::new();
    for (path, enum_name) in channel.sources {
        let Ok(src) = std::fs::read_to_string(root.join(path)) else {
            return Err(format!("could not read {path}. Run from the workspace root."));
        };
        let found = parse_enum(&src, enum_name);
        if found.is_empty() {
            return Err(format!(
                "parsed no variants out of `{enum_name}` in {path}, which cannot be true. \
                 Either the enum was renamed or the parser is broken — and in both cases this \
                 check has stopped looking at the thing it guards."
            ));
        }
        for v in found {
            if let Some(prev) = variants.insert(v.name.clone(), v) {
                return Err(format!(
                    "`{}` is declared in more than one source enum. Untagged deserialization \
                     resolves by trying each in order, so a duplicated name makes the wire \
                     ambiguous and the winner arbitrary.",
                    prev.name
                ));
            }
        }
    }
    let rendered = render(&variants, channel.what);
    Ok((variants, rendered))
}

/// What comparing one channel's source with its recording found.
enum Compared {
    /// They agree; the line `wire-check` prints for it.
    Same(String),
    /// They differ; the report `wire-check` prints for it, the differing lines listed.
    Changed(String),
}

/// One channel's source under `root` against its recording there, or why the two cannot
/// be compared at all.
fn compare_channel(root: &Path, channel: &Channel) -> Result<Compared, String> {
    let Channel { what, golden: golden_path, .. } = channel;
    let (variants, rendered) = channel_surface(root, channel)?;
    let Ok(golden) = std::fs::read_to_string(root.join(golden_path)) else {
        return Err(format!(
            "{golden_path} is missing. It is the record of what the {what} wire looks like \
             today; without it this check confirms nothing. Regenerate with \
             `cargo xtask wire-surface`."
        ));
    };
    if golden.trim().is_empty() {
        return Err(format!("{golden_path} is empty, so it asserts nothing."));
    }
    if golden == rendered {
        return Ok(Compared::Same(format!(
            "wire-check: OK — the {what} wire surface matches {golden_path} ({} variants, {} fields).",
            variants.len(),
            variants.values().map(|v| v.fields.len()).sum::<usize>()
        )));
    }
    Ok(Compared::Changed(format!(
        "wire-check: the {what} wire surface has changed. `-` is a line of {golden_path} the \
         source no longer gives, by its line there; `+` is a line `cargo xtask wire-surface` \
         would write, by its line in that re-recording; each printed raw between `|` marks.\n\n\
         {}\n\
         Every line here is a byte on the wire: a variant name is a JSON key, a field name \
         is an object key, and a `#[serde(...)]` attribute decides whether and how the field \
         is written at all.\n\nIf this change is deliberate, re-record it with \
         `cargo xtask wire-surface` **in the same commit**, so the diff of {golden_path} is the \
         review. If it is not deliberate, it is a compatibility break: an older peer or a \
         stored request will no longer parse.",
        channel_diff(golden_path, &golden, &rendered)
    )))
}

/// The lines of a channel's recording (`golden`) and of its re-recording (`rendered`)
/// that differ, through the twin rule's positional [`line_diff`]: one line per entry,
/// `-` for the recording's side and `+` for the re-recording's, each by its own line
/// number and raw. Lines are not paired as moved here, as they are within a twin block:
/// a whole recording repeats lines like `user_id: String` across variants, and a pairing
/// would join two unrelated variants' changes into one.
fn channel_diff(golden_path: &str, golden: &str, rendered: &str) -> String {
    let old: Vec<&str> = golden.lines().collect();
    let new: Vec<&str> = rendered.lines().collect();
    let mut out = String::new();
    for only in line_diff(&old, &new) {
        let line = match only {
            Only::Left(i) => format!("  -{golden_path}:{}: {}", i + 1, shown(old[i])),
            Only::Right(j) => format!("  +re-recorded:{}: {}", j + 1, shown(new[j])),
        };
        out.push_str(&line);
        out.push('\n');
    }
    if out.is_empty() {
        // Same lines, different bytes: only the line endings or the final newline differ.
        out.push_str("  (no line differs: the line endings or the final newline do)\n");
    }
    out
}

fn render(variants: &BTreeMap<String, Variant>, what: &str) -> String {
    let mut out = String::new();
    if what == "IPC request" {
        out.push_str("# The JSON surface of the IPC request enum. Generated — do not hand-edit.\n");
    } else {
        out.push_str(&format!(
            "# The JSON surface of the {what} channel. Generated — do not hand-edit.\n"
        ));
    }
    out.push_str(
        "# Regenerate with `cargo xtask wire-surface`; `cargo xtask wire-check` gates it.\n",
    );
    out.push_str("# Variants sorted by name; fields in declaration order, which is the order\n");
    out.push_str("# serde writes them. See xtask/src/wire_check.rs for why this file exists.\n");
    out.push_str(&format!("# variants: {}\n", variants.len()));
    for v in variants.values() {
        out.push_str(&v.name);
        out.push('\n');
        for f in &v.fields {
            for a in &f.attrs {
                out.push_str(INDENT);
                out.push_str(a);
                out.push('\n');
            }
            out.push_str(&format!("{INDENT}{}: {}\n", f.name, f.ty));
        }
    }
    out
}

/// Pull variants, their fields, and their serde attributes out of `pub enum <name> { .. }`.
///
/// Brace-matched rather than line-counted, for the reason `request-domains` is:
/// the enum spans well over a thousand lines and its variants carry struct
/// bodies, so "the next `}`" is wrong in about a hundred places.
fn parse_enum(src: &str, enum_name: &str) -> Vec<Variant> {
    let needle = format!("pub enum {enum_name} {{");
    let Some(start) = src.find(&needle) else {
        return Vec::new();
    };
    let body_start = start + needle.len();
    let mut depth = 1usize;
    let mut end = body_start;
    for (i, c) in src[body_start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = body_start + i;
                    break;
                }
            }
            _ => {}
        }
    }

    let mut out: Vec<Variant> = Vec::new();
    let mut current: Option<Variant> = None;
    let mut pending: Vec<String> = Vec::new();
    let mut depth = 0usize;

    for raw in src[body_start..end].lines() {
        let line = strip_comment(raw);
        let t = line.trim();
        if t.is_empty() {
            continue;
        }

        if current.is_none() {
            if let Some(name) = t.strip_suffix('{').map(str::trim).filter(|s| is_ident(s)) {
                current = Some(Variant {
                    name: name.to_string(),
                    fields: Vec::new(),
                });
                depth = 1;
                pending.clear();
                continue;
            }
            if let Some(name) = t.strip_suffix(',').map(str::trim).filter(|s| is_ident(s)) {
                out.push(Variant {
                    name: name.to_string(),
                    fields: Vec::new(),
                });
                continue;
            }
            // A tuple variant — `Name(T),` — records its one field as `0`, so
            // the variant and the type it carries are on the surface rather
            // than dropped in silence. `UserResponse` has a few; the request
            // enums have none.
            if let Some((name, rest)) = t.split_once('(') {
                let name = name.trim();
                if is_ident(name) {
                    if let Some(ty) = rest
                        .trim()
                        .strip_suffix(',')
                        .and_then(|b| b.strip_suffix(')'))
                    {
                        out.push(Variant {
                            name: name.to_string(),
                            fields: vec![Field {
                                attrs: Vec::new(),
                                name: "0".to_string(),
                                ty: normalize_ws(ty.trim()),
                            }],
                        });
                        continue;
                    }
                }
            }
            // A struct variant written on one line — `Name { field: T },` — used
            // to match none of the cases above and was skipped in silence, so it
            // never reached the golden file and `wire-check` never gated it. A
            // check that drops what it does not understand is the vacuous kind;
            // it says nothing, and says it in green.
            //
            // Found 2026-09-07: `BrowserOutbound { channel: String },` was added
            // and the variant count did not move (`DEC-0059`).
            if let Some((name, rest)) = t.split_once('{') {
                let name = name.trim();
                if is_ident(name) {
                    if let Some(body) = rest
                        .trim()
                        .strip_suffix(',')
                        .and_then(|b| b.strip_suffix('}'))
                    {
                        let mut v = Variant {
                            name: name.to_string(),
                            fields: Vec::new(),
                        };
                        for field in body.split(',') {
                            let Some((fname, ty)) = field.split_once(':') else {
                                continue;
                            };
                            let fname = fname.trim();
                            if is_field_ident(fname) {
                                v.fields.push(Field {
                                    attrs: Vec::new(),
                                    name: fname.to_string(),
                                    ty: normalize_ws(ty.trim()),
                                });
                            }
                        }
                        out.push(v);
                    }
                }
            }
            continue;
        }

        depth = depth.saturating_add(line.matches('{').count());
        depth = depth.saturating_sub(line.matches('}').count());
        if depth == 0 {
            if let Some(v) = current.take() {
                out.push(v);
            }
            pending.clear();
            continue;
        }

        if t.starts_with("#[") {
            pending.push(normalize_ws(t));
            continue;
        }
        if let Some((name, ty)) = t.split_once(':') {
            let name = name.trim();
            if is_field_ident(name) {
                let ty = ty.trim().trim_end_matches(',').trim();
                if let Some(v) = current.as_mut() {
                    v.fields.push(Field {
                        attrs: std::mem::take(&mut pending),
                        name: name.to_string(),
                        ty: normalize_ws(ty),
                    });
                }
            }
        }
    }
    out
}

fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_field_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The twin rule's findings as text, in order, without their kinds.
    fn twin_findings(root: &Path) -> Vec<String> {
        twin_report(root).into_iter().map(|(_, f)| f).collect()
    }

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    /// A recording of `body` with the two header lines `render` writes first
    /// that matter here: a comment, and the count of variants in `body`.
    fn recording(body: &str) -> String {
        let n = body
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with(INDENT))
            .count();
        format!("# The JSON surface. Generated — do not hand-edit.\n# variants: {n}\n{body}")
    }

    fn door(read_sealed_path: &str) -> String {
        recording(&format!(
            "NodeRelay\n    user_id: String\nReadFile\n    user_id: String\n    path: String\n\
             ReadSealed\n    user_id: String\n    mount: String\n    {read_sealed_path}\n    offset: u64\n\
             Tenants\nWriteSealed\n    user_id: String\n    #[serde(with = \"crate::base64_bytes\")]\n    blob: Vec<u8>\n"
        ))
    }

    fn peer() -> String {
        recording(
            "NodeRelay\n    user_id: String\nReadFile\n    user_id: String\n    path: String\n\
             ReadSealed\n    user_id: String\n    mount: String\n    path: String\n    offset: u64\n",
        )
    }

    fn vault() -> String {
        recording(
            "ReadSealed\n    user_id: String\n    mount: String\n    path: String\n    offset: u64\n\
             Tenants\nWriteSealed\n    user_id: String\n    #[serde(with = \"crate::base64_bytes\")]\n    blob: Vec<u8>\n",
        )
    }

    /// The three recordings agreeing, a fieldless variant among them, is no finding.
    #[test]
    fn three_recordings_that_agree_are_no_finding() {
        let dir = tree(&[
            (DOOR_RECORDING, &door("path: String")),
            (TWIN_RECORDINGS[0], &peer()),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        assert_eq!(twin_findings(dir.path()), Vec::<String>::new());
    }

    /// A door field re-recorded on its own — the twins left as they were — is a
    /// finding in each peer recording that mirrors it, naming the variant, both
    /// files and the line on each side.
    #[test]
    fn a_door_block_edited_alone_is_a_finding_naming_the_variant_and_both_files() {
        let dir = tree(&[
            (DOOR_RECORDING, &door("object_path: String")),
            (TWIN_RECORDINGS[0], &peer()),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 2, "{findings:#?}");
        // `path` is line 11 of the peer recording and line 6 of the vault's;
        // `object_path` is line 11 of the door's.
        for ((finding, twin), at) in findings.iter().zip(TWIN_RECORDINGS).zip([11, 6]) {
            assert!(finding.contains("`ReadSealed`"), "{finding}");
            assert!(finding.contains(&format!("in {twin} differs from its block in {DOOR_RECORDING}")), "{finding}");
            assert!(finding.contains(&format!("only in {twin}:{at}: |    path: String|")), "{finding}");
            assert!(finding.contains(&format!("only in {DOOR_RECORDING}:11: |    object_path: String|")), "{finding}");
        }
    }

    /// A door block with a repeated `#[serde(...)]` line, as `BrowserFrame`
    /// has, and a twin that dropped one of the repeats: the finding names the
    /// missing line, once, at its line in the door's file, and does not call
    /// the two blocks the same lines in another order.
    #[test]
    fn a_dropped_repeated_attribute_is_named_as_the_missing_line() {
        let skip = "    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n";
        let frame = format!(
            "BrowserFrame\n    #[serde(with = \"crate::base64_bytes\")]\n    bytes: Vec<u8>\n\
             {skip}    user_id: Option<String>\n{skip}    channel: Option<String>\n"
        );
        let dropped = frame.replacen(&format!("{skip}    channel"), "    channel", 1);
        let dir = tree(&[
            (DOOR_RECORDING, &recording(&format!("{frame}NodeRelay\n    user_id: String\n"))),
            (TWIN_RECORDINGS[0], &recording(&dropped)),
            (TWIN_RECORDINGS[1], &recording("NodeRelay\n    user_id: String\n")),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let f = &findings[0];
        // Header two lines, `BrowserFrame` on 3, the dropped repeat on 8.
        assert!(
            f.contains(&format!("only in {DOOR_RECORDING}:8: |{}|", skip.trim_end_matches('\n'))),
            "{f}"
        );
        assert_eq!(f.matches("only in ").count(), 1, "{f}");
        assert!(!f.contains("another order"), "{f}");
    }

    /// A block that repeats a line, as `BrowserFrame` repeats its
    /// `skip_serializing_if` attribute, with two fields swapped: the field that
    /// moved is printed once as moved, and the repeated attribute, which sits at
    /// the same place in both blocks, is not printed at all (kotton #305).
    #[test]
    fn a_repeated_line_at_the_same_place_in_both_blocks_is_not_printed_as_moved() {
        let skip = "    #[serde(default, skip_serializing_if = \"Option::is_none\")]";
        let (user, channel) = ("    user_id: Option<String>", "    channel: Option<String>");
        let twin = [skip, user, skip, channel];
        let door = [skip, channel, skip, user];
        assert_eq!(block_diff(&twin, &door), vec![Edit::Moved { twin: 1, door: 3 }]);

        let block = |lines: &[&str]| format!("BrowserFrame\n{}\n", lines.join("\n"));
        let dir = tree(&[
            (DOOR_RECORDING, &recording(&format!("{}NodeRelay\n    user_id: String\n", block(&door)))),
            (TWIN_RECORDINGS[0], &recording(&block(&twin))),
            (TWIN_RECORDINGS[1], &recording("NodeRelay\n    user_id: String\n")),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let f = &findings[0];
        // Header two lines, `BrowserFrame` on 3: `user_id` is on 5 in the twin, 7 in the door.
        let moved: Vec<&str> = f.lines().filter(|l| l.trim_start().starts_with("moved:")).collect();
        assert_eq!(
            moved,
            vec![format!("    moved: {}:5, {DOOR_RECORDING}:7: |{user}|", TWIN_RECORDINGS[0])],
            "{f}"
        );
        assert!(!f.contains("only in "), "{f}");
        assert!(f.contains("another order"), "{f}");
    }

    /// A trailing space on one side is a different byte in the recording; the
    /// finding prints the two lines so that they read differently.
    #[test]
    fn a_trailing_space_on_one_side_prints_visibly_different_lines() {
        let spaced = peer().replace("    path: String\n    offset", "    path: String \n    offset");
        let dir = tree(&[
            (DOOR_RECORDING, &door("path: String")),
            (TWIN_RECORDINGS[0], &spaced),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        let f = &findings[0];
        assert!(f.contains(&format!("only in {}:11: |    path: String |", TWIN_RECORDINGS[0])), "{f}");
        assert!(f.contains(&format!("only in {DOOR_RECORDING}:11: |    path: String|")), "{f}");
    }

    /// The printer drifting from the parser — here a recording indented with
    /// tabs, so every field line would read as a fieldless variant — is a
    /// finding on that recording, from its own `# variants: N` header, rather
    /// than a rule comparing misread blocks.
    #[test]
    fn a_recording_the_parser_misreads_is_a_finding() {
        let tabbed = peer().replace("\n    ", "\n\t");
        let dir = tree(&[
            (DOOR_RECORDING, &door("path: String")),
            (TWIN_RECORDINGS[0], &tabbed),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(
            findings[0].contains(&format!(
                "{} cannot be read as a recording: its header records 3 variants and the \
                 reader parsed 10",
                TWIN_RECORDINGS[0]
            )),
            "{}",
            findings[0]
        );

        // The door's recording drifting is a finding the same way, and a
        // recording with no header cannot be held to a count at all.
        let dir = tree(&[
            (DOOR_RECORDING, &door("path: String").replace("\n    ", "\n\t")),
            (TWIN_RECORDINGS[0], &peer().replace("# variants: 3\n", "")),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].contains(&format!("{DOOR_RECORDING} cannot be read as a recording")), "{}", findings[0]);
        let headless = peer().replace("# variants: 3\n", "");
        assert!(
            matches!(recorded_surface::read(&headless), Err(why) if why.contains("no `# variants: N` header"))
        );

        // A recording of no variant, reachable only by a hand edit since
        // `check_channel` refuses an empty enum before it writes, is refused by
        // the reader like the rest, and gets the same kind and advice.
        let dir = tree(&[
            (DOOR_RECORDING, &door("path: String")),
            (TWIN_RECORDINGS[0], &recording("")),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let report = twin_report(dir.path());
        assert_eq!(report.len(), 1, "{report:#?}");
        assert!(report[0].0 == Kind::Format, "{}", report[0].1);
        assert!(report[0].1.contains("records no variant"), "{}", report[0].1);
        let text = twin_findings_text("wire-check", &report);
        assert!(text.contains("A recording the rule cannot read as one"), "{text}");
    }

    /// The parser reads back exactly what the printer writes: every variant,
    /// in order, with its attribute and field lines, and a header that agrees.
    #[test]
    fn the_parser_reads_back_what_the_printer_writes() {
        let field = |attrs: &[&str], name: &str, ty: &str| Field {
            attrs: attrs.iter().map(|a| a.to_string()).collect(),
            name: name.to_string(),
            ty: ty.to_string(),
        };
        let skip = "#[serde(default, skip_serializing_if = \"Option::is_none\")]";
        let variants: BTreeMap<String, Variant> = [
            Variant {
                name: "BrowserFrame".into(),
                fields: vec![
                    field(&["#[serde(with = \"crate::base64_bytes\")]"], "bytes", "Vec<u8>"),
                    field(&[skip], "user_id", "Option<String>"),
                    field(&[skip], "channel", "Option<String>"),
                ],
            },
            Variant { name: "Tenants".into(), fields: vec![] },
            Variant { name: "NodeRelay".into(), fields: vec![field(&[], "user_id", "String")] },
        ]
        .into_iter()
        .map(|v| (v.name.clone(), v))
        .collect();
        let text = render(&variants, "peer request");
        let blocks = recorded_surface::read(&text).expect("the reader reads the printer's output");
        assert_eq!(blocks.len(), variants.len());
        for (block, v) in blocks.iter().zip(variants.values()) {
            assert_eq!(block.name, v.name);
            let expected: Vec<String> = v
                .fields
                .iter()
                .flat_map(|f| {
                    f.attrs
                        .iter()
                        .map(|a| format!("{INDENT}{a}"))
                        .chain([format!("{INDENT}{}: {}", f.name, f.ty)])
                })
                .collect();
            assert_eq!(block.texts(), expected, "{}", v.name);
        }
    }

    /// A field attribute is part of the block: dropping one on the twin's side is a finding.
    #[test]
    fn an_attribute_dropped_on_one_side_is_a_finding() {
        let edited = vault().replace("    #[serde(with = \"crate::base64_bytes\")]\n", "");
        let dir = tree(&[
            (DOOR_RECORDING, &door("path: String")),
            (TWIN_RECORDINGS[0], &peer()),
            (TWIN_RECORDINGS[1], &edited),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].contains("`WriteSealed`"), "{}", findings[0]);
        assert!(findings[0].contains("base64_bytes"), "{}", findings[0]);
    }

    /// A door variant renamed and re-recorded leaves its twin naming a verb the
    /// door no longer has, and the field order is the wire's order.
    #[test]
    fn a_renamed_door_variant_and_a_reordered_block_are_findings() {
        let renamed = door("path: String").replace("NodeRelay\n", "NodeRelayOpen\n");
        let reordered = peer().replace(
            "ReadFile\n    user_id: String\n    path: String\n",
            "ReadFile\n    path: String\n    user_id: String\n",
        );
        let dir = tree(&[
            (DOOR_RECORDING, &renamed),
            (TWIN_RECORDINGS[0], &reordered),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert!(findings[0].contains("`NodeRelay` is in core/wire/peer-request-surface.txt (line 3) and not in"), "{}", findings[0]);
        assert!(findings[1].contains("`ReadFile`") && findings[1].contains("another order"), "{}", findings[1]);
        // The swapped pair is one line moved, printed once with its line in
        // each file, not as a line "only in" each of them.
        assert!(
            findings[1].contains(&format!(
                "moved: {}:6, {DOOR_RECORDING}:7: |    path: String|",
                TWIN_RECORDINGS[0]
            )),
            "{}",
            findings[1]
        );
        assert!(!findings[1].contains("only in"), "{}", findings[1]);
    }

    /// A blank line and a comment a hand edit left inside a door block do not
    /// shift the line numbers printed for the lines after them: each line is
    /// numbered by its own line in the file.
    #[test]
    fn a_blank_line_inside_a_block_keeps_the_line_numbers_printed() {
        let edited = door("object_path: String")
            .replace("    mount: String\n    object_path", "    mount: String\n\n# by hand\n    object_path");
        let dir = tree(&[
            (DOOR_RECORDING, &edited),
            (TWIN_RECORDINGS[0], &peer()),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let findings = twin_findings(dir.path());
        assert_eq!(findings.len(), 2, "{findings:#?}");
        for ((finding, twin), at) in findings.iter().zip(TWIN_RECORDINGS).zip([11, 6]) {
            // `object_path` was line 11 of the door's file; the blank and the
            // comment above it put it on 13.
            assert!(finding.contains(&format!("only in {DOOR_RECORDING}:13: |    object_path: String|")), "{finding}");
            assert!(finding.contains(&format!("only in {twin}:{at}: |    path: String|")), "{finding}");
        }
    }

    /// The source enum of a throwaway tree's IPC request channel: one variant
    /// with the repeated `#[serde(...)]` line `BrowserFrame` has.
    const FRAME_SOURCE: &str = "pub enum UserRequest {
    BrowserFrame {
        #[serde(with = \"crate::base64_bytes\")]
        bytes: Vec<u8>,
        #[serde(default, skip_serializing_if = \"Option::is_none\")]
        user_id: Option<String>,
        #[serde(default, skip_serializing_if = \"Option::is_none\")]
        channel: Option<String>,
    },
    Tenants,
}
";

    /// A channel's recording that dropped one of two identical lines is
    /// reported with that one line, by its line in the re-recording, through
    /// the twin rule's positional diff (kotton #296): not "has changed" with
    /// no line, which a `contains` comparison printed.
    #[test]
    fn a_dropped_repeated_line_in_a_channel_recording_is_printed_as_the_one_missing_line() {
        let channel = &CHANNELS[0];
        let src = tree(&[(channel.sources[0].0, FRAME_SOURCE)]);
        let (_, rendered) = channel_surface(src.path(), channel).expect("the source parses");
        let skip = "    #[serde(default, skip_serializing_if = \"Option::is_none\")]";
        assert_eq!(rendered.matches(skip).count(), 2, "{rendered}");
        let dropped = rendered.replacen(&format!("{skip}\n    channel"), "    channel", 1);
        let dir = tree(&[(channel.sources[0].0, FRAME_SOURCE), (channel.golden, &dropped)]);
        let Ok(Compared::Changed(report)) = compare_channel(dir.path(), channel) else {
            panic!("a dropped line must be a change");
        };
        let listed: Vec<&str> = report
            .lines()
            .filter(|l| l.starts_with("  -") || l.starts_with("  +"))
            .collect();
        // Five header lines, `BrowserFrame` on 6, and the second repeat on 11.
        assert_eq!(listed, [format!("  +re-recorded:11: |{skip}|")], "{report}");

        // And the same tree re-recorded is no change.
        let same = tree(&[(channel.sources[0].0, FRAME_SOURCE), (channel.golden, &rendered)]);
        assert!(matches!(compare_channel(same.path(), channel), Ok(Compared::Same(_))));
    }

    /// The advice after the findings fits their kind: a printer drift is not
    /// told to change a peer type, and a differing block is.
    #[test]
    fn the_advice_printed_matches_the_kind_of_finding() {
        let drift = tree(&[
            (DOOR_RECORDING, &door("path: String")),
            (TWIN_RECORDINGS[0], &peer().replace("\n    ", "\n\t")),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let text = twin_findings_text("wire-check", &twin_report(drift.path()));
        assert!(text.contains("no peer type needs to change"), "{text}");
        assert!(!text.contains("change the peer type"), "{text}");

        let mirror = tree(&[
            (DOOR_RECORDING, &door("object_path: String")),
            (TWIN_RECORDINGS[0], &peer()),
            (TWIN_RECORDINGS[1], &vault()),
        ]);
        let text = twin_findings_text("wire-check", &twin_report(mirror.path()));
        assert!(text.contains("change the peer type"), "{text}");
        assert!(!text.contains("no peer type needs to change"), "{text}");

        let unread = tree(&[(DOOR_RECORDING, &door("path: String"))]);
        let text = twin_findings_text("wire-check", &twin_report(unread.path()));
        assert!(text.contains("could not be read is missing"), "{text}");
        assert!(!text.contains("change the peer type") && !text.contains("no peer type"), "{text}");
    }

    /// The names each answer claim in `src`'s docs gives, with the line each is on.
    fn claims(src: &str) -> Vec<(usize, String)> {
        answer_claims(src).into_iter().map(|c| (c.at, c.name)).collect()
    }

    fn named(pairs: &[(usize, &str)]) -> Vec<(usize, String)> {
        pairs.iter().map(|&(at, name)| (at, name.to_string())).collect()
    }

    /// Every way a doc spells the claim is read, at the line its name is on: on one
    /// line, wrapped after "with" or between "Answered" and "with", lower-case,
    /// after a few words of the same clause, with no "with", and in a module doc.
    #[test]
    fn each_spelling_of_answered_with_is_read_at_the_line_of_its_name() {
        let src = "\
/// Answered with `Drives`.
A,
/// One line, then the phrase wrapped after its last word. Answered with
/// `DriveMoved`, the drive.
B,
/// Wrapped between the two words: Answered
///   with `Pins`.
C,
/// each: answered with `VaultTenants`.
D,
/// Answered with the pool's `VaultCapacityResult` after the set.
E,
/// Answered with `UserResponse::Status`.
F,
/// A local act. Answered
/// `OperatorForgotten`.
G,
//! Answered with `OrgRootCreated`.
";
        assert_eq!(
            claims(src),
            named(&[
                (1, "Drives"),
                (4, "DriveMoved"),
                (7, "Pins"),
                (9, "VaultTenants"),
                (11, "VaultCapacityResult"),
                (13, "UserResponse::Status"),
                (16, "OperatorForgotten"),
                (18, "OrgRootCreated"),
            ])
        );
    }

    /// What is not a claim is not read as one: prose with no backticked name before
    /// the clause ends, a backticked span that is not a name, "answered like", a word
    /// that merely ends in "answered", an ordinary comment, and a phrase split by a
    /// line of code.
    #[test]
    fn prose_code_and_ordinary_comments_are_not_claims() {
        let src = "\
/// Answered with what the service answered. The `Drives` after it is another sentence.
A,
/// Answered with the readout (`kvaultd tenants`).
B,
/// Unanswered with `Nope`.
C,
// Answered with `Comment`.
D,
//// Answered with `FourSlashes`.
E,
/// Answered
F,
/// with `AcrossCode`.
G,
/// The word `MessageSend` already answered with, read again: `Later`.
H,
/// Answered like `NodeRelay`, a fact of the node.
";
        assert_eq!(claims(src), named(&[]));
    }

    /// A doc block knows the variant it documents, past attributes, a multi-line
    /// attribute and an ordinary comment, by its enum; a field's doc is no variant's,
    /// and a doc outside an enum has no item.
    #[test]
    fn a_doc_block_knows_the_variant_it_documents() {
        let src = "\
/// The enum.
pub enum UserRequest {
    /// Answered with `Drives`.
    #[serde(rename = \"x\")]
    #[serde(
        default,
    )]
    // a note
    DriveList {
        /// Answered with `Field`.
        user_id: String,
    },
}
/// Answered with `Outside`.
pub struct S;
";
        let items: Vec<Option<String>> = answer_claims(src).into_iter().map(|c| c.verb).collect();
        assert_eq!(items, [Some("UserRequest::DriveList".to_string()), None, None]);
    }

    /// An answer's "Answer to" list: bare verbs joined by `,` and "and", a bracketed
    /// `crate::` path, an enum path after a few words, and a list that ends at a word
    /// other than "and" or "or". A doc that is not on a `UserResponse` variant is not
    /// read as a list.
    #[test]
    fn an_answer_to_doc_lists_the_verbs_it_names() {
        let src = "\
pub enum UserResponse {
    /// Answer to `DriveCreate`, `DriveList` and `DriveShow`: the drives.
    Drives { drives: Vec<D> },
    /// Answer to [`crate::UserRequest::NodeRelay`]: the relay.
    NodeRelayResult,
    /// Answer to the door's `VaultRequest::Tenants` or `UserRequest::Tenants`.
    VaultTenants,
    /// The answer to `Status`, which carries `DeviceStatus`.
    Status,
    /// A client's correct answer to it is to stop.
    Bye,
}
pub enum Other {
    /// Answer to `NotAnAnswer`.
    X,
}
";
        let lists: Vec<(String, Vec<String>)> = answer_to_docs(src)
            .into_iter()
            .map(|d| (d.answer, d.verbs.into_iter().map(|(_, v)| v).collect()))
            .collect();
        let want = |answer: &str, verbs: &[&str]| {
            (answer.to_string(), verbs.iter().map(|v| v.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(
            lists,
            [
                want("Drives", &["UserRequest::DriveCreate", "UserRequest::DriveList", "UserRequest::DriveShow"]),
                want("NodeRelayResult", &["UserRequest::NodeRelay"]),
                want("VaultTenants", &["VaultRequest::Tenants", "UserRequest::Tenants"]),
                want("Status", &["UserRequest::Status"]),
            ]
        );
    }

    const REQUEST: &str = "core/wire/src/ipc/request.rs";

    /// A throwaway tree's response recording and source: `Drives` answers three verbs,
    /// `DriveMoved` answers the move, and `Ok` has no list.
    fn answers_recording() -> String {
        recording(
            "DriveMoved\n    drives: Vec<DriveDescriptor>\n    keys_refused: u32\n\
             Drives\n    drives: Vec<DriveDescriptor>\nOk\n",
        )
    }

    const RESPONSE: &str = "pub enum UserResponse {
    /// Answer to `DriveList` and `DriveShow`.
    Drives { drives: Vec<DriveDescriptor> },
    /// Answer to `DriveMove`.
    DriveMoved { drives: Vec<DriveDescriptor>, keys_refused: u32 },
    /// Done.
    Ok,
}
";

    /// The request source of that tree, every doc agreeing with its answer's.
    /// `DriveMove`'s claim is wrapped onto its next doc line, on line 7.
    const AGREEING: &str = "pub enum UserRequest {
    /// Answered with `Drives`.
    DriveList,
    /// Answered with `Drives`.
    DriveShow,
    /// Moves it. Answered with
    /// `DriveMoved`, the drive.
    DriveMove,
    /// Answered `Ok`.
    StandAt,
    /// Answered with what the service answered.
    AsOperator,
}
";

    /// The door's recording of that tree: the verbs its docs name, which an answer's doc
    /// may name only in its "Answer to" list.
    fn answers_door() -> String {
        recording("AsOperator\nDriveList\nDriveMove\nDriveShow\nStandAt\n")
    }

    fn answers_tree(request: &str) -> tempfile::TempDir {
        answers_tree_with(RESPONSE, request)
    }

    fn answers_tree_with(response: &str, request: &str) -> tempfile::TempDir {
        tree(&[
            (RESPONSE_RECORDING, &answers_recording()),
            (DOOR_RECORDING, &answers_door()),
            (RESPONSE_SOURCE, response),
            (REQUEST, request),
        ])
    }

    fn finding_texts(report: &AnswerReport) -> Vec<&str> {
        report.findings.iter().map(|(_, f)| f.as_str()).collect()
    }

    /// Docs that agree both ways are no finding, and `Ok`, a generic answer, needs no
    /// list for the verb that claims it.
    #[test]
    fn docs_that_agree_both_ways_are_no_finding() {
        let report = answer_report(answers_tree(AGREEING).path());
        assert_eq!(report.findings, Vec::new());
        assert_eq!((report.claims, report.answered_verbs), (4, 3));
    }

    /// The drift #341 was filed for: `DriveMove` saying `Drives`, a recorded answer that
    /// is not its own. Both docs are named, each by its file and line.
    #[test]
    fn a_recorded_answer_that_is_not_the_verbs_own_is_a_finding_naming_both_sides() {
        let stale = AGREEING.replace("`DriveMoved`, the drive", "`Drives`, the drive");
        let report = answer_report(answers_tree(&stale).path());
        assert_eq!(
            finding_texts(&report),
            [
                format!(
                    "  {REQUEST}:7: `DriveMove` is answered with `Drives`, but `Drives` is the \
                     answer to `DriveList`, `DriveShow` ({RESPONSE_SOURCE}:2); `DriveMoved`'s doc \
                     ({RESPONSE_SOURCE}:4) names `DriveMove`."
                ),
                format!(
                    "  {RESPONSE_SOURCE}:4: `DriveMoved` is the answer to `DriveMove`, but \
                     `DriveMove`'s doc ({REQUEST}:7) says it is answered with `Drives`."
                ),
            ]
        );
        assert!(report.findings.iter().all(|(k, _)| *k == Kind::Pair));
        let text = answer_findings_text("wire-check", &report.findings);
        assert!(text.contains("one fact written twice"), "{text}");
    }

    /// A name that is no answer at all is a finding naming the file and line, with its
    /// advice; the answer whose list names the verb is told the verb's doc disagrees.
    #[test]
    fn a_name_that_is_no_recorded_answer_is_a_finding_naming_the_file_and_line() {
        let stale = AGREEING.replace("`DriveMoved`, the drive", "`DriveMovd`, the drive");
        let report = answer_report(answers_tree(&stale).path());
        assert_eq!(
            report.findings,
            [
                (
                    Kind::Answer,
                    format!(
                        "  {REQUEST}:7: a doc says it is answered with `DriveMovd`, which is not a \
                         variant in {RESPONSE_RECORDING}."
                    )
                ),
                (
                    Kind::Pair,
                    format!(
                        "  {RESPONSE_SOURCE}:4: `DriveMoved` is the answer to `DriveMove`, but \
                         `DriveMove`'s doc ({REQUEST}:7) says it is answered with `DriveMovd`."
                    )
                ),
            ]
        );
        let text = answer_findings_text("wire-check", &report.findings);
        assert!(text.contains("change the doc to the variant"), "{text}");
    }

    /// One side written and the other not is a finding on that side: an answer whose
    /// list names a verb with no claim, and a verb claiming an answer that has no list.
    /// A verb and an answer with neither doc are none.
    #[test]
    fn one_side_written_and_the_other_not_is_unwritten() {
        let unclaimed = AGREEING.replace("    /// Answered with `Drives`.\n    DriveShow,", "    DriveShow,");
        let report = answer_report(answers_tree(&unclaimed).path());
        assert_eq!(
            report.findings,
            [(
                Kind::Unwritten,
                format!(
                    "  {RESPONSE_SOURCE}:2: `Drives` is the answer to `DriveShow`, and no doc of \
                     `DriveShow` under {ANSWER_DOCS} says what it is answered with."
                )
            )]
        );
        let text = answer_findings_text("wire-check", &report.findings);
        assert!(text.contains("write the missing side"), "{text}");

        let listless = answers_tree_with(&RESPONSE.replace("/// Answer to `DriveMove`.", "/// The move."), AGREEING);
        let report = answer_report(listless.path());
        assert_eq!(
            report.findings,
            [(
                Kind::Unwritten,
                format!(
                    "  {REQUEST}:7: `DriveMove` is answered with `DriveMoved`, and `DriveMoved`'s \
                     doc in {RESPONSE_SOURCE} names no verb it is the answer to, so this claim \
                     has no other side to hold it to."
                )
            )]
        );

        // Neither side written: no finding.
        let neither = AGREEING.replace("    /// Answered `Ok`.\n", "");
        assert_eq!(answer_report(answers_tree(&neither).path()).findings, Vec::new());
    }

    /// The finding [`stray_spans`] gives for `written` at `file:line`, told the one form.
    fn stray(file: &str, line: usize, written: &str, one_form: &str) -> (Kind, String) {
        (
            Kind::Spelling,
            format!(
                "  {file}:{line}: `{written}` states the answer claim outside its one form, which \
                 this rule does not read; write it \"{one_form}\", or \"see `{written}`\" when it \
                 is a cross-reference and not the claim."
            ),
        )
    }

    /// Every way the assessor of #369 found to state a verb's answer other than "Answered
    /// with", each in its own throwaway tree: refused at the line of the name, told the
    /// one form, and not read as a claim, so `Drives`' list naming `DriveShow` is told
    /// the verb's side is unwritten. The key is the span, not the word before it.
    #[test]
    fn an_answer_named_on_a_verb_outside_answered_with_is_refused_whatever_the_wording() {
        let probes = [
            ("/// Returns: [`UserResponse::Drives`].", "UserResponse::Drives"),
            ("/// Returns, on success, [`UserResponse::Drives`].", "UserResponse::Drives"),
            ("/// Returns `Ok` or [`UserResponse::Drives`].", "UserResponse::Drives"),
            ("/// Return [`crate::UserResponse::Drives`].", "crate::UserResponse::Drives"),
            ("/// Returned as `Drives { drives }`.", "Drives { drives }"),
            (
                "/// Responds with `crate::ipc::response::UserResponse::Drives`.",
                "crate::ipc::response::UserResponse::Drives",
            ),
            ("/// Streaming: opens with [`UserResponse::Drives`].", "UserResponse::Drives"),
        ];
        for (doc, written) in probes {
            let request = AGREEING.replace("/// Answered with `Drives`.\n    DriveShow,", &format!("{doc}\n    DriveShow,"));
            let report = answer_report(answers_tree(&request).path());
            assert_eq!(
                report.findings,
                [
                    stray(REQUEST, 4, written, "Answered with `Drives`"),
                    (
                        Kind::Unwritten,
                        format!(
                            "  {RESPONSE_SOURCE}:2: `Drives` is the answer to `DriveShow`, and no doc \
                             of `DriveShow` under {ANSWER_DOCS} says what it is answered with."
                        )
                    ),
                ],
                "{doc}"
            );
            let text = answer_findings_text("wire-check", &report.findings);
            assert!(text.contains("Reword it to the form named"), "{text}");
        }
    }

    /// Every way found to state an answer's verbs other than "Answer to", each in its own
    /// throwaway tree: refused at the line of the verb, told the one form (the verb as a
    /// list writes it), and not read as a list, so `DriveMove`'s claim of `DriveMoved` is
    /// told the answer's side is unwritten.
    #[test]
    fn a_verb_named_on_an_answer_outside_answer_to_is_refused_whatever_the_wording() {
        let probes = [
            "/// Returned by `DriveMove`.",
            "/// The move (the reply to `DriveMove`).",
            "/// Result of `DriveMove` — the drive where it lives.",
            "/// Response to `UserRequest::DriveMove`.",
            "/// Reply to a [`crate::UserRequest::DriveMove`].",
            "/// What `DriveMove { drive }` hands back.",
        ];
        for doc in probes {
            let written = doc.split('`').nth(1).unwrap();
            let response = RESPONSE.replace("/// Answer to `DriveMove`.", doc);
            let dir = answers_tree_with(&response, AGREEING);
            let report = answer_report(dir.path());
            assert_eq!(
                report.findings,
                [
                    stray(RESPONSE_SOURCE, 4, written, "Answer to `DriveMove`"),
                    (
                        Kind::Unwritten,
                        format!(
                            "  {REQUEST}:7: `DriveMove` is answered with `DriveMoved`, and \
                             `DriveMoved`'s doc in {RESPONSE_SOURCE} names no verb it is the answer \
                             to, so this claim has no other side to hold it to."
                        )
                    ),
                ],
                "{doc}"
            );
        }
    }

    /// What the refusal does not read: another enum's path (`DeviceResponse::AppRole`, as
    /// `AppGetRole`'s doc said before #369), a bare word (`true`), a bare answer name with
    /// no struct literal (the residue #385 holds), a mention after "see", a doc on no verb
    /// (a struct's), and a verb named on another response enum or outside the response
    /// source. A multi-answer claim ("`Drives` or `Ok`") is one claim of each, and agrees.
    #[test]
    fn mentions_that_are_not_a_claim_are_not_refused() {
        let request = AGREEING
            .replace(
                "/// Answered with `Drives`.\n    DriveShow,",
                "/// Answered with `Drives` or [`UserResponse::Ok`]: the drive, or nothing.\n    \
                 /// Not [`DeviceResponse::AppRole`], which is the device channel's.\n    DriveShow,",
            )
            .replace(
                "    AsOperator,\n",
                "    AsOperator,\n    /// Returns `true` when it holds; see `UserResponse::Drives` for the shape.\n    \
                 /// Answers `Drives` (bare: not read).\n    AppHolds,\n",
            )
            + "\n/// Returned by [`UserResponse::Drives`]. A struct, not a verb.\npub struct Shown;\n";
        let response = RESPONSE.replace(
            "/// Done.",
            "/// Done (see `DriveList` and `DriveShow`, which may also say it).",
        ) + "pub enum DeviceResponse {\n    /// Response to [`SysRequest::Ping`].\n    Pong,\n}\n";
        let request = request.replace("/// Answered `Ok`.", "/// Response to `StandAt` is `Ok`. Answered `Ok`.");
        let dir = answers_tree_with(&response, &request);
        let report = answer_report(dir.path());
        assert_eq!(report.findings, Vec::new());
        assert_eq!((report.claims, report.answered_verbs), (5, 3));
    }

    /// The response recording read through the one reader: one the reader refuses, or
    /// none at all, is a finding of its own kind with its own advice, not a rule that
    /// passes every name or refuses every one.
    #[test]
    fn an_unreadable_response_recording_is_a_finding_of_its_kind() {
        let headless = answers_recording().replace("# variants: 3\n", "");
        let dir = tree(&[(RESPONSE_RECORDING, &headless), (RESPONSE_SOURCE, RESPONSE), (REQUEST, AGREEING)]);
        let findings = answer_report(dir.path()).findings;
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].0 == Kind::Format, "{}", findings[0].1);
        assert!(answer_findings_text("wire-check", &findings).contains("no doc needs to change"));

        let dir = tree(&[(RESPONSE_SOURCE, RESPONSE), (REQUEST, AGREEING)]);
        let findings = answer_report(dir.path()).findings;
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].0 == Kind::Unread, "{}", findings[0].1);

        let dir = tree(&[
            (RESPONSE_RECORDING, &answers_recording()),
            (DOOR_RECORDING, &answers_door()),
            (REQUEST, AGREEING),
        ]);
        let findings = answer_report(dir.path()).findings;
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].0 == Kind::Unread && findings[0].1.contains(RESPONSE_SOURCE), "{}", findings[0].1);
    }

    /// Every answer claim in this tree names a recorded answer and agrees with its
    /// answer's list, and the rule reads enough of both not to be green by reading none.
    #[test]
    fn every_answer_named_in_this_tree_is_recorded_and_agrees() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let report = answer_report(&root);
        assert_eq!(report.findings, Vec::new());
        assert!(report.claims >= 94, "read {} claims", report.claims);
        assert!(report.answered_verbs >= 88, "read {} listed verbs", report.answered_verbs);
    }

    /// The real recordings in this tree agree, so the gate starts green.
    #[test]
    fn the_recordings_in_this_tree_agree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(twin_findings(&root), Vec::<String>::new());
    }
}
