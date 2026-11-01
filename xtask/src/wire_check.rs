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

use std::collections::BTreeMap;
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
        golden: "core/wire/response-surface.txt",
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
        return;
    }
    // The twin rule reads only the recordings, so it runs first: a recording
    // edited by hand fails its channel below and is named here as well.
    let findings = twin_report(Path::new("."));
    if !findings.is_empty() {
        print_twin_findings("wire-check", &findings);
    }
    for channel in CHANNELS {
        check_channel(channel, false);
    }
    if !findings.is_empty() {
        std::process::exit(1);
    }
    println!(
        "wire-check: OK — every verb in {} and {} records its door twin's block in {DOOR_RECORDING}.",
        TWIN_RECORDINGS[0], TWIN_RECORDINGS[1]
    );
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
    let mut scanned = 0usize;
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
        scanned += 1;
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
    if scanned != channel.sources.len() {
        return Err(format!("{scanned} of {} sources scanned.", channel.sources.len()));
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

    /// The real recordings in this tree agree, so the gate starts green.
    #[test]
    fn the_recordings_in_this_tree_agree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(twin_findings(&root), Vec::<String>::new());
    }
}
