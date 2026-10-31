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
//! So [`twin_findings`] reads the three recorded files as text, with no
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

use std::collections::BTreeMap;
use std::path::Path;

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
        return;
    }
    // The twin rule reads only the recordings, so it runs first: a recording
    // edited by hand fails its channel below and is named here as well.
    let findings = twin_findings(Path::new("."));
    if !findings.is_empty() {
        eprintln!("wire-check: a peer wire no longer mirrors the door.\n");
        for finding in &findings {
            eprintln!("{finding}\n");
        }
        eprintln!(
            "A device sends these verbs as `UserRequest` to both peer decoders, so each peer wire \
             must spell them as the door does. Change the peer type and the door's variant \
             together and re-record both with `cargo xtask wire-surface` in the same commit; \
             otherwise every vault or device refuses what the sync pass sends.\n"
        );
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

/// The variants of a recorded surface, each with its indented lines (field
/// attributes and fields) as written. Header lines start with `#`.
fn recorded_blocks(text: &str) -> Vec<(&str, Vec<&str>)> {
    let mut out: Vec<(&str, Vec<&str>)> = Vec::new();
    for line in text.lines() {
        if line.starts_with(' ') {
            if let Some((_, block)) = out.last_mut() {
                block.push(line);
            }
        } else if !line.starts_with('#') && !line.trim().is_empty() {
            out.push((line.trim_end(), Vec::new()));
        }
    }
    out
}

/// The twin rule over the recorded files under `root`, as text: one finding
/// per variant of a peer recording whose block differs from, or is missing
/// in, the door's recording. Empty when they agree.
pub fn twin_findings(root: &Path) -> Vec<String> {
    let read = |rel: &str| std::fs::read_to_string(root.join(rel));
    let door_text = match read(DOOR_RECORDING) {
        Ok(t) => t,
        Err(e) => return vec![format!("  {DOOR_RECORDING} could not be read: {e}")],
    };
    let door: BTreeMap<&str, Vec<&str>> = recorded_blocks(&door_text).into_iter().collect();
    if door.is_empty() {
        return vec![format!("  {DOOR_RECORDING} records no variant, so it mirrors nothing.")];
    }
    let mut findings = Vec::new();
    for twin in TWIN_RECORDINGS {
        let text = match read(twin) {
            Ok(t) => t,
            Err(e) => {
                findings.push(format!("  {twin} could not be read: {e}"));
                continue;
            }
        };
        let blocks = recorded_blocks(&text);
        if blocks.is_empty() {
            findings.push(format!("  {twin} records no variant, so the twin rule holds nothing."));
        }
        for (name, block) in blocks {
            match door.get(name) {
                None => findings.push(format!(
                    "  `{name}` is in {twin} and not in {DOOR_RECORDING}: the door no longer \
                     has the verb the peer wire mirrors."
                )),
                Some(door_block) if *door_block != block => {
                    let mut f = format!(
                        "  `{name}` in {twin} differs from its block in {DOOR_RECORDING}:\n"
                    );
                    for line in block.iter().filter(|l| !door_block.contains(l)) {
                        f.push_str(&format!("    {twin}: {}\n", line.trim()));
                    }
                    for line in door_block.iter().filter(|l| !block.contains(l)) {
                        f.push_str(&format!("    {DOOR_RECORDING}: {}\n", line.trim()));
                    }
                    if block.iter().all(|l| door_block.contains(l))
                        && door_block.iter().all(|l| block.contains(l))
                    {
                        f.push_str("    the same lines in another order, which is another order on the wire\n");
                    }
                    findings.push(f.trim_end().to_string());
                }
                Some(_) => {}
            }
        }
    }
    findings
}

fn check_channel(channel: &Channel, bless: bool) {
    let Channel {
        what,
        sources,
        golden,
    } = channel;
    let (sources, golden_path): (&[(&str, &str)], &str) = (sources, golden);
    let mut variants: BTreeMap<String, Variant> = BTreeMap::new();
    let mut scanned = 0usize;

    for (path, enum_name) in sources {
        let Ok(src) = std::fs::read_to_string(Path::new(path)) else {
            eprintln!("wire-check: could not read {path}. Run from the workspace root.");
            std::process::exit(1);
        };
        let found = parse_enum(&src, enum_name);
        if found.is_empty() {
            eprintln!(
                "wire-check: parsed no variants out of `{enum_name}` in {path}, which cannot \
                 be true. Either the enum was renamed or the parser is broken — and in both \
                 cases this check has stopped looking at the thing it guards."
            );
            std::process::exit(1);
        }
        scanned += 1;
        for v in found {
            if let Some(prev) = variants.insert(v.name.clone(), v) {
                eprintln!(
                    "wire-check: `{}` is declared in more than one source enum. Untagged \
                     deserialization resolves by trying each in order, so a duplicated name \
                     makes the wire ambiguous and the winner arbitrary.",
                    prev.name
                );
                std::process::exit(1);
            }
        }
    }

    if scanned != sources.len() {
        eprintln!(
            "wire-check: {scanned} of {} sources scanned.",
            sources.len()
        );
        std::process::exit(1);
    }

    let rendered = render(&variants, what);

    if bless {
        if let Err(e) = std::fs::write(golden_path, &rendered) {
            eprintln!("wire-check: could not write {golden_path}: {e}");
            std::process::exit(1);
        }
        println!("Wrote {golden_path} — {} variants.", variants.len());
        return;
    }

    let Ok(golden) = std::fs::read_to_string(golden_path) else {
        eprintln!(
            "wire-check: {golden_path} is missing. It is the record of what the {what} wire looks \
             like today; without it this check confirms nothing. Regenerate with \
             `cargo xtask wire-surface`."
        );
        std::process::exit(1);
    };
    if golden.trim().is_empty() {
        eprintln!("wire-check: {golden_path} is empty, so it asserts nothing.");
        std::process::exit(1);
    }

    if golden == rendered {
        println!(
            "wire-check: OK — the {what} wire surface matches {golden_path} ({} variants, {} fields).",
            variants.len(),
            variants.values().map(|v| v.fields.len()).sum::<usize>()
        );
        return;
    }

    eprintln!("wire-check: the {what} wire surface has changed.\n");
    let old: Vec<&str> = golden.lines().collect();
    let new: Vec<&str> = rendered.lines().collect();
    for line in old.iter().filter(|l| !new.contains(l)) {
        eprintln!("  -{line}");
    }
    for line in new.iter().filter(|l| !old.contains(l)) {
        eprintln!("  +{line}");
    }
    eprintln!(
        "\nEvery line here is a byte on the wire: a variant name is a JSON key, a field name \
         is an object key, and a `#[serde(...)]` attribute decides whether and how the field \
         is written at all.\n\nIf this change is deliberate, re-record it with \
         `cargo xtask wire-surface` **in the same commit**, so the diff of {golden_path} is the \
         review. If it is not deliberate, it is a compatibility break: an older peer or a \
         stored request will no longer parse."
    );
    std::process::exit(1);
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
                out.push_str("    ");
                out.push_str(a);
                out.push('\n');
            }
            out.push_str(&format!("    {}: {}\n", f.name, f.ty));
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

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    const HEADER: &str = "# The JSON surface. Generated — do not hand-edit.\n# variants: 3\n";

    fn door(read_sealed_path: &str) -> String {
        format!(
            "{HEADER}NodeRelay\n    user_id: String\nReadFile\n    user_id: String\n    path: String\n\
             ReadSealed\n    user_id: String\n    mount: String\n    {read_sealed_path}\n    offset: u64\n\
             Tenants\nWriteSealed\n    user_id: String\n    #[serde(with = \"crate::base64_bytes\")]\n    blob: Vec<u8>\n"
        )
    }

    fn peer() -> String {
        format!(
            "{HEADER}NodeRelay\n    user_id: String\nReadFile\n    user_id: String\n    path: String\n\
             ReadSealed\n    user_id: String\n    mount: String\n    path: String\n    offset: u64\n"
        )
    }

    fn vault() -> String {
        format!(
            "{HEADER}ReadSealed\n    user_id: String\n    mount: String\n    path: String\n    offset: u64\n\
             Tenants\nWriteSealed\n    user_id: String\n    #[serde(with = \"crate::base64_bytes\")]\n    blob: Vec<u8>\n"
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
        for (finding, twin) in findings.iter().zip(TWIN_RECORDINGS) {
            assert!(finding.contains("`ReadSealed`"), "{finding}");
            assert!(finding.contains(&format!("in {twin} differs from its block in {DOOR_RECORDING}")), "{finding}");
            assert!(finding.contains(&format!("{twin}: path: String")), "{finding}");
            assert!(finding.contains(&format!("{DOOR_RECORDING}: object_path: String")), "{finding}");
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
        assert!(findings[0].contains("`NodeRelay` is in core/wire/peer-request-surface.txt and not in"), "{}", findings[0]);
        assert!(findings[1].contains("`ReadFile`") && findings[1].contains("another order"), "{}", findings[1]);
    }

    /// The real recordings in this tree agree, so the gate starts green.
    #[test]
    fn the_recordings_in_this_tree_agree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(twin_findings(&root), Vec::<String>::new());
    }
}
