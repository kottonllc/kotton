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
    for channel in CHANNELS {
        check_channel(channel, bless);
    }
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
