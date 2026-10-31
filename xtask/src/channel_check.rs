// SPDX-License-Identifier: AGPL-3.0-or-later
//! `channel-check`: one acceptor, one request type.
//!
//! [`RFC-0082`] fixes a convention: an IPC channel is a transport, the process
//! that accepts on it, and the message types carried — and **a request type is
//! the wire for exactly one acceptor**.
//!
//! The rule earns its place because breaking it is invisible. When two servers
//! deserialize the same type, they are two channels wearing one name, and every
//! property that differs between them — who may connect, what authenticates
//! them, which messages are meaningful — has to be re-checked at runtime by
//! something a person remembered to write. Measured 2026-08-23, `UserRequest`
//! was the wire type for both `kuserd` and `kuid`; `kuid` accepted four of its
//! 151 variants and rejected the other 147 with a catch-all arm.
//!
//! Three forms count as accepting. `ChannelAcceptor::<Req, Resp>::listen` binds a
//! path and waits. `serve_inherited::<Req, Resp, ..>` serves a channel handed
//! over at spawn — no path, no listener, and nobody to turn away.
//! `read_frame::<Req, _>` is the same handed channel read directly, by an
//! acceptor that cannot use `serve_inherited` because it also *speaks*: that
//! helper owns both halves of the transport, which is right for a channel that
//! only ever answers and wrong for one where replies share a descriptor with
//! messages the acceptor raises itself.
//!
//! A peer's bytes arrive by a fourth road, and it has one form.
//! `PeerDoor::<Req, Resp>::serving(..)` builds the `PeerHandler` a node hands
//! its peer transport, and it is the only thing that can: `PeerHandler` has a
//! private field and one constructor, in `core/peer/src/door.rs` (kotton #278).
//! A closure is not a `PeerHandler`, wherever it is put — a struct field, an
//! argument, a `Result` — so the compiler holds that a peer's bytes decode as
//! the `Req` at a `PeerDoor` site, and this check reads those sites alone. A
//! `PeerDoor` named any other way (its type inferred, aliased, imported under
//! another name) or whose `Req` is not one named type is refused: a door this
//! check cannot read is a finding, never a pass.
//!
//! Two decodes are findings by themselves. Any `serde_json` decode inside a
//! `PeerHandler` region — a function whose return type names `PeerHandler`,
//! or a `PeerDoor` call — is refused whatever its type: the door has already
//! decoded the request, and a second decode there is a request type smuggled
//! inside the first. And a decode that names a request type in [`CHANNELS`],
//! anywhere outside a door, is refused: a channel's request type is decoded
//! at its door and nowhere else.
//!
//! An acceptor is a crate *and* the transport it accepts on: a daemon's local
//! door and its peer wire are two channels even in one crate, with different
//! callers and different authentication, so one type decoded at both is two
//! acceptors. A type may have more than one only where its `CHANNELS` row names
//! them all.
//!
//! Each new form was added because moving a channel onto it read as the channel
//! disappearing. That happened to `kuid` on 2026-08-24 (bound → inherited) and
//! again on 2026-08-27 (inherited → split, when the compositor gained its own
//! direction). Both times this rule caught it, which is the argument for the
//! staleness rule below being an error rather than a warning.
//!
//! This check reads every such call site rather than
//! a list someone maintains, so a new server added tomorrow is seen whether or
//! not anyone updates the table.
//!
//! It reads code outside `#[cfg(test)] mod` blocks only. A test module's door
//! is never in a binary that serves anyone: it exercises a channel, it is not
//! one, and counting it would list a test's socket as an acceptor beside the
//! daemon's.
//!
//! What it holds is *who accepts which request type*. The response-type
//! column of [`CHANNELS`] is documentation only: no rule compares it with a
//! call site.
//!
//! ## What a text check cannot see
//!
//! - **A decode with no turbofish, outside a `PeerHandler` region.**
//!   `let r: UserRequest = serde_json::from_slice(&b)?` names its type in a
//!   binding, not the call, and outside a region it is read as no one's. It
//!   cannot make a peer acceptor — no closure becomes a `PeerHandler` — but
//!   the transports below `PeerHandler` (`Connection::serve_one_request` in
//!   `kotton_sys::net`) take a raw closure, and a daemon that served one there
//!   would decode a peer's bytes where this check does not look.
//! - **Other decoders.** It reads `serde_json`'s `from_slice`, `from_str`,
//!   `from_reader` and `from_value`, spelled with the crate path or bare. A
//!   decode with another format crate, or through a renamed import, is not
//!   read.
//! - **Where a region ends.** A `PeerHandler` region ends at the first line
//!   after its opening, comments aside, indented no deeper than the line that
//!   opened it — rustfmt's layout, not the parser's. A line of a multi-line
//!   string literal written at that indent ends it early.
//! - **A decode in a helper the door's closure calls, of a type the table
//!   does not name.** The door decodes `Req`; a closure that hands a field of
//!   it to a function defined elsewhere (`fn inner(r: &PeerRequest)` that
//!   decodes `r.blob` as `Settings`) decodes outside any region, and a type
//!   with no row in [`CHANNELS`] is no channel this check knows. It is neither
//!   counted nor refused. A text check cannot follow the call, and the type
//!   change cannot close it: what the door's `Req` carries is the request
//!   type's own design. A helper decoding a `CHANNELS` type by name is
//!   refused wherever it is.
//! - **A `#[cfg(test)]` item outside a module**, and a `#[cfg(test)]` module
//!   whose closing brace is not at its own indent, are read as code. Files
//!   under the suite directory at the repository root, `tests/`, are
//!   integration tests, in no binary that serves anyone, and a request type
//!   decoded by name there is not refused. A `tests/` directory anywhere else
//!   (`core/kuserd/src/tests/`) is code like any other.
//! - **One crate, one transport, one acceptor.** Two sites of the same form
//!   in one crate on one type are counted as one acceptor, so two doors of the
//!   same transport inside one daemon are not told apart.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Which transport an acceptor reads its request off.
///
/// `Ipc` is a socket bound or handed over on this machine: `ChannelAcceptor`,
/// `serve_inherited`, `read_frame`. `Peer` is the peer transport: a `PeerDoor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Transport {
    Ipc,
    Peer,
}

impl Transport {
    fn word(self) -> &'static str {
        match self {
            Transport::Ipc => "ipc",
            Transport::Peer => "peer",
        }
    }
}

/// An acceptor: the crate that decodes a request type, and the transport it
/// decodes it from.
type Acceptor = (&'static str, Transport);

use Transport::{Ipc, Peer};

/// The channels, keyed by request type. `RFC-0082`'s table, in code.
///
/// The response type is documentation only: no rule reads it.
///
/// The acceptors are the crates expected to serve the channel, each with its
/// transport. A row names more than one only where the type is shared on
/// purpose; a second acceptor this table does not name is refused. A row naming
/// no live acceptor, or an acceptor whose type is absent here, is a table that
/// has stopped describing the system.
///
/// "Owns the socket" was the old wording and it is no longer true of every row:
/// `kuid` owns no socket. `kuserd` makes a `socketpair` before forking and hands
/// kuid the far end, so that channel has no path and nothing to bind.
const CHANNELS: &[(&str, &str, &[Acceptor])] = &[
    // request type, response type, acceptors
    ("UserRequest", "UserResponse", &[("kuserd", Ipc)]),
    // A paired peer's verbs at a device, on the peer's own standing: the peer
    // wire's own type, so a door verb (`RecordInsert` among them) is an unknown
    // variant at the decoder rather than refused by an arm.
    ("PeerRequest", "UserResponse", &[("kuserd", Peer)]),
    // The vault's door: the verbs a keeper's landlord may speak, as their own
    // type so a plaintext verb is unconstructible there rather than refused by
    // an arm. The three that enrol and revoke the operator credential are the
    // door's alone. The landlord's verbs the operator's key also says on the
    // peer transport are `VaultPeerRequest`'s, the next row, where standing
    // decides (`control::landlord` answers six).
    ("VaultRequest", "UserResponse", &[("kvaultd", Ipc)]),
    // The vault's peer wire: a tenant's verbs and the landlord's, and none of
    // a device's. A device's verb is an unknown variant there.
    ("VaultPeerRequest", "UserResponse", &[("kvaultd", Peer)]),
    // Another person's door (RFC-0022, DEC-0055): one verb, reached only at a
    // per-pair mailbox whose verifier admits one key. A contact cannot name a
    // storage verb, rather than being refused for one.
    ("ContactRequest", "ContactResponse", &[("peer", Peer)]),
    ("DeviceRequest", "DeviceResponse", &[("kdeviced", Ipc)]),
    // The window's channel, the other way: `kuid`, which is not in this tree, is the
    // acceptor of `KuidRequest` in the reference and has no row here. `kuid` reports what it
    // observed and `kuserd` accepts it — a second type rather than a second transport,
    // because RFC-0082's rule is one acceptor per request *type*, not one
    // direction per channel.
    //
    // The row names `FromCompositor`, not `CompositorEvent`, because the
    // wrapper is what is actually on the wire: replies to `KuidRequest` share
    // this descriptor with events kuid raises itself, so the discriminator has
    // to be in the frame. Naming the inner type here would describe a channel
    // that carries less than it does — and this check caught that on the first
    // run after the row was written.
    ("FromCompositor", "()", &[("kuserd", Ipc)]),
    // The inference channel, the other way: `kinferd`, which is not in this tree, is the
    // acceptor of `InferRequest` in the reference and has no row here. A row for the same
    // reason `FromCompositor` has one: `kuserd` reads this type off the pipe itself,
    // so it is an acceptor of it. No wrapper is needed here where the
    // compositor needed one — `kinferd` raises nothing of its own, so every
    // frame on the up direction is an answer.
    ("InferResponse", "()", &[("kuserd", Ipc)]),
];

/// Directories that may contain an IPC acceptor.
use crate::tree::CODE_ROOTS as ROOTS;

pub fn channel_check() {
    let mut files = Vec::new();
    for root in ROOTS {
        collect_rs(Path::new(root), &mut files);
    }
    if files.is_empty() {
        eprintln!(
            "channel-check: found no Rust sources under {ROOTS:?}. Run from the workspace \
             root — this check has not looked at anything."
        );
        std::process::exit(1);
    }

    let survey = survey(Path::new(""), &files);
    if survey.found.is_empty() {
        eprintln!(
            "channel-check: found no acceptor call site in {} file(s). \
             Either every acceptor was removed, or the pattern this check greps for has \
             changed and it is now silently vacuous.",
            files.len()
        );
        std::process::exit(1);
    }

    println!("channel-check: request type, acceptor (transport), where it decodes:");
    for (req, sites) in &survey.found {
        for site in sites {
            println!(
                "  {req:<18} {:<20} {}",
                format!("{} ({})", site.krate, site.transport.word()),
                site.at
            );
        }
    }

    let problems = judge(&survey, CHANNELS);
    if problems.is_empty() {
        println!(
            "channel-check: OK — {} channel(s), each with the acceptors its row names ({} source \
             files scanned).",
            survey.found.len(),
            files.len()
        );
        return;
    }

    eprintln!("channel-check: one acceptor, one request type — a request type is the wire for exactly one acceptor.\n");
    for p in &problems {
        eprintln!("  - {p}\n");
    }
    std::process::exit(1);
}

/// One place a request type is decoded.
#[derive(Debug)]
struct Site {
    krate: String,
    transport: Transport,
    /// `path:line`.
    at: String,
}

/// What the sources say, before the table is consulted.
#[derive(Debug, Default)]
struct Survey {
    /// request type -> every site that decodes it
    found: BTreeMap<String, Vec<Site>>,
    /// Each `PeerDoor` this check cannot read: `path:line`, and what is wrong
    /// with it.
    unreadable: Vec<(String, String)>,
    /// Each `serde_json` decode inside a `PeerHandler` region: `path:line`, and
    /// the type argument as written (empty when there is none).
    inside: Vec<(String, String)>,
    /// Each decode outside a region that names its type, outside test modules
    /// and the root `tests/` suite:
    /// `path:line`, and the type. The table says which of them is a channel's
    /// request type.
    named: Vec<(String, String)>,
}

/// Read `files`, each named by its path under `root`, the workspace root the
/// check walks.
fn survey(root: &Path, files: &[PathBuf]) -> Survey {
    let mut survey = Survey::default();
    for path in files {
        let rel = path.strip_prefix(root).unwrap_or(path);
        // The transports' own source defines these entry points and exercises
        // them on throwaway types in its tests. Those are not channels, and
        // counting them would have this check reporting on itself. `PeerDoor`
        // decodes its type parameter inside the `PeerHandler` it builds; its
        // callers name the type, and are read as `PeerDoor` sites.
        let p = display(rel);
        if p.contains("core/ipc/src/provider/") || p.ends_with("core/peer/src/door.rs") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        survey_file(rel, &src, &mut survey);
    }
    survey
}

fn survey_file(path: &Path, src: &str, survey: &mut Survey) {
    let krate = acceptor_of(path);
    let p = display(path);
    // The integration suite at the repository root; not any `tests/` below it.
    let integration = p.starts_with("tests/");
    let tests = crate::docs_present_check::test_modules(src);
    let lines: Vec<&str> = src.lines().collect();
    let regions = handler_regions(&lines);
    for (n, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with("//") || tests.iter().any(|&(a, b)| (a..=b).contains(&(n + 1))) {
            continue;
        }
        let at = format!("{p}:{}", n + 1);
        let ipc = parse_listen(t)
            .or_else(|| parse_inherited(t))
            .or_else(|| parse_split(t))
            .map(|(req, _)| (req, Ipc));
        let mut decoded: Vec<(String, Transport)> = ipc.into_iter().collect();
        for door in peer_doors(&lines[n..]) {
            match door {
                Door::Named(req) => decoded.push((req, Peer)),
                Door::Unreadable(why) => survey.unreadable.push((at.clone(), why)),
            }
        }
        let in_region = regions.iter().any(|&(a, b)| (a..=b).contains(&n));
        for decode in decodes(&lines[n..]) {
            match decode {
                Decode::Named(arg) | Decode::Unreadable(arg) if in_region => {
                    survey.inside.push((at.clone(), arg))
                }
                Decode::Named(req) if !integration => survey.named.push((at.clone(), req)),
                _ => {}
            }
        }
        for (req, transport) in decoded {
            survey.found.entry(type_name(&req)).or_default().push(Site {
                krate: krate.clone(),
                transport,
                at: at.clone(),
            });
        }
    }
}

/// Hold the sources against the table.
fn judge(survey: &Survey, channels: &[(&str, &str, &[Acceptor])]) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    let named = |k: &str, t: Transport| format!("{k} ({})", t.word());

    // 1. A request type is accepted by exactly the acceptors its row names.
    //    Two the row does not name are two channels wearing one name.
    for (req, sites) in &survey.found {
        let Some((_, _, expected)) = channels.iter().find(|(r, _, _)| r == req) else {
            continue;
        };
        let mut who: Vec<(&str, Transport)> = sites
            .iter()
            .map(|s| (s.krate.as_str(), s.transport))
            .collect();
        who.sort_unstable();
        who.dedup();
        let strangers: Vec<&(&str, Transport)> = who
            .iter()
            .filter(|a| !expected.iter().any(|e| e.0 == a.0 && e.1 == a.1))
            .collect();
        if strangers.is_empty() {
            continue;
        }
        let where_ = sites
            .iter()
            .map(|s| s.at.as_str())
            .collect::<Vec<_>>()
            .join("\n      ");
        let rows = expected
            .iter()
            .map(|&(k, t)| named(k, t))
            .collect::<Vec<_>>()
            .join(", ");
        if who.len() > 1 {
            problems.push(format!(
                "`{req}` is the wire type for {} acceptors ({}), and CHANNELS names {rows}:\n      \
                 {where_}\n    Two channels wearing one name. Every difference between them — \
                 who may connect, what authenticates them, which messages mean anything — is \
                 enforced at runtime or not at all. Give each its own type, or name every \
                 acceptor in the row if they share it on purpose.",
                who.len(),
                who.iter().map(|&(k, t)| named(k, t)).collect::<Vec<_>>().join(", "),
            ));
        } else {
            problems.push(format!(
                "`{req}` is accepted by {} at:\n      {where_}\n    but CHANNELS names {rows}. \
                 Either the acceptor moved and the row should say so, or this is a second \
                 channel on someone else's type.",
                named(strangers[0].0, strangers[0].1),
            ));
        }
    }

    // 2. Every accepted type appears in the table.
    for (req, sites) in &survey.found {
        if !channels.iter().any(|(r, _, _)| r == req) {
            problems.push(format!(
                "`{req}` is accepted at {} but has no row in CHANNELS. A channel nobody \
                 recorded is one nobody reviewed.",
                sites[0].at
            ));
        }
    }

    // 3. Every acceptor a row names actually accepts its type — the staleness
    //    rule. A row for a channel that no longer exists reads as a decision
    //    when it is a leftover.
    for (req, _, expected) in channels {
        for a in *expected {
            let live = survey
                .found
                .get(*req)
                .is_some_and(|sites| sites.iter().any(|s| s.krate == a.0 && s.transport == a.1));
            if !live {
                problems.push(format!(
                    "CHANNELS names `{req}` (acceptor {}) but it does not accept it. Either \
                     the channel is gone and the row should be, or the acceptor moved and this \
                     check is no longer watching it.",
                    named(a.0, a.1)
                ));
            }
        }
    }

    // 4. A `PeerDoor` whose request type this check cannot read.
    for (at, why) in &survey.unreadable {
        problems.push(format!(
            "{at} builds a peer door {why}. This check cannot say which channel that is; \
             name the request type at the call, `{DOOR}::<Req, Resp>::serving(..)`."
        ));
    }

    // 5. A decode inside a `PeerHandler` region, whatever its type.
    for (at, arg) in &survey.inside {
        let what = if arg.is_empty() {
            String::new()
        } else {
            format!(" as `{arg}`")
        };
        problems.push(format!(
            "{at} decodes{what} inside a `PeerHandler`. The `{DOOR}` has already decoded the \
             peer's request; a second decode there is a request type carried inside the first, \
             a door no row names. Give it a field of the request type instead."
        ));
    }

    // 6. A channel's request type decoded by name outside its door.
    for (at, req) in &survey.named {
        let name = type_name(req);
        if channels.iter().any(|(r, _, _)| *r == name) {
            problems.push(format!(
                "{at} decodes `{name}`, a channel's request type, outside its door. A request \
                 type is decoded where its channel accepts it — `{DOOR}`, `ChannelAcceptor`, \
                 `serve_inherited`, `read_frame` — and nowhere else."
            ));
        }
    }

    problems
}

/// The last path segment: `kotton_wire::ipc::VaultPeerRequest` →
/// `VaultPeerRequest`. The table keys types by name, however a site spells
/// the path to them.
fn type_name(req: &str) -> String {
    req.rsplit("::").next().unwrap_or(req).trim().to_string()
}

/// The names this check reads, spelled in pieces: this file is under a root the
/// check walks, and a whole name in its code would be read as a door.
const DOOR: &str = concat!("Peer", "Door");
const HANDLER: &str = concat!("Peer", "Handler");

/// The `PeerHandler` regions of a file, as 0-based inclusive line ranges: each
/// function whose return type names `PeerHandler`, and each `PeerDoor` call.
///
/// A region ends at the first line after its opening — comments and blank
/// lines aside — indented no deeper than the line that opened it. A struct
/// field typed `Box<dyn Fn() -> PeerHandler>` is no function, and opens none.
fn handler_regions(lines: &[&str]) -> Vec<(usize, usize)> {
    let indent = |l: &str| l.len() - l.trim_start().len();
    let close_after = |open: usize, body: usize| -> usize {
        (body + 1..lines.len())
            .find(|&k| {
                let t = lines[k].trim();
                !t.is_empty() && !t.starts_with("//") && indent(lines[k]) <= indent(lines[open])
            })
            .unwrap_or(lines.len().saturating_sub(1))
    };
    let mut out = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if is_fn_item(t) {
            // The signature runs to the line that opens the body, or ends a
            // declaration with no body.
            let Some(body) = (n..lines.len().min(n + 24))
                .find(|&k| lines[k].contains('{') || lines[k].trim_end().ends_with(';'))
            else {
                continue;
            };
            if !lines[body].contains('{') {
                continue;
            }
            let sig: String = lines[n..=body].concat();
            let sig = &sig[..sig.find('{').unwrap_or(sig.len())];
            let returns = sig
                .find("->")
                .is_some_and(|i| has_word(&sig[i..], HANDLER));
            if !returns {
                continue;
            }
            let b = lines[body];
            let one_line = b.matches('{').count() == b.matches('}').count();
            out.push((n, if one_line { body } else { close_after(n, body) }));
        } else if has_word(t, DOOR) && t.contains(&format!("{DOOR}::<")) {
            out.push((n, close_after(n, n)));
        }
    }
    out
}

/// A line that begins a function item: `fn`, after any of `pub`, `pub(..)`,
/// `async`, `const`, `unsafe`, `extern "C"`.
fn is_fn_item(t: &str) -> bool {
    let mut rest = t;
    loop {
        if let Some(r) = rest.strip_prefix("fn ") {
            return !r.is_empty();
        }
        let word_end = if rest.starts_with("pub(") {
            rest.find(')').map(|i| i + 1)
        } else {
            rest.find(' ')
        };
        let Some(end) = word_end else {
            return false;
        };
        let word = &rest[..end];
        let modifier = word.starts_with("pub")
            || ["async", "const", "unsafe", "extern", "\"C\"", "\"Rust\""].contains(&word);
        if !modifier {
            return false;
        }
        rest = rest[end..].trim_start();
    }
}

/// `word` appears in `text` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(word).any(|(i, _)| {
        !text[..i].ends_with(is_ident) && !text[i + word.len()..].starts_with(is_ident)
    })
}

/// A `serde_json` decode, as written.
#[derive(Debug, PartialEq, Eq)]
enum Decode {
    /// `serde_json::from_slice::<T>`: one named type.
    Named(String),
    /// A decode whose type argument is not one named type, as written; empty
    /// when there is no turbofish at all.
    Unreadable(String),
}

/// The decoders this check reads.
const DECODERS: &[&str] = &["from_slice", "from_str", "from_reader", "from_value"];

/// The `serde_json` decodes that begin on `lines[0]`.
///
/// Inside a `PeerHandler` region every one is refused; outside, one that names
/// a channel's request type is. Any other decode outside a region is a client
/// reading an answer, or a file read back, and is no acceptor.
///
/// The turbofish is gathered from the following lines when it is wrapped, as
/// rustfmt wraps a long one.
fn decodes(lines: &[&str]) -> Vec<Decode> {
    let first = lines.first().copied().unwrap_or_default();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some((at, name)) = DECODERS
        .iter()
        .filter_map(|d| first[from..].find(d).map(|i| (from + i, *d)))
        .min()
    {
        from = at + name.len();
        let before = &first[..at];
        let after = &first[from..];
        // `serde_json::from_slice`, or bare `from_slice` from a `use`; not
        // `Vec::from_slice`, `x.from_str`, or a longer identifier.
        let ident_before = before.ends_with(|c: char| c.is_alphanumeric() || c == '_');
        let other_path = before.ends_with("::") && !before.ends_with("serde_json::");
        if ident_before || other_path || before.ends_with('.') {
            continue;
        }
        if after.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
            continue;
        }
        // No turbofish: inferred from a binding, or the function passed by
        // name (`.and_then(serde_json::from_slice)`). Either way, unnamed here.
        out.push(match turbofish(after, &lines[1..]) {
            None => Decode::Unreadable(String::new()),
            Some(Ok(args)) => match args.as_slice() {
                [one] if one_path(one) => Decode::Named(one.clone()),
                _ => Decode::Unreadable(args.join(",")),
            },
            Some(Err(open)) => Decode::Unreadable(open),
        });
    }
    out
}

/// The turbofish that `after` opens, read over as many of `more` as it takes:
/// its top-level arguments with whitespace removed, and the text after its
/// closing `>`. `None` when `after` opens none; `Err` with what was read when
/// it never closes.
fn turbofish_with_rest(after: &str, more: &[&str]) -> Option<Result<(Vec<String>, String), String>> {
    let mut text = after.to_string();
    for m in more.iter().take(8) {
        text.push_str(m.trim());
    }
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let rest = text.strip_prefix("::<")?;
    let mut depth = 1;
    let mut args = vec![String::new()];
    for (i, c) in rest.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 1 => {
                args.push(String::new());
                continue;
            }
            _ => {}
        }
        if depth == 0 {
            // rustfmt leaves a trailing comma on a turbofish it wraps.
            if args.len() > 1 && args.last().is_some_and(|a| a.is_empty()) {
                args.pop();
            }
            return Some(Ok((args, rest[i + 1..].to_string())));
        }
        args.last_mut().unwrap().push(c);
    }
    Some(Err(format!("{}…", rest.chars().take(40).collect::<String>())))
}

fn turbofish(after: &str, more: &[&str]) -> Option<Result<Vec<String>, String>> {
    turbofish_with_rest(after, more).map(|r| r.map(|(args, _)| args))
}

/// One type path: `kotton_wire::ipc::VaultPeerRequest`, not `_`, a tuple, a
/// generic or a reference.
fn one_path(arg: &str) -> bool {
    !arg.is_empty()
        && arg != "_"
        && arg.split("::").all(|seg| {
            !seg.is_empty()
                && seg.chars().all(|c| c.is_alphanumeric() || c == '_')
                && !seg.starts_with(|c: char| c.is_ascii_digit())
        })
}

/// A `PeerDoor` named on `lines[0]`.
#[derive(Debug, PartialEq, Eq)]
enum Door {
    /// `PeerDoor::<Req, Resp>::serving(..)`: an acceptor of `Req` on the peer
    /// transport.
    Named(String),
    /// A door this check cannot read, and why.
    Unreadable(String),
}

/// Every `PeerDoor` named on `lines[0]`, read over the following lines when
/// rustfmt wraps its turbofish.
///
/// A door on a peer circuit is an acceptor as a listener is: a thing that
/// deserializes a wire type. The one form read is the call with both type
/// parameters written; a bare name ends an import (`use ..::PeerDoor;`,
/// `{door::PeerDoor, ..}`) and is no door. Anything else — the type inferred
/// from the closure (`PeerDoor::serving`), an alias (`PeerDoor<A, B>` in type
/// position), a rename (`PeerDoor as D`), a request type that is not one path
/// — is a door whose type the call site does not say.
fn peer_doors(lines: &[&str]) -> Vec<Door> {
    let first = lines.first().copied().unwrap_or_default();
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for (i, _) in first.match_indices(DOOR) {
        let after = &first[i + DOOR.len()..];
        if first[..i].ends_with(is_ident) || after.starts_with(is_ident) {
            continue;
        }
        let next = after.trim_start();
        if next.is_empty() || next.starts_with([',', ';', '}']) {
            continue;
        }
        out.push(match turbofish_with_rest(after, &lines[1..]) {
            Some(Ok((args, rest))) if rest.starts_with("::serving") => match args.as_slice() {
                [req, _resp] if one_path(req) => Door::Named(req.clone()),
                [req, _resp] => {
                    Door::Unreadable(format!("on `{req}`, which is not one named type"))
                }
                _ => Door::Unreadable(format!("as `{DOOR}::<{}>`", args.join(","))),
            },
            None if next.starts_with("as ") => Door::Unreadable("under another name".to_string()),
            _ => Door::Unreadable(
                format!("that is not a `{DOOR}::<Req, Resp>::serving` call"),
            ),
        });
    }
    out
}

/// `serve_inherited::<Req, Resp, ..>` → `(Req, Resp)`.
///
/// The acceptor of a channel it was handed rather than one it bound.
fn parse_inherited(line: &str) -> Option<(String, String)> {
    let i = line.find("serve_inherited::<")?;
    let rest = &line[i + "serve_inherited::<".len()..];
    let close = rest.find('>')?;
    let mut parts = rest[..close].split(',').map(|p| p.trim());
    let req = parts.next()?.to_string();
    let resp = parts.next()?.to_string();
    if req.is_empty() || resp.is_empty() {
        return None;
    }
    Some((req, resp))
}

/// `read_frame::<Req, _>` → `(Req, "()")`.
///
/// The split form: an acceptor that reads the request type off a handed channel
/// itself, because it also writes messages of its own onto the same descriptor
/// and so cannot hand both halves to `serve_inherited`.
///
/// There is no response type to recover from the call — replies leave by another
/// path — so `()` stands in. That is honest rather than lossy: what this check
/// enforces is *who accepts which request type*, and a split acceptor answers
/// that question exactly as well as a bound one.
fn parse_split(line: &str) -> Option<(String, String)> {
    let i = line.find("read_frame::<")?;
    let rest = &line[i + "read_frame::<".len()..];
    let close = rest.find('>')?;
    let req = rest[..close].split(',').next()?.trim().to_string();
    if req.is_empty() {
        return None;
    }
    Some((req, "()".to_string()))
}

/// `ChannelAcceptor::<Req, Resp>::listen` → `(Req, Resp)`.
fn parse_listen(line: &str) -> Option<(String, String)> {
    let i = line.find("ChannelAcceptor::<")?;
    let rest = &line[i + "ChannelAcceptor::<".len()..];
    let close = rest.find('>')?;
    if !rest[close..].starts_with(">::listen") {
        return None;
    }
    let (a, b) = rest[..close].split_once(',')?;
    Some((a.trim().to_string(), b.trim().to_string()))
}

/// The crate a file belongs to: the directory holding its `src/`.
fn acceptor_of(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    match s.split_once("/src/") {
        Some((crate_dir, _)) => crate_dir
            .rsplit('/')
            .next()
            .unwrap_or(crate_dir)
            .to_string(),
        None => s,
    }
}

fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name == "target" || name == ".git" {
                continue;
            }
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Each case writes a throwaway tree and reads it as the check does.
///
/// The fixtures spell the forms the check reads in pieces (`concat!`, and the
/// module's [`DOOR`] and [`HANDLER`]), because this file is itself under a root
/// the check walks: written whole, a fixture would be read as an acceptor of
/// the tree.
#[cfg(test)]
mod tests {
    use super::*;

    const DECODE: &str = concat!("serde_json::from_", "slice");
    const LISTEN: &str = concat!("Channel", "Acceptor");

    /// A daemon's local door accepting `req`, as kuserd's does.
    fn door(req: &str) -> String {
        format!("fn serve() {{\n    let a = {LISTEN}::<{req}, UserResponse>::listen(&path)?;\n}}\n")
    }

    /// A peer acceptor, as kvaultd's and kuserd's are: a function returning
    /// `ret` that builds a `PeerDoor` of `req`.
    fn peer_door(ret: &str, req: &str) -> String {
        format!(
            "impl Daemon {{\n    fn peer_handler(&self) -> {ret} {{\n        \
             let ctx = Arc::clone(&self.ctx);\n        \
             {DOOR}::<{req}, UserResponse>::serving(\n            \
             move |peer_did, request| {{\n                \
             let ctx = Arc::clone(&ctx);\n                \
             async move {{ serve(&ctx, &peer_did, request).await }}\n            }},\n            \
             |e| UserResponse::Error {{ message: format!(\"invalid: {{e}}\") }},\n        \
             )\n    }}\n}}\n"
        )
    }

    fn tree(files: &[(&str, String)]) -> (tempfile::TempDir, Survey) {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for (rel, src) in files {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, src).unwrap();
            paths.push(p);
        }
        let survey = survey(dir.path(), &paths);
        (dir, survey)
    }

    fn acceptors(survey: &Survey, req: &str) -> Vec<(String, Transport)> {
        survey
            .found
            .get(req)
            .map(|sites| {
                sites
                    .iter()
                    .map(|s| (s.krate.clone(), s.transport))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The problems that name `rel` at `line`.
    fn at(problems: &[String], rel: &str, line: usize) -> bool {
        problems.iter().any(|p| p.contains(&format!("{rel}:{line} ")))
    }

    /// The 1-based lines of `src` that contain `needle`.
    fn lines_with(src: &str, needle: &str) -> Vec<usize> {
        src.lines()
            .enumerate()
            .filter(|(_, l)| l.contains(needle))
            .map(|(n, _)| n + 1)
            .collect()
    }

    /// The tree as it stands today, in miniature: every row of the table has
    /// its acceptor, so each case below changes one thing.
    fn as_it_stands() -> Vec<(&'static str, String)> {
        vec![
            (
                "core/kuserd/src/agent/mod.rs",
                door("UserRequest") + &peer_door(HANDLER, "PeerRequest"),
            ),
            (
                "core/kvaultd/src/lib.rs",
                door("VaultRequest")
                    + &peer_door(
                        &format!("kotton_peer::{HANDLER}"),
                        "kotton_wire::ipc::VaultPeerRequest",
                    ),
            ),
            (
                "core/peer/src/contact_door.rs",
                format!(
                    "pub fn contact_door<F>(take: F) -> {HANDLER}\nwhere\n    F: Send,\n{{\n    \
                     {DOOR}::<ContactRequest, ContactResponse>::serving(\n        \
                     move |_peer_did, request| take(request),\n        \
                     |e| ContactResponse::Refused {{ reason: e }},\n    )\n}}\n"
                ),
            ),
            (
                "core/kdeviced/src/system.rs",
                format!(
                    "{}::<DeviceRequest, DeviceResponse, _>(fd)\n",
                    concat!("serve_", "inherited")
                ),
            ),
            (
                "core/kuserd/src/surface_proxy.rs",
                format!(
                    "{}::<FromCompositor, _>(&mut r)\n",
                    concat!("read_", "frame")
                ),
            ),
            (
                "core/kuserd/src/infer_proxy.rs",
                format!(
                    "{}::<InferResponse, _>(&mut r)\n",
                    concat!("read_", "frame")
                ),
            ),
        ]
    }

    fn with(
        mut files: Vec<(&'static str, String)>,
        rel: &'static str,
        src: String,
    ) -> Vec<(&'static str, String)> {
        files.retain(|(r, _)| *r != rel);
        files.push((rel, src));
        files
    }

    #[test]
    fn the_tree_in_miniature_passes() {
        let (_dir, survey) = tree(&as_it_stands());
        assert_eq!(judge(&survey, CHANNELS), Vec::<String>::new());
    }

    #[test]
    fn a_peer_door_is_an_acceptor_on_the_peer_transport() {
        let (_dir, survey) = tree(&as_it_stands());
        assert_eq!(
            acceptors(&survey, "PeerRequest"),
            vec![("kuserd".to_string(), Transport::Peer)]
        );
        // A path to the type and a path to the handler both read as the name.
        assert_eq!(
            acceptors(&survey, "VaultPeerRequest"),
            vec![("kvaultd".to_string(), Transport::Peer)]
        );
        assert_eq!(
            acceptors(&survey, "ContactRequest"),
            vec![("peer".to_string(), Transport::Peer)]
        );
    }

    #[test]
    fn a_decode_outside_a_handler_that_names_no_channel_is_no_acceptor() {
        let client = format!(
            "fn ask() -> Result<UserResponse> {{\n    let r = {DECODE}::<UserResponse>(&bytes)?;\n    Ok(r)\n}}\n\
             fn after() {{\n    let s = {DECODE}::<Settings>(&b)?;\n}}\n"
        );
        let files = with(as_it_stands(), "core/device/src/client.rs", client);
        let (_dir, survey) = tree(&files);
        assert!(!survey.found.contains_key("UserResponse"), "{:?}", survey.found);
        assert_eq!(judge(&survey, CHANNELS), Vec::<String>::new());
    }

    /// The shapes `kotton #279` names: a closure handed to something
    /// peer-facing without a signature that says `-> PeerHandler` — a struct
    /// field typed as one, an argument, a `Result<PeerHandler>`. None of them
    /// compiles now (a closure is not a `PeerHandler`); the check refuses each
    /// all the same, because each decodes a channel's request type outside its
    /// door. On the check before `kotton #278` all three passed.
    #[test]
    fn a_raw_decode_in_a_closure_handed_to_anything_peer_facing_is_refused() {
        let closure = format!(
            "Arc::new(move |_, b: Vec<u8>| {{\n            \
             pinned(async move {{\n                \
             let r = {DECODE}::<UserRequest>(&b);\n            }})\n        }})"
        );
        let src = format!(
            "fn field() {{\n    inboxes.push(DmInbox {{\n        own: k,\n        handler: {closure},\n    }});\n}}\n\
             fn argument(rt: &Runtime) {{\n    rt.serve_introductions(\n        {closure},\n    );\n}}\n\
             fn wrapped() -> Result<{HANDLER}> {{\n    Ok({closure})\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src.clone());
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        let decodes = lines_with(&src, DECODE);
        assert_eq!(decodes.len(), 3, "{src}");
        for line in decodes {
            assert!(at(&problems, "core/kx/src/lib.rs", line), "line {line} passed: {problems:#?}");
        }
    }

    /// The case that went unflagged: a second crate's peer acceptor decoding
    /// the local door's type.
    #[test]
    fn a_second_acceptor_of_user_request_fails_naming_both_sites() {
        let files = with(
            as_it_stands(),
            "core/kvaultd/src/lib.rs",
            door("VaultRequest")
                + &peer_door(
                    &format!("kotton_peer::{HANDLER}"),
                    "kotton_wire::ipc::UserRequest",
                ),
        );
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        let two = problems
            .iter()
            .find(|p| p.starts_with("`UserRequest` is the wire type for 2 acceptors"))
            .unwrap_or_else(|| panic!("{problems:#?}"));
        assert!(two.contains("kuserd (ipc), kvaultd (peer)"), "{two}");
        assert!(two.contains("core/kuserd/src/agent/mod.rs:2"), "{two}");
        assert!(two.contains("core/kvaultd/src/lib.rs:"), "{two}");
    }

    /// kuserd's peer wire swapped back to the door's type is two acceptors in
    /// one crate: the door and the peer transport are two channels.
    #[test]
    fn the_peer_wire_swapped_back_to_user_request_is_refused() {
        let files = with(
            as_it_stands(),
            "core/kuserd/src/agent/mod.rs",
            door("UserRequest") + &peer_door(HANDLER, "UserRequest"),
        );
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        assert!(
            problems.iter().any(|p| p.starts_with(
                "`UserRequest` is the wire type for 2 acceptors (kuserd (ipc), kuserd (peer))"
            )),
            "{problems:#?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("CHANNELS names `PeerRequest`")),
            "{problems:#?}"
        );
    }

    #[test]
    fn two_acceptors_pass_only_where_the_row_names_both() {
        let files = with(
            as_it_stands(),
            "core/kvaultd/src/lib.rs",
            door("VaultRequest") + &peer_door(HANDLER, "UserRequest"),
        );
        let (_dir, survey) = tree(&files);
        let shared: Vec<(&str, &str, &[Acceptor])> = CHANNELS
            .iter()
            .filter(|(r, _, _)| *r != "VaultPeerRequest")
            .map(|&(r, s, a)| {
                if r == "UserRequest" {
                    (r, s, &[("kuserd", Ipc), ("kvaultd", Peer)][..])
                } else {
                    (r, s, a)
                }
            })
            .collect();
        assert_eq!(judge(&survey, &shared), Vec::<String>::new());
    }

    #[test]
    fn an_acceptor_the_row_does_not_name_is_refused() {
        let files = with(
            as_it_stands(),
            "core/kuserd/src/agent/mod.rs",
            door("UserRequest") + &door("PeerRequest"),
        );
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        assert!(
            problems
                .iter()
                .any(|p| p.starts_with("`PeerRequest` is accepted by kuserd (ipc)")),
            "{problems:#?}"
        );
    }

    /// Inside a `PeerHandler` region the door has already decoded; a decode
    /// there is refused whatever it names — a type, none, `_`, a tuple, the
    /// function passed by name — over a signature that runs across lines.
    #[test]
    fn any_decode_inside_a_handler_is_refused() {
        let src = format!(
            "fn h(\n    x: u8,\n) -> Option<kotton_peer::{HANDLER}>\nwhere\n    F: Send,\n{{\n    \
             Some({DOOR}::<Envelope, UserResponse>::serving(\n        |_, env| async move {{\n            \
             let a = {DECODE}::<Settings>(&env.body);\n            \
             let b: UserRequest = {DECODE}(&env.body)?;\n            \
             let c = {DECODE}::<_>(&env.body);\n            \
             let d = {DECODE}::<(kotton_wire::ipc::UserRequest, u8)>(&env.body);\n            \
             let e = Ok(env.body).and_then({DECODE});\n        }},\n        \
             |e| UserResponse::Error {{ message: e }},\n    ))\n}}\n\
             fn after() {{\n    let s = {DECODE}::<Settings>(&x);\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src.clone());
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        let decodes = lines_with(&src, DECODE);
        assert_eq!(decodes.len(), 6, "{src}");
        let (inside, after) = decodes.split_at(5);
        for &line in inside {
            assert!(
                problems.iter().any(|p| p
                    .contains(&format!("core/kx/src/lib.rs:{line} decodes"))
                    && p.contains(concat!("inside a `Peer", "Handler`"))),
                "line {line}: {problems:#?}"
            );
        }
        assert!(!at(&problems, "core/kx/src/lib.rs", after[0]), "{problems:#?}");
    }

    /// rustfmt wraps a long turbofish over lines; the door is the same
    /// acceptor, and a third crate's is still a third acceptor.
    #[test]
    fn a_door_wrapped_over_lines_is_an_acceptor() {
        let src = format!(
            "fn h() -> kotton_peer::{HANDLER} {{\n    {DOOR}::<\n        \
             kotton_wire::ipc::UserRequest,\n        kotton_wire::ipc::UserResponse,\n    \
             >::serving(|_, r| async move {{ answer(r) }}, |e| refuse(e))\n}}\n"
        );
        let files = with(as_it_stands(), "core/kdeviced/src/peer.rs", src);
        let (_dir, survey) = tree(&files);
        assert!(
            acceptors(&survey, "UserRequest").contains(&("kdeviced".to_string(), Transport::Peer)),
            "{:?}",
            survey.found
        );
        let problems = judge(&survey, CHANNELS);
        assert!(
            problems.iter().any(|p| p.starts_with(
                "`UserRequest` is the wire type for 2 acceptors (kdeviced (peer), kuserd (ipc))"
            ) && p.contains("core/kdeviced/src/peer.rs:2")),
            "{problems:#?}"
        );
    }

    /// A door whose request type the call site does not say: inferred from the
    /// closure, aliased, imported under another name, or not one named type.
    /// A plain import names no door.
    #[test]
    fn a_door_that_does_not_name_its_request_type_is_refused() {
        let src = format!(
            "use kotton_peer::door::{DOOR};\nuse kotton_peer::{{door::{DOOR}, {HANDLER}}};\n\
             fn inferred() -> {HANDLER} {{\n    {DOOR}::serving(|_, r: UserRequest| async move {{ answer(r) }}, refuse)\n}}\n\
             type Aliased = {DOOR}<UserRequest, UserResponse>;\n\
             use kotton_peer::door::{DOOR} as Renamed;\n\
             fn tuple() -> {HANDLER} {{\n    {DOOR}::<(UserRequest, u8), UserResponse>::serving(serve, refuse)\n}}\n\
             fn generic<R>() -> {HANDLER} {{\n    {DOOR}::<Vec<u8>, UserResponse>::serving(serve, refuse)\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src.clone());
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        for line in [4, 6, 7, 9, 12] {
            assert!(
                problems
                    .iter()
                    .any(|p| p.contains(&format!("core/kx/src/lib.rs:{line} builds a peer door"))),
                "line {line}: {problems:#?}"
            );
        }
        for line in [1, 2] {
            assert!(!at(&problems, "core/kx/src/lib.rs", line), "line {line}: {problems:#?}");
        }
        assert!(!survey.found.contains_key("u8)"), "{:?}", survey.found);
    }

    /// The decode that used to be a stated limit, in a helper the handler
    /// calls, is refused by name: a channel's request type is decoded at its
    /// door and nowhere else.
    #[test]
    fn a_request_type_decoded_in_a_helper_is_refused() {
        let src = format!(
            "fn decode(b: &[u8]) -> Result<UserRequest> {{\n    Ok({DECODE}::<UserRequest>(b)?)\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src);
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        assert!(
            problems.iter().any(|p| p
                .contains("core/kx/src/lib.rs:2 decodes `UserRequest`, a channel's request type")),
            "{problems:#?}"
        );
    }

    /// A stated limit, held so that it stays stated: a decode that names its
    /// type only in a binding, outside a `PeerHandler` region, is read as no
    /// one's. It cannot be a peer acceptor (a closure is not a `PeerHandler`);
    /// the module doc lists the transports below `PeerHandler` where it could
    /// still be one, under "What a text check cannot see".
    #[test]
    fn an_inferred_decode_outside_a_handler_is_not_read() {
        let src = format!(
            "fn serve(conn: Conn) {{\n    conn.serve_one_request(|b| async move {{\n        \
             let r: UserRequest = {DECODE}(&b).unwrap();\n    }});\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src);
        let (_dir, survey) = tree(&files);
        assert_eq!(judge(&survey, CHANNELS), Vec::<String>::new());
    }

    /// A field typed `Arc<dyn Fn() -> PeerHandler>` is no function returning a
    /// handler: it opens no region, and a decode after it is a client's.
    #[test]
    fn a_field_whose_type_returns_a_handler_opens_no_region() {
        let src = format!(
            "struct Builders {{\n    builder: Arc<dyn Fn() -> {HANDLER}>,\n    n: u8,\n}}\n\
             fn read() {{\n    let s = {DECODE}::<Settings>(&b)?;\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src);
        let (_dir, survey) = tree(&files);
        assert!(survey.inside.is_empty(), "{:?}", survey.inside);
        assert_eq!(judge(&survey, CHANNELS), Vec::<String>::new());
    }

    /// An integration test decodes request types to assert what does not
    /// decode; it is in no binary that serves anyone.
    #[test]
    fn a_request_type_decoded_under_tests_is_not_refused() {
        let src = format!("fn a() {{\n    assert!({DECODE}::<UserRequest>(b).is_err());\n}}\n");
        let files = with(as_it_stands(), "tests/tests/suite/kx.rs", src);
        let (_dir, survey) = tree(&files);
        assert_eq!(judge(&survey, CHANNELS), Vec::<String>::new());
    }

    /// A `tests/` directory inside a crate's `src/` is code in the crate, not
    /// the integration suite: a request type decoded by name there is refused.
    #[test]
    fn a_request_type_decoded_under_a_crates_src_tests_is_refused() {
        let src = format!("fn replay(b: &[u8]) {{\n    let r = {DECODE}::<UserRequest>(b);\n}}\n");
        let files = with(as_it_stands(), "core/kuserd/src/tests/replay.rs", src);
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        assert!(
            problems.iter().any(|p| p.contains(
                "core/kuserd/src/tests/replay.rs:2 decodes `UserRequest`, a channel's request type"
            )),
            "{problems:#?}"
        );
    }

    /// A stated limit, held so that it stays stated: a helper the door's
    /// closure calls, decoding a field of the request as a type the table does
    /// not name, is outside every region and is no channel this check knows.
    /// It is neither counted nor refused. The module doc lists it under "What
    /// a text check cannot see"; a `CHANNELS` type in the same place is
    /// refused (`a_request_type_decoded_in_a_helper_is_refused`).
    #[test]
    fn a_decode_in_a_helper_called_from_a_door_is_not_seen() {
        let src = format!(
            "fn h() -> {HANDLER} {{ {DOOR}::<PeerRequest, UserResponse>::serving(|_, r| async move {{ inner(&r) }}, refuse) }}\n\
             fn inner(r: &PeerRequest) -> UserResponse {{\n    let s = {DECODE}::<Settings>(&r.blob);\n    answer(s)\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src);
        let (_dir, survey) = tree(&files);
        assert!(survey.inside.is_empty(), "{:?}", survey.inside);
        assert!(!survey.found.contains_key("Settings"), "{:?}", survey.found);
        let problems = judge(&survey, CHANNELS);
        assert!(
            !problems.iter().any(|p| p.contains("core/kx/src/lib.rs:3")),
            "{problems:#?}"
        );
    }

    /// A test module's door is in no binary that serves anyone.
    #[test]
    fn a_door_inside_a_test_module_is_not_an_acceptor() {
        let src = format!(
            "fn real() {{}}\n\n#[cfg(test)]\nmod tests {{\n    async fn a_door() {{\n        \
             let s = {LISTEN}::<UserRequest, UserResponse>::listen(e).await;\n    }}\n}}\n"
        );
        let files = with(as_it_stands(), "core/kuserd/src/agent/streamed.rs", src);
        let (_dir, survey) = tree(&files);
        assert!(
            !survey.found["UserRequest"]
                .iter()
                .any(|s| s.at.contains("streamed.rs")),
            "{:?}",
            survey.found
        );
    }
}
