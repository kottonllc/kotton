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
//! A peer's bytes arrive by a fourth road. A `PeerHandler` is the closure a node
//! hands its peer transport, and the acceptors that predate `PeerDoor` decode
//! inside one with `serde_json::from_slice::<Req>`. That call, inside a function
//! that returns a `PeerHandler` (or a binding typed as one), is an acceptor of
//! `Req` on the peer transport, however the turbofish is wrapped across lines.
//! Any `serde_json` decode there whose type argument is not one named type — no
//! turbofish, `_`, a tuple, a generic — is refused: a decode this check cannot
//! read is a finding, never a pass.
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
//! call site, and the `PeerHandler` form has no response type to read.
//!
//! ## What a text check cannot see
//!
//! - **A decode in a helper.** A `PeerHandler` closure that hands its bytes to
//!   a function defined elsewhere (`fn decode(b: &[u8]) -> Result<UserRequest>`)
//!   decodes outside the handler's text, and is neither counted nor refused.
//!   `PeerDoor` is the way to build a peer acceptor this check reads whole.
//! - **Braces in a string or char literal.** The end of a `PeerHandler` is
//!   found by counting `{` and `}` on each line, literals included. A `"{"`
//!   with no partner can end the handler early (a decode after it is missed)
//!   or late (a decode after it is read as the handler's).
//! - **Other decoders.** It reads `serde_json`'s `from_slice`, `from_str`,
//!   `from_reader` and `from_value`, spelled with the crate path or bare. A
//!   decode with another format crate, or through a renamed import, is not
//!   read.
//! - **A `#[cfg(test)]` item outside a module**, and a `#[cfg(test)]` module
//!   whose closing brace is not at its own indent, are read as code.
//! - **One crate, one transport, one acceptor.** Two sites of the same form
//!   in one crate on one type are counted as one acceptor, so two doors of the
//!   same transport inside one daemon are not told apart.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Which transport an acceptor reads its request off.
///
/// `Ipc` is a socket bound or handed over on this machine: `ChannelAcceptor`,
/// `serve_inherited`, `read_frame`. `Peer` is the peer transport: a `PeerDoor`,
/// or a decode inside a `PeerHandler`.
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

    let survey = survey(&files);
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
    /// Each decode inside a `PeerHandler` whose type this check cannot read:
    /// `path:line`, and the type argument as written (empty when there is none).
    unreadable: Vec<(String, String)>,
}

fn survey(files: &[PathBuf]) -> Survey {
    let mut survey = Survey::default();
    for path in files {
        // The transports' own source defines these entry points and exercises
        // them on throwaway types in its tests. Those are not channels, and
        // counting them would have this check reporting on itself. `PeerDoor`
        // decodes its type parameter inside the `PeerHandler` it builds; its
        // callers name the type, and are read as `PeerDoor` sites.
        let p = display(path);
        if p.contains("core/ipc/src/provider/") || p.ends_with("core/peer/src/door.rs") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        survey_file(path, &src, &mut survey);
    }
    survey
}

fn survey_file(path: &Path, src: &str, survey: &mut Survey) {
    let krate = acceptor_of(path);
    let p = display(path);
    let tests = crate::docs_present_check::test_modules(src);
    let lines: Vec<&str> = src.lines().collect();
    // Inside a `PeerHandler`: the brace depth of its body, and whether the
    // body has opened yet (a signature can run over several lines).
    let mut handler: Option<(i64, bool)> = None;
    for (n, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t.starts_with("//") || tests.iter().any(|&(a, b)| (a..=b).contains(&(n + 1))) {
            continue;
        }
        let at = format!("{p}:{}", n + 1);
        if handler.is_none() && opens_peer_handler(t) {
            handler = Some((0, false));
        }
        let ipc = parse_listen(t)
            .or_else(|| parse_inherited(t))
            .or_else(|| parse_split(t))
            .map(|(req, _)| (req, Ipc));
        let peer = parse_peer_door(t).map(|(req, _)| (req, Peer));
        let mut decoded: Vec<(String, Transport)> = ipc.or(peer).into_iter().collect();
        if handler.is_some() && decoded.is_empty() {
            for decode in peer_handler_decodes(&lines[n..]) {
                match decode {
                    Decode::Named(req) => decoded.push((req, Peer)),
                    Decode::Unreadable(arg) => survey.unreadable.push((at.clone(), arg)),
                }
            }
        }
        for (req, transport) in decoded {
            survey.found.entry(type_name(&req)).or_default().push(Site {
                krate: krate.clone(),
                transport,
                at: at.clone(),
            });
        }
        if let Some((depth, opened)) = handler.as_mut() {
            *depth += t.matches('{').count() as i64 - t.matches('}').count() as i64;
            *opened |= *depth > 0;
            let closed = if *opened {
                *depth <= 0
            } else {
                t.ends_with(';')
            };
            if closed {
                handler = None;
            }
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

    // 4. A decode inside a `PeerHandler` that does not name its type.
    for (at, arg) in &survey.unreadable {
        let what = if arg.is_empty() {
            "without naming the type".to_string()
        } else {
            format!("as `{arg}`, which is not one named type")
        };
        problems.push(format!(
            "{at} decodes a peer's bytes inside a `PeerHandler` {what}. This check cannot \
             say which channel that is; decode one request type, \
             `serde_json::from_slice::<Req>`, or build the door with `PeerDoor`."
        ));
    }

    problems
}

/// The last path segment: `kotton_wire::ipc::VaultPeerRequest` →
/// `VaultPeerRequest`. The table keys types by name, however a site spells
/// the path to them.
fn type_name(req: &str) -> String {
    req.rsplit("::").next().unwrap_or(req).trim().to_string()
}

/// A line that begins a `PeerHandler`: a function returning one
/// (`-> PeerHandler`, `-> kotton_peer::PeerHandler`), or a binding typed as one
/// (`let h: PeerHandler = ..`).
fn opens_peer_handler(line: &str) -> bool {
    let Some(i) = line.find("PeerHandler") else {
        return false;
    };
    let after = &line[i + "PeerHandler".len()..];
    if after.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
        return false;
    }
    // Strip a path in front of the name: `kotton_peer::`, `crate::`.
    let mut before = line[..i].trim_end();
    while let Some(b) = before.strip_suffix("::") {
        before = b.trim_end_matches(|c: char| c.is_alphanumeric() || c == '_');
    }
    let before = before.trim_end();
    before.ends_with("->") || (before.ends_with(':') && after.trim_start().starts_with('='))
}

/// A `serde_json` decode inside a `PeerHandler`.
#[derive(Debug, PartialEq, Eq)]
enum Decode {
    /// `serde_json::from_slice::<Req>`: an acceptor of `Req`.
    Named(String),
    /// A decode whose type argument is not one named type, as written; empty
    /// when there is no turbofish at all.
    Unreadable(String),
}

/// The decoders a `PeerHandler` is read for.
const DECODERS: &[&str] = &["from_slice", "from_str", "from_reader", "from_value"];

/// The decodes that begin on `lines[0]`, read inside a `PeerHandler`.
///
/// The peer acceptors that are closures rather than `PeerDoor`s decode their
/// request type this way. Outside a `PeerHandler` the same call is a client
/// reading an answer, or a file read back, and is no acceptor.
///
/// The turbofish is gathered from the following lines when it is wrapped, as
/// rustfmt wraps a long one. Its argument must be one type path
/// (`kotton_wire::ipc::VaultPeerRequest`); anything else — none, `_`, a tuple,
/// a generic, a turbofish that never closes — is [`Decode::Unreadable`].
fn peer_handler_decodes(lines: &[&str]) -> Vec<Decode> {
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
        // The call's text from here, over as many lines as the turbofish takes.
        let mut text = after.to_string();
        for more in lines.iter().skip(1).take(8) {
            text.push_str(more.trim());
        }
        let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        // No turbofish: inferred from a binding, or the function passed by
        // name (`.and_then(serde_json::from_slice)`). Either way, unnamed here.
        let Some(rest) = text.strip_prefix("::<") else {
            out.push(Decode::Unreadable(String::new()));
            continue;
        };
        let mut depth = 1;
        let close = rest.char_indices().find_map(|(i, c)| {
            match c {
                '<' => depth += 1,
                '>' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(i)
        });
        let Some(close) = close else {
            out.push(Decode::Unreadable(format!(
                "{}…",
                &rest[..rest.len().min(40)]
            )));
            continue;
        };
        // rustfmt leaves a trailing comma on a turbofish it wraps.
        let arg = rest[..close].strip_suffix(',').unwrap_or(&rest[..close]);
        let one_path = !arg.is_empty()
            && arg != "_"
            && arg.split("::").all(|seg| {
                !seg.is_empty()
                    && seg.chars().all(|c| c.is_alphanumeric() || c == '_')
                    && !seg.starts_with(|c: char| c.is_ascii_digit())
            });
        out.push(if one_path {
            Decode::Named(arg.to_string())
        } else {
            Decode::Unreadable(arg.to_string())
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
/// `PeerDoor::<Req, Resp>::serving(..)` — a door on a peer circuit rather than
/// a socket (`DEC-0055`'s contact mailbox is the first). An acceptor is a thing
/// that deserializes a wire type; until this existed, every one of them was a
/// listener, and reading only listener call sites would have made this check
/// blind to the next kind.
fn parse_peer_door(line: &str) -> Option<(String, String)> {
    let i = line.find("PeerDoor::<")?;
    let rest = &line[i + "PeerDoor::<".len()..];
    let close = rest.find('>')?;
    let (a, b) = rest[..close].split_once(',')?;
    Some((a.trim().to_string(), b.trim().to_string()))
}

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
/// The fixtures spell the forms the check reads in pieces (`concat!`), because
/// this file is itself under a root the check walks: written whole, a fixture
/// would be read as an acceptor of the tree.
#[cfg(test)]
mod tests {
    use super::*;

    const HANDLER: &str = concat!("Peer", "Handler");
    const DECODE: &str = concat!("serde_json::from_", "slice");
    const LISTEN: &str = concat!("Channel", "Acceptor");

    /// A daemon's local door accepting `req`, as kuserd's does.
    fn door(req: &str) -> String {
        format!("fn serve() {{\n    let a = {LISTEN}::<{req}, UserResponse>::listen(&path)?;\n}}\n")
    }

    /// A peer acceptor in the closure form, as kvaultd's and kuserd's are.
    fn peer_handler(ret: &str, req: &str) -> String {
        format!(
            "impl Daemon {{\n    fn peer_handler(&self) -> {ret} {{\n        \
             Arc::new(move |peer_did: String, req_bytes: Vec<u8>| {{\n            \
             pinned(async move {{\n                \
             let request = match {DECODE}::<{req}>(&req_bytes) {{\n                    \
             Ok(r) => r,\n                    Err(e) => return error(format!(\"invalid: {{e}}\")),\n                \
             }};\n                serve(request).await\n            }})\n        }})\n    }}\n}}\n"
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
        let survey = survey(&paths);
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

    /// The tree as it stands today, in miniature: every row of the table has
    /// its acceptor, so each case below changes one thing.
    fn as_it_stands() -> Vec<(&'static str, String)> {
        vec![
            (
                "core/kuserd/src/agent/mod.rs",
                door("UserRequest") + &peer_handler(HANDLER, "PeerRequest"),
            ),
            (
                "core/kvaultd/src/lib.rs",
                door("VaultRequest")
                    + &peer_handler(
                        &format!("kotton_peer::{HANDLER}"),
                        "kotton_wire::ipc::VaultPeerRequest",
                    ),
            ),
            (
                "core/peer/src/contact_door.rs",
                format!(
                    "    {}::<ContactRequest, ContactResponse>::serving(\n",
                    concat!("Peer", "Door")
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
    fn a_decode_inside_a_peer_handler_is_an_acceptor_on_the_peer_transport() {
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
    }

    #[test]
    fn a_decode_outside_a_peer_handler_is_no_acceptor() {
        let client = format!(
            "fn ask() -> Result<UserResponse> {{\n    let r = {DECODE}::<UserResponse>(&bytes)?;\n    Ok(r)\n}}\n\
             fn after() {{\n    let s = {DECODE}::<Settings>(&b)?;\n}}\n"
        );
        let (_dir, survey) = tree(&[("core/device/src/client.rs", client)]);
        assert!(survey.found.is_empty(), "{:?}", survey.found);
    }

    #[test]
    fn a_handler_binding_and_a_multi_line_signature_both_open_a_peer_handler() {
        let src = format!(
            "fn a(\n    x: u8,\n) -> kotton_peer::{HANDLER}\nwhere\n    F: Send,\n{{\n    \
             Arc::new(|_, b| {{ let r = {DECODE}::<AlphaRequest>(&b); }})\n}}\n\
             fn b() {{\n    let h: {HANDLER} = Arc::new(|_, b| {{ {DECODE}::<BetaRequest>(&b) }});\n    \
             let after = {DECODE}::<Gamma>(&x);\n}}\n"
        );
        let (_dir, survey) = tree(&[("core/kx/src/lib.rs", src)]);
        assert_eq!(
            acceptors(&survey, "AlphaRequest"),
            vec![("kx".to_string(), Transport::Peer)]
        );
        assert_eq!(
            acceptors(&survey, "BetaRequest"),
            vec![("kx".to_string(), Transport::Peer)]
        );
        assert!(
            !survey.found.contains_key("Gamma"),
            "the binding's handler ended at its `;`"
        );
    }

    /// The case that went unflagged: a second crate's peer acceptor decoding
    /// the local door's type.
    #[test]
    fn a_second_acceptor_of_user_request_fails_naming_both_sites() {
        let files = with(
            as_it_stands(),
            "core/kvaultd/src/lib.rs",
            door("VaultRequest")
                + &peer_handler(
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
            door("UserRequest") + &peer_handler(HANDLER, "UserRequest"),
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
            door("VaultRequest") + &peer_handler(HANDLER, "UserRequest"),
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

    #[test]
    fn a_peer_handler_decode_that_names_no_type_is_refused() {
        let src = format!(
            "fn h() -> {HANDLER} {{\n    Arc::new(|_, b| {{\n        let r: UserRequest = {DECODE}(&b)?;\n    }})\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src);
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("core/kx/src/lib.rs:3 decodes a peer's bytes")),
            "{problems:#?}"
        );
    }

    /// rustfmt wraps a long turbofish over three lines; the decode is the
    /// same acceptor, and a third crate's is still a third acceptor.
    #[test]
    fn a_turbofish_wrapped_over_lines_is_an_acceptor() {
        let src = format!(
            "fn h() -> kotton_peer::{HANDLER} {{\n    Arc::new(|_, b| {{\n        \
             let r = match {DECODE}::<\n            kotton_wire::ipc::UserRequest,\n        \
             >(&b) {{\n            Ok(r) => r,\n        }};\n    }})\n}}\n"
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
            ) && p.contains("core/kdeviced/src/peer.rs:3")),
            "{problems:#?}"
        );
    }

    #[test]
    fn a_tuple_turbofish_is_refused_as_unreadable() {
        let src = format!(
            "fn h() -> {HANDLER} {{\n    Arc::new(|_, b| {{\n        \
             let (r, n) = {DECODE}::<(kotton_wire::ipc::UserRequest, u8)>(&b)?;\n    }})\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src);
        let (_dir, survey) = tree(&files);
        assert!(
            !survey.found.contains_key("UserRequest)")
                && acceptors(&survey, "UserRequest").len() == 1
        );
        let problems = judge(&survey, CHANNELS);
        assert!(
            problems.iter().any(
                |p| p.contains("core/kx/src/lib.rs:3 decodes a peer's bytes")
                    && p.contains(
                        "`(kotton_wire::ipc::UserRequest,u8)`, which is not one named type"
                    )
            ),
            "{problems:#?}"
        );
    }

    #[test]
    fn a_decoder_passed_by_name_or_with_an_inferred_type_is_refused() {
        let src = format!(
            "fn h() -> {HANDLER} {{\n    Arc::new(|_, b| {{\n        \
             let r = Some(b).map(|b| {DECODE}::<_>(&b));\n        \
             let s = Ok(b).and_then({DECODE});\n    }})\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src);
        let (_dir, survey) = tree(&files);
        let problems = judge(&survey, CHANNELS);
        for line in [3, 4] {
            assert!(
                problems
                    .iter()
                    .any(|p| p
                        .contains(&format!("core/kx/src/lib.rs:{line} decodes a peer's bytes"))),
                "line {line}: {problems:#?}"
            );
        }
    }

    /// A stated limit, held so that it stays stated: a decode in a helper the
    /// handler calls is outside the handler's text, and is neither counted nor
    /// refused. The module doc lists it under "What a text check cannot see".
    #[test]
    fn a_decode_in_a_helper_called_from_a_handler_is_not_seen() {
        let src = format!(
            "fn decode(b: &[u8]) -> Result<UserRequest> {{\n    Ok({DECODE}::<UserRequest>(b)?)\n}}\n\
             fn h() -> {HANDLER} {{\n    Arc::new(|_, b| {{\n        let r = decode(&b);\n    }})\n}}\n"
        );
        let files = with(as_it_stands(), "core/kx/src/lib.rs", src);
        let (_dir, survey) = tree(&files);
        assert_eq!(
            acceptors(&survey, "UserRequest"),
            vec![("kuserd".to_string(), Transport::Ipc)]
        );
        assert_eq!(judge(&survey, CHANNELS), Vec::<String>::new());
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
