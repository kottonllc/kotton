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
//! Each new form was added because moving a channel onto it read as the channel
//! disappearing. That happened to `kuid` on 2026-08-24 (bound → inherited) and
//! again on 2026-08-27 (inherited → split, when the compositor gained its own
//! direction). Both times this rule caught it, which is the argument for the
//! staleness rule below being an error rather than a warning.
//!
//! This check reads every such call site rather than
//! a list someone maintains, so a new server added tomorrow is seen whether or
//! not anyone updates the table.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The channels, keyed by request type. `RFC-0082`'s table, in code.
///
/// The acceptor is the crate expected to serve the channel. A row naming no
/// live acceptor, or an acceptor whose type is absent here, is a table that has
/// stopped describing the system.
///
/// "Owns the socket" was the old wording and it is no longer true of every row:
/// `kuid` owns no socket. `kuserd` makes a `socketpair` before forking and hands
/// kuid the far end, so that channel has no path and nothing to bind.
const CHANNELS: &[(&str, &str, &str)] = &[
    // request type, response type, acceptor crate
    ("UserRequest", "UserResponse", "kuserd"),
    // The vault's door (RFC-0084): the thirteen verbs a keeper's landlord may
    // speak, as their own type so a plaintext verb is unconstructible there
    // rather than refused by an arm. Two of them — enrolling and revoking the
    // operator credential — are the door's alone; four more the operator's
    // key also says on the peer transport, where standing decides.
    ("VaultRequest", "UserResponse", "kvaultd"),
    // Another person's door (RFC-0022, DEC-0055): one verb, reached only at a
    // per-pair mailbox whose verifier admits one key. A contact cannot name a
    // storage verb, rather than being refused for one.
    ("ContactRequest", "ContactResponse", "peer"),
    ("DeviceRequest", "DeviceResponse", "kdeviced"),
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
    ("FromCompositor", "()", "kuserd"),
    // The inference channel, the other way: `kinferd`, which is not in this tree, is the
    // acceptor of `InferRequest` in the reference and has no row here. A row for the same
    // reason `FromCompositor` has one: `kuserd` reads this type off the pipe itself,
    // so it is an acceptor of it. No wrapper is needed here where the
    // compositor needed one — `kinferd` raises nothing of its own, so every
    // frame on the up direction is an answer.
    ("InferResponse", "()", "kuserd"),
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

    // request type -> the acceptors that deserialize it
    let mut found: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for path in &files {
        // The transports' own source defines these entry points and exercises
        // them on throwaway types in its tests. Those are not channels, and
        // counting them would have this check reporting on itself.
        let p = path.to_string_lossy();
        if p.contains("core/ipc/src/provider/") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in src.lines() {
            let t = line.trim();
            if t.starts_with("//") {
                continue;
            }
            if let Some((req, resp)) = parse_listen(t)
                .or_else(|| parse_inherited(t))
                .or_else(|| parse_split(t))
                .or_else(|| parse_peer_door(t))
            {
                let who = acceptor_of(path);
                found.entry(req).or_default().push((who, display(path)));
                let _ = resp;
            }
        }
    }

    if found.is_empty() {
        eprintln!(
            "channel-check: found no acceptor call site in {} file(s). \
             Either every acceptor was removed, or the pattern this check greps for has \
             changed and it is now silently vacuous.",
            files.len()
        );
        std::process::exit(1);
    }

    let mut problems: Vec<String> = Vec::new();

    // 1. No request type may be accepted by two servers.
    for (req, sites) in &found {
        let mut who: Vec<&str> = sites.iter().map(|(w, _)| w.as_str()).collect();
        who.sort_unstable();
        who.dedup();
        if who.len() > 1 {
            let where_ = sites
                .iter()
                .map(|(_, p)| p.as_str())
                .collect::<Vec<_>>()
                .join("\n      ");
            problems.push(format!(
                "`{req}` is the wire type for {} acceptors ({}):\n      {where_}\n    \
                 Two channels wearing one name. Every difference between them — who may \
                 connect, what authenticates them, which messages mean anything — is \
                 enforced at runtime or not at all.",
                who.len(),
                who.join(", ")
            ));
        }
    }

    // 2. Every accepted type appears in the table.
    for (req, sites) in &found {
        if !CHANNELS.iter().any(|(r, _, _)| r == req) {
            problems.push(format!(
                "`{req}` is accepted at {} but has no row in CHANNELS. A channel nobody \
                 recorded is one nobody reviewed.",
                sites[0].1
            ));
        }
    }

    // 3. Every table row names a type some server actually accepts — the
    //    staleness rule. A row for a channel that no longer exists reads as a
    //    decision when it is a leftover.
    for (req, _, who) in CHANNELS {
        if !found.contains_key(*req) {
            problems.push(format!(
                "CHANNELS names `{req}` (acceptor `{who}`) but no server accepts it. Either \
                 the channel is gone and the row should be, or the acceptor moved and this \
                 check is no longer watching it."
            ));
        }
    }

    if problems.is_empty() {
        println!(
            "channel-check: OK — {} channel(s), each with exactly one acceptor ({} source \
             files scanned).",
            found.len(),
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
