// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;

use super::{Command, CommandOutput};
use crate::out::Out;
use crate::state::ShellState;
use kotton_wire::peer::PairedNode;

pub struct PeerCommand;

#[async_trait]
impl Command for PeerCommand {
    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        let user_id = state.user_id.clone();
        let mut client = state.client.lock().await;

        match args.first().map(String::as_str) {
            Some("identity") => {
                let (did, pubkey_hex) = client
                    .get_node_identity()
                    .await
                    .map_err(|e| anyhow::anyhow!("peer identity: {e}"))?;
                Ok(CommandOutput::shapes(vec![Out::Record(vec![
                    ("did".into(), did),
                    ("pubkey".into(), pubkey_hex),
                ])]))
            }

            Some("list") => {
                let nodes = client
                    .list_nodes(&user_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("peer list: {e}"))?;
                // `addresses` and `relay_url` are the two answers this command is
                // asked for and did not give until 2026-09-11: it printed label,
                // did and a raw unix timestamp, so the one question a person has
                // about a peer — *can I reach it, and how* — had no answer here.
                //
                // Measured the hard way. A vault on a rented host could not be
                // reached; the log said NAT traversal and the relay both failed,
                // and the obvious next step was to look at the address recorded
                // for it. There was nowhere to look. Worse, `peer add` — the
                // command a fresh device ran before `id recover` (until #80, when
                // `id recover` came to take the vault's line itself), and the whole
                // reason to write these down before wiping anything — *takes* an
                // address, and the only command that could have supplied it
                // dropped the field.
                let mut shapes = vec![list_table(&nodes)];
                shapes.extend(super::device::notes_said(&nodes.notes));
                Ok(CommandOutput::shapes(shapes))
            }

            Some("show") => {
                let Some(remote) = args.get(1) else {
                    return Ok(CommandOutput::fail(
                        "usage: peer show <remote>",
                        Some("peer list".into()),
                    ));
                };
                let nodes = client
                    .list_nodes(&user_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("peer show: {e}"))?;
                let shown = shown_by(&nodes, remote);
                if shown.is_empty() {
                    return Ok(CommandOutput::fail(
                        format!("no paired peer '{remote}'"),
                        Some("peer list".into()),
                    ));
                }
                Ok(CommandOutput::shapes(shown.into_iter().map(show_record).collect()))
            }

            Some("add") => {
                let Some([label, did, pubkey_hex, addr_str]) = add_words(&args[1..]) else {
                    return Ok(CommandOutput::fail(
                        "usage: peer add <remote> <did> <pubkey-hex> <addr>",
                        None,
                    ));
                };
                let addr: SocketAddr = addr_str
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid addr '{}': {e}", addr_str))?;
                let node = client
                    .peer_add(&user_id, label, did, pubkey_hex, addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("peer add: {e}"))?;
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: format!("added peer '{}'", node.id),
                    subject: node.device_did.to_string(),
                }]))
            }

            Some("revoke") => {
                let peer_id = match args.get(1) {
                    Some(id) => id.clone(),
                    None => {
                        return Ok(CommandOutput::fail("usage: peer revoke <remote>", None))
                    }
                };
                client
                    .revoke_node(&user_id, &peer_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("peer revoke: {e}"))?;
                Ok(CommandOutput::shapes(vec![Out::Confirm {
                    action: format!("revoked peer '{peer_id}'"),
                    subject: String::new(),
                }]))
            }

            Some("mount") => match args.get(1).map(String::as_str) {
                Some("list") => {
                    let mounts = client
                        .list_mounts(&user_id)
                        .await
                        .map_err(|e| anyhow::anyhow!("peer mount list: {e}"))?;
                    let rows: Vec<Vec<String>> = mounts
                        .iter()
                        .map(|m| {
                            vec![
                                m.node_id.clone(),
                                m.remote_path.clone(),
                                m.local_path.clone(),
                            ]
                        })
                        .collect();
                    Ok(CommandOutput::shapes(vec![Out::Table {
                        columns: vec!["peer".into(), "remote path".into(), "local path".into()],
                        rows,
                    }]))
                }

                Some("add") => {
                    let node = match args.get(2) {
                        Some(n) => n.clone(),
                        None => {
                            return Ok(CommandOutput::error(
                                1,
                                "usage: peer mount add <node> <remote-path> <local-path>"
                                    .to_string(),
                            ))
                        }
                    };
                    let remote_path = match args.get(3) {
                        Some(p) => p.clone(),
                        None => {
                            return Ok(CommandOutput::error(
                                1,
                                "usage: peer mount add <node> <remote-path> <local-path>"
                                    .to_string(),
                            ))
                        }
                    };
                    let local_path = match args.get(4) {
                        Some(p) => p.clone(),
                        None => format!("/{}/{}", node, remote_path.trim_start_matches('/')),
                    };
                    let budget = flag_u64(args, "--budget");
                    let pins: Vec<String> = args
                        .windows(2)
                        .filter(|w| w[0] == "--pin")
                        .map(|w| w[1].clone())
                        .collect();
                    let cfg = client
                        .mount(&user_id, &node, &remote_path, &local_path, budget, pins)
                        .await
                        .map_err(|e| anyhow::anyhow!("peer mount add: {e}"))?;
                    Ok(CommandOutput::success_with_output(format!(
                        "✓ Mounted '{}/{}' at '{}'",
                        cfg.node_id, cfg.remote_path, cfg.local_path
                    )))
                }

                Some("evict") => {
                    let node = match args.get(2) {
                        Some(n) => n.clone(),
                        None => {
                            return Ok(CommandOutput::error(
                                1,
                                "usage: peer mount evict <node> <local-path>".to_string(),
                            ))
                        }
                    };
                    let local_path = match args.get(3) {
                        Some(p) => p.clone(),
                        None => {
                            return Ok(CommandOutput::error(
                                1,
                                "usage: peer mount evict <node> <local-path>".to_string(),
                            ))
                        }
                    };
                    let freed = client
                        .evict_mount(&user_id, &node, &local_path)
                        .await
                        .map_err(|e| anyhow::anyhow!("peer mount evict: {e}"))?;
                    Ok(CommandOutput::success_with_output(format!(
                        "✓ Mount '{}' evicted ({} bytes freed)",
                        local_path, freed
                    )))
                }

                _ => Ok(CommandOutput::error(
                    1,
                    "usage: peer mount <list|add|evict> ...".to_string(),
                )),
            },

            Some("help") | None => {
                Ok(CommandOutput::success_with_output(HELP.to_string()))
            }

            Some(other) => Ok(CommandOutput::error(
                1,
                format!("peer: unknown subcommand '{}'. Try 'peer help'.", other),
            )),
        }
    }

    fn flags(&self) -> Vec<&'static str> {
        vec!["identity", "list", "show", "add", "revoke", "mount", "help"]
    }

    fn help_text(&self) -> &'static str {
        HELP
    }
}

/// The four words `peer add` reads after its verb, `<remote> <did> <pubkey-hex>
/// <addr>`, or `None` where one is missing or empty. The one reading of them, so
/// the line `peer show` prints is held to what this verb hands the daemon.
fn add_words(args: &[String]) -> Option<[&str; 4]> {
    let word = |i: usize| args.get(i).map(String::as_str).filter(|w| !w.is_empty());
    Some([word(0)?, word(1)?, word(2)?, word(3)?])
}

fn flag_u64(args: &[String], flag: &str) -> Option<u64> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1)?.parse().ok()
}

/// `peer list`'s table, as a pure function of the paired nodes so its columns are
/// testable without a daemon. Each label is as stored: the renderer prints it with
/// every character shown, and `--json` carries it as stored (kottonllc/kotton#597, 39A).
pub(crate) fn list_table(nodes: &[PairedNode]) -> Out {
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|n| {
            vec![
                n.id.clone(),
                n.device_did.to_string(),
                format_addresses(n),
                n.relay_url.clone().unwrap_or_else(|| "—".to_string()),
                format_paired_at(n.paired_at),
            ]
        })
        .collect();
    Out::Table {
        // `remote` is the word `peer show <remote>` takes this value by, and the
        // word a join's completion line names the device by. `sync` takes no
        // word after it: a device is not a sync target.
        columns: vec![
            "remote".into(),
            "did".into(),
            "addresses".into(),
            "relay".into(),
            "paired".into(),
        ],
        rows,
    }
}

/// One peer, whole: `peer show <remote>`.
///
/// The first row is the node's line, `kotton-instance:vault:<key>@<address>`, the line
/// `kotton id recover` asks for, printed by the one function the recovery card prints
/// it with ([`super::id::recovery_line`]). So the line of a vault that keeps your copy
/// can be read again on any device that holds the identity, and reading it makes
/// nothing: `id add-recovery` would print it too, but only beside new words, a second
/// authority the committed set keeps for good. A node with no address recorded has no
/// line, and the row says so.
///
/// `peer list` is a table, and the renderer shrinks a table's widest column to fit
/// the terminal — so the DID, the widest thing in it, is the one cell cut with `…`.
/// That is the right rule for a table and the wrong place to read a DID from.
/// Every node `name` names: its DID, or the label it is shown under. A label
/// keys no row, so two of the person's nodes may carry one, and `peer show`
/// shows each of them, never only the first; each record says its DID, which
/// names it to `peer revoke` and `sync`.
fn shown_by<'a>(nodes: &'a [PairedNode], name: &str) -> Vec<&'a PairedNode> {
    nodes.iter().filter(|n| n.id == name || n.device_did.to_string() == name).collect()
}

/// A `Record` is not fitted, so every value here is printed whole, including the
/// public key the table never showed; `peer add` needs all four, and the last row is
/// that command where there is one ([`add_line`]), or says why there is none.
fn show_record(n: &PairedNode) -> Out {
    let pubkey: String = n.public_key.iter().map(|b| format!("{b:02x}")).collect();
    let add = add_line(n).unwrap_or_else(|why| format!("— none: {why}"));
    let line = super::id::recovery_line(n)
        .map(|(line, _)| line)
        .unwrap_or_else(|| "— none: no address is recorded for it".to_string());
    Out::Record(vec![
        ("line".into(), line),
        ("remote".into(), n.id.clone()),
        ("did".into(), n.device_did.to_string()),
        ("pubkey".into(), pubkey),
        ("addresses".into(), format_addresses(n)),
        ("relay".into(), n.relay_url.clone().unwrap_or_else(|| "—".to_string())),
        ("paired".into(), format_paired_at(n.paired_at)),
        ("to add it".into(), add),
    ])
}

/// The `peer add` line that adds `n` as it is recorded, or why there is none.
///
/// **The line's DID is the key's derivation, made from the row's bytes, and not the
/// DID stored beside them.** `peer add` refuses a DID that is not the `did:key` of the
/// key it is given, and where the person has a row for that key it rewrites that row,
/// under its DID as stored, with the label and address the line brings, and adds
/// none (kottonllc/kotton#597, 28A and 30A). So the one line is taken for a row stored
/// under the derivation's string and for a row an earlier build stored under another
/// spelling of the key's `did:key`, and on a device with no row for the key it adds
/// one under the derivation. The row's `did` is printed as stored in the record above.
/// On another device the line adds the row; on this one, typing it rewrites the key's
/// row with the line's one address, so the row's other addresses go, and its posture
/// and relay are kept: 30A's rewrite.
///
/// There is none:
///
/// - where the row's bytes are no Ed25519 key: they have no `did:key`, and `peer add`
///   takes no such key (kottonllc/kotton#597, 1A and 2A);
/// - where the row's label is not [`kotton_wire::note::one_plain_word`]: a command is
///   printed only with a name that is one plain word (kottonllc/kotton#597, 23A, with
///   25A's concession that the set is ASCII), so that a printed command is held to
///   reach its row typed as printed (20A), and `peer add` rewrites the row's label
///   with the one it is given;
/// - where no address is recorded for the row: `peer add` takes one.
fn add_line(n: &PairedNode) -> Result<String, &'static str> {
    let Ok(did) = kotton_crypto::DidKeyMethod::from_public_key_bytes(&n.public_key) else {
        return Err("the key recorded for it is no Ed25519 key, and `peer add` takes none");
    };
    if !kotton_wire::note::one_plain_word(&n.id) {
        return Err("its remote is not one plain word, and a line is printed only with one");
    }
    let Some(address) = n.addresses.first() else {
        return Err("no address is recorded for it, and `peer add` takes one");
    };
    let pubkey: String = n.public_key.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("peer add {} {did} {pubkey} {address}", n.id))
}

fn format_addresses(n: &PairedNode) -> String {
    if n.addresses.is_empty() {
        // Not cosmetic. An empty list is why a dial fails, and a blank cell reads
        // as "not shown" rather than "there is nothing here".
        "— none recorded".to_string()
    } else {
        n.addresses
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A pairing time a person can read.
///
/// `paired_at` is unix seconds and was printed raw — `1789155858`, which tells a
/// reader nothing they can act on. Rendered as an age, because the question this
/// column actually answers is "is this the pairing I just did, or an old one".
fn format_paired_at(paired_at: i64) -> String {
    let now = kotton_common::time::now_secs();
    let age = now.saturating_sub(paired_at);
    if age < 0 {
        // A clock that disagrees is worth showing rather than rendering as
        // nonsense; `in the future` is a fact about this machine.
        return format!("{paired_at} (in the future — check this machine's clock)");
    }
    match age {
        a if a < 90 => "just now".to_string(),
        a if a < 3_600 => format!("{} min ago", a / 60),
        a if a < 86_400 => format!("{} hr ago", a / 3_600),
        a => format!("{} days ago", a / 86_400),
    }
}

const HELP: &str = "\
peer — manage paired peer nodes

USAGE:
  peer identity                                    print this node's DID and signing key
  peer list                                        paired peers: the remote `peer show <remote>` takes,
                                                   where each is reachable, and its relay
  peer show <remote>                               one peer whole: its line (the one `id recover` asks
                                                   for), its full DID and key, and the `peer add` line
                                                   that adds it, or why there is none
  peer add <remote> <did> <pubkey-hex> <addr>      add a peer manually (no ceremony)
  peer revoke <remote>                             remove a peer from the allowlist
  peer mount list                                  list configured peer mounts
  peer mount add <node> <remote-path> <local-path> [--budget N] [--pin p]
                                                   mount a path from a peer
  peer mount evict <node> <local-path>             evict a mount's local cache";

#[cfg(test)]
mod peer_list_tests {
    use super::*;

    /// A whole `did:key`, longer than any table cell a narrow terminal leaves it.
    const DID: &str = "did:key:z6MktGLn5v9bCrdxWgRojq7m1D2Y8ZKc3sP4hT9uXeVbNwAa";


    /// Each band reads as itself, and the boundaries are the ones a person
    /// notices: a pairing done a moment ago must not read as "0 min ago".
    #[test]
    fn a_pairing_time_reads_as_an_age() {
        let now = kotton_common::time::now_secs();
        assert_eq!(format_paired_at(now), "just now");
        assert_eq!(format_paired_at(now - 89), "just now");
        assert_eq!(format_paired_at(now - 600), "10 min ago");
        assert_eq!(format_paired_at(now - 7_200), "2 hr ago");
        assert_eq!(format_paired_at(now - 172_800), "2 days ago");
    }

    fn node(id: &str, did: &str) -> PairedNode {
        PairedNode {
            id: id.into(),
            device_did: kotton_wire::did::Did::parse(did).unwrap(),
            public_key: [0xab; 32],
            paired_at: kotton_common::time::now_secs(),
            addresses: vec!["203.0.113.84:7710".parse().unwrap()],
            relay_url: Some("http://203.0.113.84:7700".into()),
            posture: None,
        }
    }

    /// The column holding what `peer show <remote>` takes is headed `remote`, the
    /// word its usage names it by. It was headed `label` until 2026-09-28, and the
    /// owner, with a vault paired, had to ask which column a verb wanted. `sync`
    /// took it too until the command-tree decision's tree, where `sync` takes no remote.
    #[test]
    fn the_column_peer_show_takes_is_headed_by_the_word_its_usage_uses() {
        let Out::Table { columns, rows } = list_table(&[node("ubuntu-s-1vcpu-1gb-nyc1", DID)])
        else {
            panic!("peer list is a table");
        };
        assert_eq!(columns[0], "remote");
        assert_eq!(rows[0][0], "ubuntu-s-1vcpu-1gb-nyc1");
        assert!(HELP.contains("peer show <remote>"), "`peer show`'s usage names the argument by the same word");
    }

    /// `peer show` prints the DID whole — every character, no `…` — through a
    /// shape the renderer does not fit to the terminal, and with it the key and
    /// address `peer add` takes, so a person can write a peer down before a wipe.
    #[test]
    fn peer_show_prints_the_whole_did_and_the_peer_add_line() {
        let (bytes, did) = seeded(7);
        let n = PairedNode { public_key: bytes, ..node("ubuntu-s-1vcpu-1gb-nyc1", &did) };
        let shape = show_record(&n);
        let Out::Record(pairs) = &shape else {
            panic!("peer show is a record");
        };
        let get = |k: &str| pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(get("remote").as_deref(), Some("ubuntu-s-1vcpu-1gb-nyc1"));
        assert_eq!(get("did").as_deref(), Some(did.as_str()));
        let key = hex_of(&bytes);
        assert_eq!(get("pubkey").as_deref(), Some(key.as_str()));
        assert_eq!(
            get("to add it"),
            Some(format!("peer add ubuntu-s-1vcpu-1gb-nyc1 {did} {key} 203.0.113.84:7710"))
        );
        // Rendered, the DID survives whole: a Record is not truncated the way a
        // table is. The same DID in `peer list` is the widest cell, and the one cut.
        let rendered = crate::out::render_shape(&shape);
        assert!(rendered.contains(&did), "rendered: {rendered}");
        assert!(!rendered.contains('…'), "rendered: {rendered}");
    }

    /// The key made from `seed`, as the row's bytes, and its `did:key` as the
    /// derivation makes it.
    fn seeded(seed: u8) -> ([u8; 32], String) {
        use kotton_crypto::ed25519::Ed25519Keypair;
        let (_, public) = Ed25519Keypair::new().from_seed(&[seed; 32]).expect("a 32-byte seed");
        let bytes: [u8; 32] = public.try_into().expect("an Ed25519 key is 32 bytes");
        let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&bytes).expect("a key made from a seed passes");
        (bytes, did.to_string())
    }

    fn hex_of(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `peer show`'s last row for `n`.
    fn to_add_it(n: &PairedNode) -> String {
        let Out::Record(pairs) = show_record(n) else {
            panic!("peer show is a record");
        };
        let (last, value) = pairs.last().expect("a record has rows").clone();
        assert_eq!(last, "to add it", "the `peer add` row is the record's last: {pairs:?}");
        value
    }

    /// The words this shell hands `peer add` for `typed`, read as a typed line is:
    /// the chain's parser, the variables, the words, the redirect, then the verb's
    /// own reading ([`add_words`]). Exactly one command, `peer add`, must result.
    fn read_as_typed(typed: &str) -> [String; 4] {
        let chain = crate::parser::parse_command_chain(typed);
        assert_eq!(chain.len(), 1, "`{typed}` is {} commands: {chain:?}", chain.len());
        let words = crate::utils::parse_command(&crate::utils::expand_vars(&chain[0].command, &Default::default()));
        let (words, redirect) = crate::executor::parse_redirect(words);
        assert!(redirect.is_none(), "`{typed}` redirects");
        assert_eq!(words.get(..2), Some(&["peer".to_owned(), "add".to_owned()][..]), "`{typed}`");
        assert_eq!(words.len(), 6, "`{typed}` hands `peer add` other than its four words: {words:?}");
        add_words(&words[2..]).unwrap_or_else(|| panic!("`{typed}` is `peer add`'s usage")).map(str::to_owned)
    }

    /// **The `peer add` line `peer show` prints is one `peer add` takes, for a row
    /// stored under its key's derivation and for one stored under another spelling**
    /// (kottonllc/kotton#620). For a key made from a seed, each row's line is the same
    /// line, and reads back through this shell's parser as `peer add` with the row's
    /// label, the `did:key` the derivation makes of the row's bytes (the one DID the
    /// daemon takes beside them, kottonllc/kotton#597, 28A), those bytes and the row's
    /// first address, at an IPv4 address and at an IPv6 one. The string stored beside
    /// the bytes is in the record's `did` row and in no command. That the daemon takes
    /// the line and adds no row is held in the suite
    /// (`the_peer_add_line_peer_show_prints_is_one_the_daemon_takes`).
    #[test]
    fn peer_shows_a_line_peer_add_takes_for_a_row_under_any_spelling_of_its_key() {
        let (bytes, derived) = seeded(61);
        let other = kotton_crypto::DidKeyMethod::spelled_otherwise(&bytes).to_string();
        assert_ne!(other, derived, "the other spelling is another string");
        for address in ["203.0.113.84:7710", "[2001:db8::7]:7710"] {
            let row = |did: &str| PairedNode {
                public_key: bytes,
                addresses: vec![address.parse().unwrap(), "198.51.100.9:1".parse().unwrap()],
                ..node("laptop", did)
            };
            let (under_derived, under_other) = (row(&derived), row(&other));
            let line = to_add_it(&under_derived);
            assert_eq!(to_add_it(&under_other), line, "one key, one line, whatever its row is stored under");
            assert!(!line.contains(&other), "the line names the stored string: {line}");
            let [label, did, pubkey, addr] = read_as_typed(&line);
            assert_eq!((label.as_str(), did.as_str(), pubkey.as_str()), ("laptop", derived.as_str(), hex_of(&bytes).as_str()));
            assert_eq!(addr.parse::<std::net::SocketAddr>().unwrap(), under_other.addresses[0]);
            let Out::Record(pairs) = show_record(&under_other) else { panic!("peer show is a record") };
            assert!(pairs.contains(&("did".to_string(), other.clone())), "the DID as stored is shown: {pairs:?}");
        }
    }

    /// **Where there is no line, the record says so and gives no command**
    /// (kottonllc/kotton#620): for a row under each key `kotton_ed25519::refused`
    /// names, which has no `did:key` and which `peer add` refuses; for a label that is
    /// not one plain word, which no line typed as printed hands `peer add`
    /// (kottonllc/kotton#597, 20A); and for a row with no address recorded.
    #[test]
    fn peer_show_says_there_is_no_line_where_there_is_none() {
        let (bytes, derived) = seeded(62);
        let none = |n: &PairedNode, why: &str| {
            let said = to_add_it(n);
            assert!(said.starts_with("— none: ") && said.contains(why), "{:?}: {said}", n.id);
            assert!(!said.contains("peer add "), "a command was printed: {said}");
        };
        for (name, refused) in kotton_crypto::ed25519::refused_keys() {
            let n = PairedNode { public_key: refused, ..node("laptop", &derived) };
            assert!(kotton_wire::note::one_plain_word(&n.id) && !n.addresses.is_empty(), "{name}");
            none(&n, "no Ed25519 key");
        }
        for label in ["my phone", "a;b", "a|b", "a&&b", "it's", "say\"x", "a`b", "--old", "-x", "bell\u{7}", "$HOME", "caf\u{e9}", ""] {
            none(&PairedNode { public_key: bytes, ..node(label, &derived) }, "not one plain word");
        }
        none(&PairedNode { public_key: bytes, addresses: vec![], ..node("laptop", &derived) }, "no address is recorded");
        // The same row with a plain label and an address has its line.
        assert!(to_add_it(&PairedNode { public_key: bytes, ..node("laptop", &derived) }).starts_with("peer add laptop "));
    }

    /// `peer show`'s first row is the node's line, the one `kotton id recover` asks
    /// for: it reads back through the parser `enrol` and `id recover` read lines with
    /// as this node's key and address, and it is the line the recovery card prints for
    /// it, byte for byte. So a device that holds the identity reads the line again
    /// without `id add-recovery`, which would mint new words to print it. A node with
    /// no address recorded has no line, and the row says so rather than printing one.
    #[test]
    fn peer_show_prints_the_line_id_recover_asks_for_first() {
        let n = node("vault", DID);
        let Out::Record(pairs) = show_record(&n) else {
            panic!("peer show is a record");
        };
        let (first, line) = &pairs[0];
        assert_eq!(first, "line", "the line is the first row: {pairs:?}");
        let read = kotton_wire::line::InstanceLine::parse(line).unwrap_or_else(|e| panic!("`{line}`: {e}"));
        assert_eq!(read.kind, kotton_wire::ipc::OperatedService::Vault);
        assert_eq!(read.key, n.public_key);
        assert_eq!(read.hint, "203.0.113.84:7710");
        let (card, _) = super::super::id::recovery_line(&n).expect("the card has a line for it");
        assert_eq!(line, &card, "peer show and the recovery card print one line");

        let nowhere = PairedNode { addresses: vec![], ..node("vault", DID) };
        let Out::Record(pairs) = show_record(&nowhere) else {
            panic!("peer show is a record");
        };
        assert_eq!(pairs[0].0, "line");
        assert!(
            !pairs[0].1.contains("kotton-instance") && pairs[0].1.contains("no address"),
            "a node with no address prints no line, and says why: {:?}",
            pairs[0]
        );
    }

    /// A clock skew says so instead of rendering a negative age as a huge one.
    /// `saturating_sub` on an i64 does not saturate at zero for this, so without
    /// the guard a future timestamp read as "just now" — a wrong answer that
    /// looks right, which is the worst kind.
    #[test]
    fn a_future_timestamp_is_called_out_rather_than_smoothed_over() {
        let ahead = kotton_common::time::now_secs() + 10_000;
        let got = format_paired_at(ahead);
        assert!(got.contains("in the future"), "got: {got}");
        assert!(got.contains("clock"), "the reader is told what to check: {got}");
    }

    /// **`peer show` shows every node a label names** (kotton #99): two rows
    /// under `vault` are both shown, and a DID shows the one it names.
    #[test]
    fn peer_show_shows_every_node_a_label_names() {
        const OTHER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let nodes = [node("vault", DID), node("vault", OTHER), node("laptop", "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")];
        let shown: Vec<String> = shown_by(&nodes, "vault").iter().map(|n| n.device_did.to_string()).collect();
        assert_eq!(shown, [DID, OTHER]);
        let by_did: Vec<&str> = shown_by(&nodes, OTHER).iter().map(|n| n.id.as_str()).collect();
        assert_eq!(by_did, ["vault"]);
        assert!(shown_by(&nodes, "nowhere").is_empty());
    }
}
