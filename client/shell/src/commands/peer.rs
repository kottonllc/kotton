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
                Ok(CommandOutput::shapes(vec![list_table(&nodes)]))
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
                let label = args.get(1).cloned().unwrap_or_default();
                let did = args.get(2).cloned().unwrap_or_default();
                let pubkey_hex = args.get(3).cloned().unwrap_or_default();
                let addr_str = args.get(4).cloned().unwrap_or_default();
                if label.is_empty() || did.is_empty() || pubkey_hex.is_empty() || addr_str.is_empty() {
                    return Ok(CommandOutput::fail(
                        "usage: peer add <remote> <did> <pubkey-hex> <addr>",
                        None,
                    ));
                }
                let addr: SocketAddr = addr_str
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid addr '{}': {e}", addr_str))?;
                let node = client
                    .peer_add(&user_id, &label, &did, &pubkey_hex, addr)
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

fn flag_u64(args: &[String], flag: &str) -> Option<u64> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1)?.parse().ok()
}

/// `peer list`'s table, as a pure function of the paired nodes so its columns are
/// testable without a daemon.
fn list_table(nodes: &[PairedNode]) -> Out {
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
        // `remote` is the word `sync [--push | --pull] <remote>` takes this value
        // by. It was headed `label` until 2026-09-28, and a person with a vault
        // paired had to ask which column `sync` wanted.
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
/// that command.
fn show_record(n: &PairedNode) -> Out {
    let pubkey: String = n.public_key.iter().map(|b| format!("{b:02x}")).collect();
    let add = format!(
        "peer add {} {} {} {}",
        n.id,
        n.device_did,
        pubkey,
        n.addresses
            .first()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "<no address recorded>".to_string()),
    );
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
  peer list                                        paired peers: the remote `sync <remote>` takes, where
                                                   each is reachable, and its relay
  peer show <remote>                               one peer whole: its line (the one `id recover` asks
                                                   for), its full DID, key, and `peer add` line
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

    /// The column holding what `sync <remote>` takes is headed `remote`, the word
    /// `sync`'s usage names it by. It was headed `label` until 2026-09-28, and the
    /// owner, with a vault paired, had to ask which column `sync` wanted.
    #[test]
    fn the_column_sync_takes_is_headed_by_the_word_sync_uses() {
        let Out::Table { columns, rows } = list_table(&[node("ubuntu-s-1vcpu-1gb-nyc1", DID)])
        else {
            panic!("peer list is a table");
        };
        assert_eq!(columns[0], "remote");
        assert_eq!(rows[0][0], "ubuntu-s-1vcpu-1gb-nyc1");
        assert!(
            super::super::sync::HELP.contains("<remote>"),
            "`sync`'s usage names the argument by the same word"
        );
    }

    /// `peer show` prints the DID whole — every character, no `…` — through a
    /// shape the renderer does not fit to the terminal, and with it the key and
    /// address `peer add` takes, so a person can write a peer down before a wipe.
    #[test]
    fn peer_show_prints_the_whole_did_and_the_peer_add_line() {
        let n = node("ubuntu-s-1vcpu-1gb-nyc1", DID);
        let shape = show_record(&n);
        let Out::Record(pairs) = &shape else {
            panic!("peer show is a record");
        };
        let get = |k: &str| pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(get("remote").as_deref(), Some("ubuntu-s-1vcpu-1gb-nyc1"));
        assert_eq!(get("did").as_deref(), Some(DID));
        let key = "ab".repeat(32);
        assert_eq!(get("pubkey").as_deref(), Some(key.as_str()));
        assert_eq!(
            get("to add it"),
            Some(format!("peer add ubuntu-s-1vcpu-1gb-nyc1 {DID} {key} 203.0.113.84:7710"))
        );
        // Rendered, the DID survives whole: a Record is not truncated the way a
        // table is. The same DID in `peer list` is the widest cell, and the one cut.
        let rendered = crate::out::render_shape(&shape);
        assert!(rendered.contains(DID), "rendered: {rendered}");
        assert!(!rendered.contains('…'), "rendered: {rendered}");
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
