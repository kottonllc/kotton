// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests for [`kotton_peer::daemon::db`], which is `peer`'s.
//!
//! They stay here because they run the machine db migrator, and the
//! migrations are **one directory building one `agent.db`** — twenty files with
//! ordering constraints across six domains. Splitting them per domain is a real
//! question and a much larger one than moving a table module, so *a domain's
//! daemon tier owns its own tables* holds for the code and not yet for the
//! migrations.
//!
//! The repo already has this shape: `05_runtime` keeps `pair_channel_tests.rs`
//! and `frost_signing_tests.rs` for code that moved to `peer` and `org`.

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use kotton_crypto::DidKeyMethod;
    use kotton_peer::daemon::db::*;
    use kotton_record::open_sqlite;
    use sqlx::SqlitePool;
    use std::net::SocketAddr;
    use std::sync::Arc;

    async fn migrated_pool(path: &std::path::Path) -> Arc<SqlitePool> {
        let pool = open_sqlite(path).await.expect("open sqlite");
        kotton_device::db::MIGRATOR
            .run(&pool)
            .await
            .expect("run migrations");
        Arc::new(pool)
    }

    /// A valid `(public_key, did:key)` pair derived from a deterministic seed
    /// (arbitrary 32 bytes are not necessarily valid Edwards points).
    fn key_and_did(seed: u8) -> ([u8; 32], String) {
        let pk = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let did = DidKeyMethod::from_public_key_bytes(&pk)
            .unwrap()
            .to_string();
        (pk, did)
    }

    /// **A paired node is read with the posture its row records**, so a paired
    /// node that is no device of yours cannot hand a relay key your device
    /// presents: the dialler weighs a node's answer to `NodeRelay` by it, so a cosigner
    /// read back as a node of no posture would be taken for a full device. A row
    /// with none is read as none, and a later write that knows none keeps it.
    #[tokio::test]
    async fn a_paired_node_is_read_with_the_posture_its_row_records() {
        let dir = tempfile::tempdir().unwrap();
        let db = migrated_pool(&dir.path().join("net.db")).await;
        let rows = [(7u8, "cosigner", Some("cosigner")), (8, "vault", Some("blind-storage")), (9, "desktop", Some("full")), (10, "old", None)];
        for (seed, id, posture) in rows {
            let (pk, did) = key_and_did(seed);
            insert_paired_node(&db, id, "alice", &did, &pk, "[]", 0, posture).await.unwrap();
        }
        let (pk, did) = key_and_did(7);
        insert_paired_node(&db, "cosigner", "alice", &did, &pk, "[]", 1, None).await.unwrap();

        let read = |id: &str, nodes: &[kotton_wire::peer::PairedNode]| nodes.iter().find(|n| n.id == id).unwrap().posture.clone();
        let nodes = list_paired_nodes(&db, "alice").await.unwrap();
        assert_eq!(read("cosigner", &nodes).as_deref(), Some("cosigner"), "a write that knew no posture erased it");
        assert_eq!(read("vault", &nodes).as_deref(), Some("blind-storage"));
        assert_eq!(read("desktop", &nodes).as_deref(), Some("full"));
        assert_eq!(read("old", &nodes), None);
        for id in ["cosigner", "vault", "desktop", "old"] {
            let one = get_paired_node_by_id(&db, "alice", id).await.unwrap().unwrap();
            assert_eq!(one.posture, read(id, &nodes), "{id} by its label");
        }
    }

    /// **A posture the row records but this build does not recognise is not
    /// *full*.** A newer variant read after a downgrade,
    /// or a corrupted row, is no reason to accept an `offer`: the dialler reads
    /// it as `kuserd`'s `NodeRelay` arm does from the other end — anything but
    /// `full`, or no posture at all, is not full.
    #[tokio::test]
    async fn a_posture_this_build_does_not_recognise_offers_nothing() {
        use kotton_peer::relay_keys::offers_from;
        let dir = tempfile::tempdir().unwrap();
        let db = migrated_pool(&dir.path().join("net.db")).await;
        let (pk, did) = key_and_did(11);
        insert_paired_node(&db, "newer", "alice", &did, &pk, "[]", 0, Some("steward")).await.unwrap();
        let node = list_paired_nodes(&db, "alice").await.unwrap().pop().unwrap();
        assert!(!offers_from(node.posture), "an unrecognised posture was read as full");
        let one = get_paired_node_by_id(&db, "alice", "newer").await.unwrap().unwrap();
        assert!(!offers_from(one.posture), "an unrecognised posture was read as full, by its label");
    }

    #[tokio::test]
    async fn update_paired_node_address_replaces_the_stale_addr() {
        let dir = tempfile::tempdir().unwrap();
        let db = migrated_pool(&dir.path().join("net.db")).await;
        let (pk, did) = key_and_did(7);

        // Paired with the (stale) enrollment-bootstrap address.
        let stale: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        insert_paired_node(
            &db,
            "node1",
            "alice",
            &did,
            &pk,
            &serde_json::to_string(&vec![stale]).unwrap(),
            0,
            None,
        )
        .await
        .unwrap();

        // A successful direct connect observed a different live address.
        let fresh: SocketAddr = "203.0.113.5:5555".parse().unwrap();
        update_paired_node_address(&db, "alice", &did, fresh)
            .await
            .unwrap();

        let nodes = list_paired_nodes(&db, "alice").await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].addresses,
            vec![fresh],
            "the stored address is refreshed to the live one"
        );
    }

    #[tokio::test]
    async fn update_paired_node_address_is_a_noop_for_an_unknown_node() {
        // Best-effort: updating a device not paired to this user must not error.
        let dir = tempfile::tempdir().unwrap();
        let db = migrated_pool(&dir.path().join("net.db")).await;
        let (_pk, did) = key_and_did(9);
        let addr: SocketAddr = "203.0.113.9:9999".parse().unwrap();
        update_paired_node_address(&db, "alice", &did, addr)
            .await
            .expect("unknown-node update is a no-op, not an error");
        assert!(list_paired_nodes(&db, "alice").await.unwrap().is_empty());
    }
}
