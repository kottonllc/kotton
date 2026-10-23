-- A device's sync rules name a drive, and nothing else.
--
-- A rule used to name a paired node and a path: any node, another of the
-- person's devices among them, and a path nothing read. The sync engine now
-- replicates a device to its person's drives and to nothing else, so a rule is
-- kept under the drive itself — the vault's key and the person's tenancy on
-- it — with this device's direction for it and whether the background pass
-- syncs it. A rule for a node is not one this device can keep: the old table
-- goes, and its rules with it. A rule that named a vault is set again with
-- `sync add <drive>`.
DROP TABLE IF EXISTS sync_rules;

CREATE TABLE IF NOT EXISTS drive_rules (
    user_id       TEXT    NOT NULL,
    vault_key     BLOB    NOT NULL,
    tenancy       TEXT    NOT NULL,
    direction     TEXT,              -- 'push' | 'pull'; NULL is both ways
    watch         INTEGER NOT NULL DEFAULT 0,
    configured_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, vault_key, tenancy)
);
