-- A person may keep several drives on one vault (#56; RFC 0002 in
-- kotton-protocol: "a person may have several drives, on one vault or many").
-- Until now a drive was named by the vault's key and the tenancy alone, because
-- a vault kept one pool per tenant; now the vault keeps the tenancy's own tree
-- and any drive made beside it, each a sealed tree of its own, so the record
-- names the tree too, and the person's name for the drive.
-- `kotton_peer::daemon::drives` says what the record is and who writes it.
--
-- `tree` is the mount the vault keeps the drive's sealed tree under: `local`
-- for the tenancy's own (the pool a vault kept before), `drive-<32 hex>` for a
-- made one (`kotton_wire::ipc::MadeDrive`). It is the vault's word for the
-- tree, minted fresh for each vault a drive is kept on, so it joins nothing
-- across vaults, and it is part of the key: one person, one vault, one
-- tenancy, several trees.
--
-- `name` is the person's name for the drive, opened on this device from what
-- the vault keeps sealed for it; the tenancy's own tree has none sealed, and
-- every device calls it `personal` (`kotton_wire::ipc::FIRST_DRIVE_NAME`). It
-- keys nothing: a name is text the person reads, and two vaults may each keep
-- a `personal`.
--
-- SQLite changes a primary key by rebuilding the table. Every row today is a
-- tenancy's own tree — the only kind there was — so each carries over as that,
-- in place, named `personal`: the per-tenant pool becomes the person's first
-- drive on that vault, and nothing at the vault moves.
CREATE TABLE drives_0028 (
    user_id     TEXT    NOT NULL,
    vault_key   BLOB    NOT NULL,
    tenancy     TEXT    NOT NULL,
    tree        TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    node_id     TEXT    NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, vault_key, tenancy, tree)
);
INSERT INTO drives_0028 (user_id, vault_key, tenancy, tree, name, node_id, recorded_at)
    SELECT user_id, vault_key, tenancy, 'local', 'personal', node_id, recorded_at
    FROM drives;
DROP TABLE drives;
ALTER TABLE drives_0028 RENAME TO drives;
CREATE INDEX IF NOT EXISTS idx_drives_node ON drives (user_id, node_id);
CREATE INDEX IF NOT EXISTS idx_drives_name ON drives (user_id, name);
