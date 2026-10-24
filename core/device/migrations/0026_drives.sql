-- A drive, recorded as a drive on the device (#61; RFC 0002 in kotton-protocol:
-- "a drive is a tenancy on a vault", and "a device names a drive by the vault's
-- key and the tenancy"). `kotton_peer::daemon::drives` says what the record is
-- and who writes it.
--
-- `vault_key` is the vault's key, the one the device dials it under and the key
-- its paired node row carries; `tenancy` the name the vault keeps the person's
-- pool under; `node_id` the paired node the drive is reached through. A vault
-- keeps one pool per tenant today, so a person has one tenancy on a vault and
-- the record names that one; the key admits several drives on one vault when a
-- vault keeps them (#56).
--
-- `user_id` is the person on this device whose drive it is. On a vault this
-- table is one of "the device tables a vault leaves empty" that
-- `kvaultd::tenancy` sweeps by `user_id`.
CREATE TABLE IF NOT EXISTS drives (
    user_id     TEXT    NOT NULL,
    vault_key   BLOB    NOT NULL,
    tenancy     TEXT    NOT NULL,
    node_id     TEXT    NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, vault_key, tenancy)
);
CREATE INDEX IF NOT EXISTS idx_drives_node ON drives (user_id, node_id);

-- The drives enrolled before the record existed. Until now the one thing that
-- said a node was a drive was the posture the enrolment wrote on its row, and
-- a vault's tenancy was the person's own name on this device (the admit checks
-- the two agree, `refused_as`), so each such row is read once, here, into the
-- record. Nothing reads a row's posture for this after it.
INSERT OR IGNORE INTO drives (user_id, vault_key, tenancy, node_id, recorded_at)
    SELECT user_id, public_key, user_id, id, paired_at
    FROM paired_nodes
    WHERE posture = 'blind-storage';
