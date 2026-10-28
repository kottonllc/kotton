-- kotton #171, on kotton-protocol #26 (RFC 0002, "Exit" and "The types").
--
-- **A device's pin settings are its own** — its default, and each drive or
-- folder set the other way — kept on this device and nothing of them
-- replicated. Until now they were `sh.kotton.pin` records in the person's
-- drive; this is where they live instead. One row per person and scope:
-- `scope` is `default`, `drive` or `folder`, `drive` names the drive for the
-- last two (empty for the default), `folder` the folder for the last (empty
-- otherwise), `value` is `whole` or `on-demand`. `default` at a drive or a
-- folder is the row deleted. `kotton_device::users::pins` writes and reads it,
-- and moves this device's own `sh.kotton.pin` records here the first time it
-- reads (`pins::migrate`), deleting each from the drive as it does.
CREATE TABLE IF NOT EXISTS pin_settings (
    user_id TEXT    NOT NULL,
    scope   TEXT    NOT NULL,
    drive   TEXT    NOT NULL DEFAULT '',
    folder  TEXT    NOT NULL DEFAULT '',
    value   TEXT    NOT NULL,
    set_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, scope, drive, folder)
);

-- **A drive's id**: minted at random once, at `drive create`, sealed with its
-- name, and shared by every copy a move makes, so two finished copies that
-- share it are one drive kept twice (`kotton_device::users::drive_verbs`).
-- What this device records of a drive carries it beside the vault's own tree
-- id. It is opened from the sealed name, so it is never sent to a vault and
-- is in no path or name a vault or relay sees. The tenancy's own tree has no
-- sealed name, and its id is `first` (`kotton_wire::ipc::FIRST_DRIVE_ID`)
-- until it becomes a made drive (kotton #124). A made drive recorded before
-- this has none until the next listing of its vault records it.
ALTER TABLE drives ADD COLUMN drive_id TEXT;
UPDATE drives SET drive_id = 'first' WHERE tree = 'local';
