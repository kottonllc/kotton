-- What this device's last pass found when it ran short of room for what its
-- pins keep whole (kotton #55; RFC 0002's Exit: "when a device that keeps a
-- drive whole runs short of room, it says so and names the setting that keeps
-- less"). `kotton_device::users::pins` writes and reads it.
--
-- A fact about this device and its disk, not the person's: their settings are
-- records in their drive (`sh.kotton.pin`), and this is what this device made
-- of them last time. One row per person and drive while the shortfall lasts;
-- the pass that fits deletes it. `settings` is a JSON list of the settings
-- that keep more than fits, each as `pin` names it.
CREATE TABLE IF NOT EXISTS pin_room (
    user_id     TEXT    NOT NULL,
    drive       TEXT    NOT NULL,
    held        INTEGER NOT NULL,
    budget      INTEGER,
    wanted      INTEGER NOT NULL,
    settings    TEXT    NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, drive)
);
