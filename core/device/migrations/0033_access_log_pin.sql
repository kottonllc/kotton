-- kotton #450: where this device's access log goes.
--
-- **The access log is kept on the device that wrote it** unless that device
-- pins it to a drive (the protocol's *The first release is a platform a
-- stranger can use from the command line*). This is the pin: one row per
-- person, naming the drive the log rides to, and `personal` is the only drive
-- it may name. No row is the log kept here, which is every device's default. It
-- is this device's own, as `pin_settings` is: nothing of it is sent to a vault
-- or to another device. `kotton_device::users::log_pin` writes and reads it,
-- and the sync engine reads it for each pass of `personal`.
CREATE TABLE access_log_pin (
    user_id TEXT    NOT NULL PRIMARY KEY,
    drive   TEXT    NOT NULL,
    set_at  INTEGER NOT NULL
);
