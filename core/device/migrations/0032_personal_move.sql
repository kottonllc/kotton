-- kotton #124: the move of `personal` this device began and has not finished.
--
-- A move copies `personal` to a tree at another vault, names that copy
-- finished, and then retires the tree it left. Cut off between the naming and
-- the retire, two finished trees carry the first drive's id, and a move of it
-- is refused while two do, since two devices apart from each other may each
-- have made one (`kotton_device::users::drive_verbs::move_to`). This row is
-- how this device tells the move it began from that: the tree the move read
-- (`from_*`) and the tree it named finished (`to_*`), by the vault's key and
-- the vault's own word for each tree. Running the move again lets these two
-- through and retires the first. One row per person, written when the copy is
-- made and deleted when the move is finished or abandoned. It is this
-- device's own: nothing of it is sent to a vault or to another device.
CREATE TABLE personal_move (
    user_id    TEXT NOT NULL,
    tenancy    TEXT NOT NULL,
    from_vault BLOB NOT NULL,
    from_tree  TEXT NOT NULL,
    to_vault   BLOB NOT NULL,
    to_tree    TEXT NOT NULL,
    PRIMARY KEY (user_id, tenancy)
);
