-- kdeviced schema v5: each person's own key, kept before it stands for anything
-- (TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key).
--
-- An operator used to be made by another operator naming a key (`SudoersAdd`),
-- and the person the key was said to answer for proved nothing. Now a person's
-- own daemon mints a key into their sealed store and proves it here by signing
-- this connection's nonce (`Authenticate` with `person`); a key that is not
-- yet an operator's is kept in this table as that person's, and admits
-- nothing. An operator then makes the *person* an operator (`OperatorAdd`),
-- which moves their kept key into `operators` — so no operator ever names a
-- key they do not hold.
--
-- `person` is unique: the first key a person's daemon proves is theirs, and a
-- second, different one is refused rather than replacing it. That is trust on
-- first use per person, the same posture as the device's own first operator
-- (DEC-0017), and its reach is this socket's; the record says what closes it.
CREATE TABLE IF NOT EXISTS operator_keys_kept (
    did       TEXT PRIMARY KEY,
    person    TEXT NOT NULL UNIQUE,
    kept_at   INTEGER NOT NULL
);
