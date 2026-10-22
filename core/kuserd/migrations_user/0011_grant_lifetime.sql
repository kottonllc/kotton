-- Per-envelope grant lifetime state (TASK-a-grant-cannot-be-once-or-while-open).
--
-- The signed `GrantEnvelope` says *what* is granted; this says *how long*, for
-- the two lifetimes a clock cannot express. `Uses(n)` carries a counter the
-- daemon decrements once per activation and `WhileOpen` a binding to the running
-- instance. `UntilRevoked` and `Seconds` need no row here — their enforcement is
-- the revocation list and `expires_at`. When either counted lifetime is spent,
-- the daemon writes the envelope id into `revocation_list`, so the runner's
-- existing revocation check is what denies it — no second enforcement path.
CREATE TABLE IF NOT EXISTS grant_lifetime (
    envelope_id    TEXT    NOT NULL PRIMARY KEY, -- GrantEnvelope.id
    app_id         TEXT    NOT NULL,             -- for teardown by app
    kind           TEXT    NOT NULL,             -- 'uses' | 'while_open'
    uses_remaining INTEGER,                      -- for 'uses'; NULL otherwise
    bound_instance TEXT,                         -- for 'while_open' once activated
    set_at         INTEGER NOT NULL              -- Unix seconds (UTC)
);
CREATE INDEX IF NOT EXISTS idx_grant_lifetime_app ON grant_lifetime (app_id);
