-- The box's operator credential, by its public half: the key a landlord's
-- desktop speaks the landlord's four verbs under, over the peer transport
-- (`TASK-the-landlords-verbs-reach-the-desktop-over-the-wire`). A row, not a
-- file, so revoking it is one DELETE beside the allowlist it projects into.
--
-- Beside `paired_nodes` because it is the same kind of fact — a key this node
-- admits at the handshake — and projected by the same function
-- (`reproject_allowlist`). **No `user_id` column, on purpose**: the operator is
-- nobody's tenant, so a drop's sweep of every table keyed by a tenant
-- (`kvaultd::tenancy::sweep`) never takes it. Only a vault's door writes it; on
-- a device it stays empty, and no verb of a device's names it.
CREATE TABLE IF NOT EXISTS operator_key (
    public_key BLOB PRIMARY KEY NOT NULL,
    enrolled_at INTEGER NOT NULL
);
