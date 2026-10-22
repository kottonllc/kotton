-- A paired node's posture, projected beside its key so the peer path can
-- enforce it without opening the user's store (RFC-0078: the gateway is a
-- device that speaks one verb). NULL for rows written before this column
-- existed, which the peer path reads as "no restriction beyond paired".
ALTER TABLE paired_nodes ADD COLUMN posture TEXT;
