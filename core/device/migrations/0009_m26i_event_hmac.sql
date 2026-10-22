-- M26i: Add HMAC integrity chain column to events table.
--
-- Each row's hmac is HMAC-SHA256(key=hmac_key, data=prev_hmac || event_id_bytes || payload_bytes)
-- where hmac_key = HKDF(master_secret, "kotton:hmac:events:v1").
--
-- Existing rows get the zero sentinel (X'') — they predate the chain and are skipped
-- during verification. Only rows written after this migration carry a valid hmac.

ALTER TABLE events ADD COLUMN hmac BLOB NOT NULL DEFAULT X'';
