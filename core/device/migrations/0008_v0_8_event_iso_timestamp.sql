-- M22a: Add iso_timestamp column to events table.
--
-- ISO 8601 makes the `since` cursor query human-readable in the inspector
-- and trivially correct for display without client-side conversion.
-- The existing `timestamp` (Unix seconds INTEGER) is kept for backward
-- compatibility and efficient range queries.

ALTER TABLE events ADD COLUMN iso_timestamp TEXT;

-- Back-fill existing rows: convert Unix seconds to ISO 8601.
UPDATE events
SET iso_timestamp = datetime(timestamp, 'unixepoch') || 'Z'
WHERE iso_timestamp IS NULL;
