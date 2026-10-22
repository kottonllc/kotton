-- Event log table for the system daemon
-- All daemon-emitted events are persisted here for lettuce events / MCP get_events.

CREATE TABLE IF NOT EXISTS events (
    id        TEXT    PRIMARY KEY,
    category  TEXT    NOT NULL,
    level     TEXT    NOT NULL,
    message   TEXT    NOT NULL,
    payload   TEXT,
    timestamp INTEGER NOT NULL  -- Unix seconds
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_category  ON events (category);
CREATE INDEX IF NOT EXISTS idx_events_level     ON events (level);
