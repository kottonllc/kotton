-- The bearer-credential door is retired (DEC-0053): a browser is paired like a
-- device and its channel is its session, so no token is issued, stored, or
-- validated. The table 0019 created holds only hashes of tokens nothing will
-- ever present again; it goes with the door.
DROP TABLE IF EXISTS web_shell_credentials;
