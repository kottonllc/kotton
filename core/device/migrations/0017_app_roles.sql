-- M0017: app role registry
--
-- Maps named system roles to installed app IDs.  The host queries this table
-- at boot to determine which app to open for each role instead of hardcoding
-- app IDs.
--
-- Known roles:
--   "shell"  — primary user interface; opened unconditionally at startup.
--              Required capability contract: declares `shell.exec = true`.
--   "dock"   — optional persistent dock surface.
--              Required capability contract: declares `events.subscribe = true`.
--
-- The daemon validates the role contract at SetRole time:  if the target app
-- does not satisfy the required capabilities the request is rejected with an
-- error.  This prevents misconfiguration from making the system unbootable.
--
-- Default values ("sh.kotton.shell" for "shell") are inserted by the daemon
-- at startup if no row exists for that role, so a fresh install always has a
-- usable default without requiring the user to run any configuration command.

CREATE TABLE IF NOT EXISTS app_roles (
    role    TEXT NOT NULL PRIMARY KEY,
    app_id  TEXT NOT NULL
);
