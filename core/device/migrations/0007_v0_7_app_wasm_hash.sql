-- M20a: add wasm_hash to app_registry
--
-- Stores a SHA-256 hex digest of the embedded WASM bytes at install time.
-- On daemon startup, auto_install_bundled_apps compares this hash against
-- the currently embedded bytes and reinstalls if they differ — eliminating
-- the need to manually wipe the data directory after `cargo xtask build-apps`.

ALTER TABLE app_registry ADD COLUMN wasm_hash TEXT NOT NULL DEFAULT '';
