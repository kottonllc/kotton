-- M0016: add bundle_path and dev flag to app_registry
--
-- `bundle_path` is the absolute filesystem path to the app's pre-built web
-- bundle directory (i.e. a `dist/` folder produced by `pnpm build`).
-- NULL for WASM-only apps that have no web UI component.
--
-- `dev` is 1 if this entry was registered with `app dev` (points at a live
-- build output directory that may still be under active development).
-- Dev entries are shown with a "(dev)" badge in `app list` and are not
-- eligible for export or network distribution.
-- 0 (or NULL) means a production install.

ALTER TABLE app_registry ADD COLUMN bundle_path TEXT;
ALTER TABLE app_registry ADD COLUMN dev INTEGER NOT NULL DEFAULT 0;
