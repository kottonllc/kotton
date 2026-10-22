-- Rename coord_url → relay_url in device_config
--
-- `kotton-coord` was renamed to `kotton-relay`; the corresponding device_config
-- key is updated to match. Existing rows (if any) are migrated; the migration
-- is a no-op on fresh installs where the key was never written.

UPDATE device_config SET key = 'relay_url' WHERE key = 'coord_url';
