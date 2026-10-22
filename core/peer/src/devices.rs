// SPDX-License-Identifier: AGPL-3.0-or-later
//! The user's own device list — the machines they have enrolled, by name.
//!
//! On whose authority? **The user's fleet**, which is why this is `peer`'s and
//! not `device`'s: a single machine knows its own fingerprint, but the list of
//! *all* the machines a user owns is a fact about the fleet.
//!
//! ## What this is not
//!
//! It is not the routing table and it is not membership. Three structures
//! record something about a device and none is a superset of the others:
//!
//! | | keyed by | carries | read by |
//! | --- | --- | --- | --- |
//! | `device_routing` (`device`) | fingerprint | user id | connection dispatch |
//! | [`crate::membership`] `Member` | DID | role, posture, label | pairing, allowlists |
//! | this | fingerprint | **name, added-at, last-seen** | nothing yet |
//!
//! **Nothing reads this list yet.**
//! It is kept because the human-facing name and the added-at/last-seen
//! timestamps exist nowhere else, and a "these are your devices" view needs
//! exactly those. Written down rather than deleted, because unused and
//! unfinished look identical from a call-site count.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::SystemTime;

/// One enrolled machine, as the user would see it listed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub fingerprint: String,
    pub added_at: SystemTime,
    pub last_seen: SystemTime,
}

/// The on-disk shape of `devices.json`. Private: the file format is this
/// module's business, and the wrapper object is why it is not a bare array.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DeviceRegistry {
    devices: Vec<DeviceInfo>,
}

/// A user's enrolled devices.
///
/// **Mutating does not persist.** `add`, `remove` and `update_seen` change the
/// list and nothing else; [`DeviceList::save`] is a separate call. That is a
/// change from the `UserRuntime` methods this replaced, which each wrote
/// `devices.json` **and `config.toml`** — the store's file, which has nothing
/// to do with a device list. The two were bundled only because one `save()`
/// happened to write both.
#[derive(Debug, Clone, Default)]
pub struct DeviceList {
    devices: Vec<DeviceInfo>,
}

impl std::ops::Deref for DeviceList {
    type Target = [DeviceInfo];
    fn deref(&self) -> &Self::Target {
        &self.devices
    }
}

impl DeviceList {
    /// Read `devices.json` from a user's base directory. A missing file is an
    /// empty list rather than an error — a user who has enrolled nothing is
    /// an ordinary user, not a broken one.
    pub fn load(base_dir: &Path) -> Result<Self> {
        let path = base_dir.join("devices.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path).context("Failed to read devices.json")?;
        let registry: DeviceRegistry =
            serde_json::from_str(&data).context("Failed to parse devices.json")?;
        Ok(Self {
            devices: registry.devices,
        })
    }

    /// Write `devices.json` into a user's base directory.
    pub fn save(&self, base_dir: &Path) -> Result<()> {
        let registry = DeviceRegistry {
            devices: self.devices.clone(),
        };
        let json =
            serde_json::to_string_pretty(&registry).context("Failed to serialize devices")?;
        std::fs::write(base_dir.join("devices.json"), json)
            .context("Failed to write devices.json")?;
        Ok(())
    }

    /// Enrol a device. Refuses a fingerprint already present: the fingerprint
    /// *is* the machine, so two entries for one would make "which is it"
    /// undecidable.
    pub fn add(&mut self, device: DeviceInfo) -> Result<()> {
        if self
            .devices
            .iter()
            .any(|d| d.fingerprint == device.fingerprint)
        {
            anyhow::bail!(
                "Device with fingerprint {} already exists",
                device.fingerprint
            );
        }
        self.devices.push(device);
        Ok(())
    }

    /// Drop a device. Absent is an error rather than a no-op, so a caller that
    /// believed it was removing something learns that it was not.
    pub fn remove(&mut self, fingerprint: &str) -> Result<()> {
        let before = self.devices.len();
        self.devices.retain(|d| d.fingerprint != fingerprint);
        if self.devices.len() == before {
            anyhow::bail!("Device with fingerprint {fingerprint} not found");
        }
        Ok(())
    }

    /// Mark a device as seen now.
    pub fn update_seen(&mut self, fingerprint: &str) -> Result<()> {
        match self
            .devices
            .iter_mut()
            .find(|d| d.fingerprint == fingerprint)
        {
            Some(device) => {
                device.last_seen = SystemTime::now();
                Ok(())
            }
            None => anyhow::bail!("Device with fingerprint {fingerprint} not found"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(fingerprint: &str) -> DeviceInfo {
        let now = SystemTime::now();
        DeviceInfo {
            device_id: format!("device_{fingerprint}"),
            device_name: "Test Device".to_string(),
            fingerprint: fingerprint.to_string(),
            added_at: now,
            last_seen: now,
        }
    }

    #[test]
    fn a_duplicate_fingerprint_is_refused() {
        let mut list = DeviceList::default();
        list.add(device("fp1")).unwrap();
        assert!(list.add(device("fp1")).is_err());
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn remove_reports_an_absent_device() {
        let mut list = DeviceList::default();
        list.add(device("fp1")).unwrap();
        assert!(list.remove("nope").is_err());
        list.remove("fp1").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn update_seen_advances_only_the_named_device() {
        let mut list = DeviceList::default();
        list.add(device("fp1")).unwrap();
        list.add(device("fp2")).unwrap();
        let untouched = list[1].last_seen;
        list.update_seen("fp1").unwrap();
        assert_eq!(list[1].last_seen, untouched);
        assert!(list.update_seen("gone").is_err());
    }

    #[test]
    fn a_missing_file_loads_as_empty_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        assert!(DeviceList::load(dir.path()).unwrap().is_empty());

        let mut list = DeviceList::default();
        list.add(device("fp1")).unwrap();
        list.save(dir.path()).unwrap();

        let loaded = DeviceList::load(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].fingerprint, "fp1");
    }

    /// `save` writes the device list and nothing else. The methods this
    /// replaced also wrote `config.toml`, which belongs to the store.
    #[test]
    fn save_touches_only_devices_json() {
        let dir = tempfile::tempdir().unwrap();
        DeviceList::default().save(dir.path()).unwrap();
        let written: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(written, vec!["devices.json"]);
    }
}
