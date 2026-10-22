// SPDX-License-Identifier: AGPL-3.0-or-later
//! Serde helper: carry a `Vec<u8>` as a base64 string on the wire.
//!
//! The peer/IPC wire is JSON, where a bare `Vec<u8>` serializes as an **array of
//! numbers** — roughly 4x the bytes, and slow to parse element-by-element. Bulk
//! sealed blobs (packs, large objects) use this instead so they travel as compact
//! base64 (~1.33x). Applied per field: `#[serde(with = "crate::base64_bytes")]`.
//!
//! Encoding only — no seal, no format dependency under one. The field stays a
//! `Vec<u8>` in Rust; only its wire form changes.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize `bytes` as a base64 string.
pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
}

/// Deserialize a base64 string back into bytes.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    BASE64_STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
}
