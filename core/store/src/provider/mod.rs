// SPDX-License-Identifier: AGPL-3.0-or-later
//! Generic object storage providers

pub mod blinded;
pub mod chunker;
pub mod history;
pub mod manifest;
pub mod pack;
pub mod packed;
pub mod replay;
pub mod superblock;
pub mod cached;
pub mod encrypted;
pub mod local;
pub mod memory;
pub mod sealed_only;
pub mod s3;

#[cfg(test)]
pub mod contracts;

pub use blinded::BlindedObjectStorage;
pub use cached::CachedObjectStorage;
pub use encrypted::{open_envelope, path_aad, seal_envelope, EncryptedObjectStorage};
pub use local::LocalObjectStorage;
pub use memory::MemoryObjectStorage;
pub use sealed_only::SealedOnlyStorage;
pub use s3::{S3Shelf, S3Shelves};
pub use history::{Entry as HistoryEntry, Segment as HistorySegment};
pub use replay::{replay, ReplayState, Version as HistoryVersion};
pub use packed::{LooseObjectSource, PackedObjectStorage};
