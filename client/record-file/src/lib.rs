// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton-record-file` — a governance record's file, and its row (RFC-0088, phase one).
//!
//! Three things, and the reason they are one crate is that none of them may disagree:
//!
//! - [`header`] — **the** record header parser. The board generator, every gate in `xtask`,
//!   and the converter read a field through these functions and no others.
//! - [`row`] — the byte-exact map between a record file and a row of
//!   `sh.kotton.governance.record`: [`row::to_row`] and [`row::to_file`], each the other's
//!   inverse (rule 2: the markdown file is the wire format).
//! - [`schema`] — that schema's definition, and the principal the converter acts as.
//!
//! It links `serde_json` and nothing else, because `xtask` links it and `just lint` pays for
//! whatever `xtask` does.

pub mod header;
pub mod row;
pub mod schema;
