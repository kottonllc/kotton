// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kdeviced` internals as a library.
//!
//! The binary in `main.rs` is a thin shell over this; the library exists so the
//! device-layer principal types (Article II's operator and supervised-child
//! classes) are `pub` enough to carry a `compile_fail` doctest — the mechanical
//! proof that a handler for one class cannot be handed the other
//! (`TASK-the-device-layer-principal-classes-are-untyped`).
pub mod db;
pub mod system;
