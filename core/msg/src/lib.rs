// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `msg` domain — direct messages and channels between principals.
//!
//! Two shapes, one protocol (RFC-0064). A **direct message** is sealed to one
//! recipient's key. A **channel** is sealed to a per-epoch channel key, handed
//! to each member as a wrapped key grant, so adding or removing a member mints
//! the next epoch rather than re-encrypting history.
//!
//! Both are ordinary records. A message is written to the sender's store and
//! delivered by replication, not by a message bus — which is why messaging owns
//! no transport and no delivery guarantee of its own: the store's replication
//! is the delivery, and a message that has not synced is simply a record that
//! has not synced.
//!
//! **Epoch 0 is absent, not zero.** Grants and messages written before epochs
//! existed carry no epoch field and read as the channel's first key. That keeps
//! a conversation already in progress readable by the people already in it,
//! which is the identity-continuity invariant applied to a conversation rather
//! than an identity — and it outranks anything a later tightening would gain.
pub mod daemon;
pub mod envelope;
pub mod read_marks;
pub mod share;
