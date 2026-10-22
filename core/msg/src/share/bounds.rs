// SPDX-License-Identifier: AGPL-3.0-or-later
//! How large a share may be, and the sentence one larger is refused with
//! (RFC-0090; `TASK-the-share-sheet-reads-a-file-whole-before-the-node-refuses-it-for-size`).
//!
//! **One source, compiled into two crates.** `kotton-msg` refuses with it
//! (`kotton_msg::share::Manifest::of_file` and its group form), and the
//! shell's logic in `guest/apps/kotton-shell/logic` compiles this same file
//! with a `#[path]` and refuses with it from the size the file browser's
//! listing already shows, before it reads the file. The guest has no host
//! call that answers a bound, and a second copy of the numbers or the words
//! would be a second answer nothing holds to the first. That is a region
//! crossing, and it is declared in tier-check's `REGION_EXCEPTIONS` on
//! DEC-0041's reason: a guest's reach is its WIT import set, and this file
//! adds nothing to it — a few numbers, a sentence and a comparison, reaching
//! no key, store or host. So this file names nothing outside `core`'s own
//! prelude: what is said here must compile in both crates, and the rule
//! ([`carries`]) is here as well as the bounds, so the two cannot disagree
//! about where the line is either.
//!
//! The node stays the authority. A listing can be stale — the file may have
//! grown since it was read — and the node refuses from the bytes it is
//! handed whatever the shell decided; the shell's refusal only spares a
//! person reading a whole film into memory to be told no.

/// The largest file a share carries `inline`, in plaintext bytes: five MiB.
///
/// The bytes travel base64 inside the manifest, inside the signed inner
/// envelope, which is sealed and travels base64 again inside the contact
/// request: about 16/9 of the plaintext on the wire. Five MiB comes to a little
/// under nine, which leaves the 10 MiB frame room for everything around it; a
/// test seals a share of exactly this size and measures the request.
///
/// Above it a share travels by the streaming transport, in ranges, and its
/// manifest carries `stream` instead of `inline` — to a person sealed to them,
/// to a group under the channel's key ([`GROUP_INLINE_MAX`]).
pub const INLINE_MAX: usize = 5 * 1024 * 1024;

/// The largest file a share carries at all, in plaintext bytes: 256 MiB.
///
/// Not a frame bound — above `INLINE_MAX` a share is as many frames as it
/// needs (RFC-0048 ST1). It is the store's: the recipient's copy is assembled
/// whole and filed with the store's whole-file write (`UserStore::write_file`,
/// a `&[u8]`), and a whole-buffered file is held to 256 MiB on this node
/// (`kotton-device`'s `MAX_BUFFERED_FILE_BYTES`: *a store that cannot stream
/// refuses above this rather than trying*). A larger share would be one this
/// node refuses to hold, so it is refused before anything is sealed.
pub const STREAM_MAX: usize = 256 * 1024 * 1024;

/// The sentence a file of `size` bytes, above [`STREAM_MAX`], is refused with.
///
/// `u64`, not `usize`: the shell reads a size off a listing on a 32-bit
/// target, where a file of several GiB would wrap in a `usize` and be named
/// smaller than it is.
pub fn too_large(size: u64) -> String {
    format!(
        "this file is {} — a share carries at most {}, because the copy is assembled whole on \
         their node and written there in one piece, so nothing was sent",
        mib(size),
        mib(STREAM_MAX as u64)
    )
}

/// The largest file a share **to a group** carries **inline**, in plaintext
/// bytes: [`INLINE_MAX`], what a person is carried inline (RFC-0090, *Delivery ›
/// To a group*;
/// `TASK-a-file-shared-with-a-group-is-a-copy-of-each-members-under-shared-with-you`).
///
/// **The same figure, because a channel copy is encoded no more than a direct
/// message is.** A group share's manifest is sealed under the channel key
/// first, and that ciphertext rides inside the envelope each member's copy is
/// sealed in as its own bytes — after the envelope's JSON, not base64 inside it
/// (`kotton_msg::envelope::ChannelCopy::body`) — so the frame each member is
/// handed is a direct share's, give or take the envelope's fields. It was one
/// `RANGE_LEN`, four MiB, while the channel ciphertext was base64 inside the
/// JSON as well: five MiB then came to nearly twelve on the wire, past the
/// frame (`TASK-a-channel-copy-carries-its-sealed-bytes-base64-twice`). A test
/// seals a group share at exactly this size, measures the request each member
/// is handed against the frame and against a direct share of the same file.
///
/// **Above it a group share streams, as a direct one does** — up to
/// [`STREAM_MAX`], the same bound, by the same rule ([`carries`]). Its manifest
/// carries `stream`, and the file's ranges follow it each sealed **once, under
/// the channel's key**, and handed to every current member as a channel copy
/// of their own: one ciphertext per range, as one ciphertext is the manifest
/// (`TASK-a-share-to-a-group-above-the-inline-cap-is-a-stream-to-each-member`;
/// the orchestrator's ruling of 2026-10-09 on RFC-0090). Until then a group
/// share above this was refused, with a sentence that said a larger file would
/// travel as a separate stream to each member and that was not built.
pub const GROUP_INLINE_MAX: usize = INLINE_MAX;

/// Who a share is to, which is what decides how its bytes travel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum To {
    /// One person, as a direct message: up to [`STREAM_MAX`], streamed above
    /// [`INLINE_MAX`].
    Person,
    /// A group, over its channel: up to [`STREAM_MAX`], streamed above
    /// [`GROUP_INLINE_MAX`] under the channel's key.
    Group,
}

/// Whether a share to `to` carries a file of `size` bytes, or the sentence
/// it is refused with — **the one rule**: above [`STREAM_MAX`], with
/// [`too_large`]'s sentence, for a person and a group alike. The store files a
/// copy in one piece on every member's node as on one person's, so the bound
/// is the same; `to` stays in the rule because it is where a bound for a group
/// would go if one ever differed, and the shell asks it with the kind it is
/// sharing to.
pub fn carries(to: To, size: u64) -> Result<(), String> {
    match to {
        To::Person | To::Group if size > STREAM_MAX as u64 => Err(too_large(size)),
        _ => Ok(()),
    }
}

/// `bytes` in MiB, to one decimal place: how every sentence here names a size.
pub(crate) fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}
