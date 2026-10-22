// SPDX-License-Identifier: AGPL-3.0-or-later
//! A share: a direct message whose body is a file (RFC-0090, *Mechanism › The
//! record*; `TASK-a-file-shared-with-a-contact-is-a-copy-of-theirs-under-shared-with-you`).
//!
//! **Nothing new is sealed, carried or stored.** A share to one person is a
//! direct message whose `type` is [`MESSAGE_TYPE`] and whose opened body holds a
//! [`Manifest`]: sealed to them with a fresh key, handed over their contact
//! door, kept in the sender's outbox until a device of theirs signs for it, and
//! waiting at their vault otherwise — every step the message protocol's own
//! (SH2, SH7). What this module adds is the manifest's shape, and the rules for
//! where the recipient's copy lands.
//!
//! **The manifest carries the thing and never where it lives (SH5).** Its fields
//! are fixed by this type: a name, a kind, a media type, a size, a digest and the
//! bytes. There is no field a path, a store, a root id or a key could ride in.
//!
//! **Above [`INLINE_MAX`] the bytes stream** (RFC-0090's unit 4,
//! `TASK-a-share-above-the-frame-cap-arrives-whole-by-the-streaming-transport`):
//! the manifest carries `stream` — its digest — instead of the bytes, and they
//! follow it as [`Range`]s of [`RANGE_LEN`], each sealed as a message of its own
//! and keyed by that digest, which the recipient's node files only once they
//! are whole and hash to it (`daemon::stream`). A share to a group streams
//! the same way above [`GROUP_INLINE_MAX`], each range's plaintext sealed once
//! under the channel's key and handed to every member as a channel copy
//! (`TASK-a-share-to-a-group-above-the-inline-cap-is-a-stream-to-each-member`).
//! Above [`STREAM_MAX`] a share is refused, to a person or a group: more than
//! the recipient's store files in one piece.
//! [`Manifest::origin`] is the one field that names anything of the sender's,
//! and it exists on the sender's own copy of a **direct** share only, sealed to
//! the sender's key alone: [`Manifest::for_recipient`] is what is sealed to the
//! recipient, and it is the manifest without it. A share to a **group** carries
//! no `origin` anywhere, the sender's own copy included: that copy is sealed
//! under the channel key, which every member holds.
//!
//! **The copy lands in one folder and nowhere else (SH6).** The recipient's node
//! files it at `Shared with you/<sender's card name>/<name>` in their Personal
//! tree ([`landing`]). Both names are words somebody else chose — the name the
//! sender gave their file, and the name the pair chose at the ceremony — so a
//! path is composed only from a [`Plain`] name, and a word that is not one is
//! **refused, never cleaned** ([`Plain::new`], the rule `roots::plain_name` in
//! the store takes for a name off the network). It refuses a word that is
//! empty; holds a `/` or a `\`; holds a control character; has a space at
//! either end; is `.` or `..`; or begins with `.`. A cleaned word is a word
//! that still landed somewhere nobody chose: `". .."` cleaned to `..` composed
//! a path the store collapses onto *Shared with you* itself. A **file name** the
//! rule refuses is the sender's word, so the share is refused before it is
//! sealed on the sender's node and filed nowhere on the recipient's. A **card
//! name** the rule refuses is no usable name: it is set aside, not cleaned, and
//! the folder is named by the first eight characters of the sender's AID, as a
//! card with no name is ([`sender_folder`]).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use kotton_sys::crypto::Hasher as _;
use serde::{Deserialize, Serialize};

/// The `message-type` a share carries (RFC-0064's envelope, `sh.kotton.message.v1`).
pub const MESSAGE_TYPE: &str = "share";

/// The `kind` of a manifest that carries a file's bytes.
pub const KIND_FILE: &str = "file";

/// The folder of the recipient's Personal tree a share from a person lands in
/// (RFC-0090 SH6), beside *Inbox*, which is the one a device of your own lands in.
pub const SHARED_WITH_YOU: &str = "Shared with you";

/// The peer frame cap a delivery travels under (`kotton-net`'s relayed and TCP
/// transports, 10 MiB; RFC-0048 ST1 keeps it where it is). Named here only so
/// [`INLINE_MAX`] can be held to it by a test: nothing in this crate frames.
pub const FRAME_CAP: usize = 10 * 1024 * 1024;

/// The plaintext one range of a streamed share carries: RFC-0048's
/// `RANGE_LEN`, four MiB, the range length the store's own sealed transfer
/// moves in. Every range but the last is exactly this long, so a carrier sees
/// the same frame for every range of every share (ST4: fixed boundaries, never
/// content-derived). Sealed, one comes to a little over seven MiB on the wire,
/// under [`FRAME_CAP`]; a test seals one and measures it.
pub const RANGE_LEN: usize = 4 * 1024 * 1024;

// How large a share may be, and the sentence one larger is refused with: a file
// of its own, because the shell's logic compiles it too and refuses from a
// listing's size with these words before it reads a file (`share/bounds.rs`).
mod bounds;
use bounds::mib;
pub use bounds::{carries, too_large, To, GROUP_INLINE_MAX, INLINE_MAX, STREAM_MAX};

/// What a share's opened body holds (RFC-0090, *The record*).
///
/// Absent optionals are **omitted**, never written as `null`: the sender's
/// signature covers the inner envelope's bytes exactly as sealed, and a field
/// that is not there must not be there in any spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The file's name as the sender had it — one segment, never a path.
    pub name: String,
    /// [`KIND_FILE`], or a schema NSID when the thing is a record of that schema.
    pub kind: String,
    /// The file's media type. The sender's store keeps none, so it is read from
    /// the name's extension ([`mime_for`]).
    pub mime: String,
    /// Plaintext length in bytes.
    pub size: u64,
    /// SHA-256 of the plaintext, lowercase hex.
    pub digest: String,
    /// The plaintext, base64, when it is at most [`INLINE_MAX`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<String>,
    /// When `inline` is absent: the streaming transport's id for the sealed
    /// stream that carries the bytes (RFC-0090's unit 4). The stream is keyed by
    /// its content (RFC-0048 ST3), so its id is [`Self::digest`]: the bytes
    /// follow as [`Range`]s naming that digest, each sealed as this manifest is,
    /// and the recipient's node files the share only once they are whole and
    /// hash to it. A manifest whose `stream` names other bytes than its digest
    /// is refused ([`Self::stream_holds`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
    /// Which file of the sender's this was — on the sender's own copy of a
    /// direct share only, which is sealed to them alone, and stripped before
    /// anything is sealed to a recipient ([`Self::for_recipient`]). Never under a
    /// channel key: a share to a group carries none, on any copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl Manifest {
    /// The manifest for a file called `name` holding `bytes`, with `origin`
    /// naming the sender's file on their own copy: the bytes `inline` up to
    /// [`INLINE_MAX`], and above it a `stream` the bytes follow as [`ranges`].
    ///
    /// Refused above [`STREAM_MAX`], with [`too_large`]'s sentence, and for a
    /// name that is not [`Plain`], with [`PLAIN_RULE`] — before anything is sealed.
    pub fn of_file(name: &str, bytes: &[u8], origin: Option<String>) -> Result<Self, String> {
        Self::shared(To::Person, name, bytes, origin)
    }

    /// The manifest for a file shared with `to`: inline up to that kind's
    /// inline bound, streamed above it, refused by [`carries`].
    fn shared(to: To, name: &str, bytes: &[u8], origin: Option<String>) -> Result<Self, String> {
        carries(to, bytes.len() as u64)?;
        let name = Plain::new(name)?.0;
        let digest = digest_of(bytes);
        let inline_max = match to {
            To::Person => INLINE_MAX,
            To::Group => GROUP_INLINE_MAX,
        };
        let streamed = bytes.len() > inline_max;
        Ok(Self {
            mime: mime_for(&name).to_string(),
            name,
            kind: KIND_FILE.to_string(),
            size: bytes.len() as u64,
            inline: (!streamed).then(|| B64.encode(bytes)),
            stream: streamed.then(|| digest.clone()),
            digest,
            origin,
        })
    }

    /// Whether this share's bytes follow it as a stream rather than inside it.
    pub fn is_streamed(&self) -> bool {
        self.inline.is_none() && self.stream.is_some()
    }

    /// Whether a streamed manifest is one the recipient's node may wait on:
    /// a file, its `stream` the digest it carries, its size one a stream may
    /// declare ([`Range::holds`]). What is wrong here stays wrong, so the
    /// share is refused, not waited on.
    pub fn stream_holds(&self) -> Result<(), String> {
        if self.kind != KIND_FILE {
            return Err(format!("a share of kind '{}' cannot be filed yet; only a file can", self.kind));
        }
        if self.stream.as_deref() != Some(self.digest.as_str()) {
            return Err("its stream names other bytes than its digest".to_string());
        }
        stream_size_holds(self.size)
    }

    /// The manifest as it is sealed to a recipient: everything but [`Self::origin`]
    /// (SH5). The one place the sender's copy and the recipient's differ.
    pub fn for_recipient(&self) -> Self {
        Self { origin: None, ..self.clone() }
    }

    /// The plaintext this manifest carries, checked against its own `size` and
    /// `digest` — or why it cannot be filed. A share that does not hold files
    /// nothing (RFC-0090, *Filing*, step 1). Its name is held to [`Plain`] at
    /// the door by the filing, not here: a name is where it lands, not what it is.
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        if self.kind != KIND_FILE {
            return Err(format!("a share of kind '{}' cannot be filed yet; only a file can", self.kind));
        }
        let Some(inline) = &self.inline else {
            return Err("this share's bytes travel by stream, not inside it".to_string());
        };
        let bytes = B64
            .decode(inline)
            .map_err(|_| "its bytes are not base64".to_string())?;
        if bytes.len() as u64 != self.size || digest_of(&bytes) != self.digest {
            return Err("its bytes do not match the digest it carries".to_string());
        }
        Ok(bytes)
    }
}

impl Manifest {
    /// The manifest for a file called `name` holding `bytes`, shared with a
    /// group: inline up to [`GROUP_INLINE_MAX`], and above it a `stream` whose
    /// ranges are each sealed once under the channel's key and handed to every
    /// current member (RFC-0090, *Delivery › To a group*, the ruling of
    /// 2026-10-09). Refused above [`STREAM_MAX`], as a share to a person is.
    pub fn of_file_for_a_group(name: &str, bytes: &[u8], origin: Option<String>) -> Result<Self, String> {
        Self::shared(To::Group, name, bytes, origin)
    }

    /// What a channel share's ciphertext opens to: this manifest, as JSON. The
    /// decrypted body of a `share` message *is* its manifest (RFC-0090, *The
    /// record*), sealed under the channel key at the epoch it is sent in, and
    /// every member is handed the same ciphertext of it.
    pub fn channel_body(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a manifest serialises")
    }

    /// The manifest a channel share's ciphertext opened to — or why it is
    /// none. One that carries its bytes neither inside it nor as a stream is
    /// refused here; one whose stream is not one a node may wait on is
    /// refused where the filing asks ([`Self::stream_holds`]), as a direct
    /// share's is.
    pub fn of_channel_body(plaintext: &[u8]) -> Result<Self, String> {
        let manifest: Self = serde_json::from_slice(plaintext)
            .map_err(|_| "what it opens to is not a share's manifest".to_string())?;
        if manifest.inline.is_none() && manifest.stream.is_none() {
            return Err("a share to a group carries its bytes inside it or as a stream, and this one does neither".to_string());
        }
        Ok(manifest)
    }
}

/// What opening a channel message shows: its text, or — for a share, whose
/// opened body is its manifest — the file's name, as a direct share opens to
/// it. Never the bytes: a reader of the conversation reaches the file through
/// *Shared with you* and the grant it holds there, not through the message
/// (SH4).
///
/// Read off the plaintext, because the verb that opens a channel message is
/// handed a body and a nonce and not the record's type. A plaintext that is a
/// manifest with a digest is a share; a member who writes text that is itself
/// such a manifest sees it open as the name it carries, which confuses only
/// their own message — filing reads the signed `type`, never this.
pub fn channel_text(plaintext: String) -> String {
    match serde_json::from_str::<Manifest>(&plaintext) {
        Ok(m) if is_digest(&m.digest) => m.name,
        _ => plaintext,
    }
}

/// SHA-256 of `bytes`, lowercase hex.
pub fn digest_of(bytes: &[u8]) -> String {
    hex::encode(
        kotton_crypto::Sha256Hasher::new()
            .hash(bytes)
            .expect("SHA-256 over a byte slice does not fail"),
    )
}

/// One range of a streamed share's bytes (RFC-0090, *Mechanism › Above the
/// frame cap*; RFC-0048 ST2–ST4).
///
/// **Sealed exactly as the manifest is.** To a person, a range travels as a
/// direct message of its own — [`crate::envelope::DmInner::range`], sealed to
/// the recipient with a fresh key and signed by the sender — and is handed over
/// the contact door as every message is, so what crosses is an ephemeral key, a
/// nonce and ciphertext, and nothing outside the seal says *share*, *range* or
/// *which*. Its fields are inside the seal: the stream it belongs to, the
/// stream's length, where it starts, and its plaintext.
///
/// **To a group, its plaintext is under the channel's key** (the ruling of
/// 2026-10-09 on RFC-0090): the range's bytes are sealed once under the epoch
/// the manifest was, and ride as that envelope's channel copy
/// ([`crate::envelope::ChannelCopy::body`]) — one ciphertext, handed to every
/// current member, as the manifest is one. This struct then carries the
/// range's place and no bytes ([`Self::bytes`] empty): the bytes are the
/// channel ciphertext's, and only a holder of the epoch's key opens them.
///
/// **Keyed by content** (ST3): the stream is named by the share's digest, so
/// the recipient's node reassembles by `(sender, digest, size, share)`, and
/// files nothing until the whole hashes to the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// The share's digest — SHA-256 of the whole plaintext, lowercase hex —
    /// which is the stream's id ([`Manifest::stream`]).
    pub digest: String,
    /// The whole plaintext's length, as the manifest declares it.
    pub size: u64,
    /// The share this range is part of, by an id every copy of its manifest
    /// shares with its ranges, so two shares of the same bytes are two streams,
    /// each filed when its own ranges are whole. To a person, the manifest's
    /// message id — the sealed ephemeral key of the envelope it came in. To a
    /// group, the nonce of the channel ciphertext the manifest is sealed in:
    /// each member's manifest comes in an envelope of its own, so its id is
    /// theirs alone, while a range is one ciphertext for every member and names
    /// the share by what every member's copy of it holds.
    pub share: String,
    /// Where in the plaintext this range starts: a multiple of [`RANGE_LEN`].
    pub offset: u64,
    /// This range's plaintext, base64 — or empty, for a range of a share to a
    /// group, whose plaintext is its envelope's channel ciphertext. Omitted
    /// when empty: a range to a person always carries bytes, so it serialises,
    /// and is signed, as it did before a group's could.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bytes: String,
}

impl Range {
    /// This range's plaintext, if it is a range a stream of its digest and size
    /// can hold ([`Self::place_holds`]) and its bytes are exactly what its
    /// place holds. Refused otherwise — what is wrong here stays wrong.
    pub fn holds(&self) -> Result<Vec<u8>, String> {
        let bytes = B64.decode(&self.bytes).map_err(|_| "its bytes are not base64".to_string())?;
        self.holds_bytes(&bytes)?;
        Ok(bytes)
    }

    /// Whether `bytes` — this range's plaintext, from wherever it rode — are
    /// what a range in this place holds: the digest is one, the size is one a
    /// stream may declare, the offset is on a [`RANGE_LEN`] boundary inside
    /// it, and the bytes are exactly as long as that boundary holds.
    pub fn holds_bytes(&self, bytes: &[u8]) -> Result<(), String> {
        if !is_digest(&self.digest) {
            return Err("its stream is not named by a digest".to_string());
        }
        if self.share.is_empty() || self.share.len() > 128 {
            return Err("it names no share it is part of".to_string());
        }
        stream_size_holds(self.size)?;
        if !self.offset.is_multiple_of(RANGE_LEN as u64) || self.offset >= self.size {
            return Err("it starts where no range of its stream starts".to_string());
        }
        let expected = (self.size - self.offset).min(RANGE_LEN as u64);
        if bytes.len() as u64 != expected {
            return Err("it does not hold the bytes its place in the stream holds".to_string());
        }
        Ok(())
    }

}

/// `bytes`, whose digest is `digest`, as the ranges of the share whose
/// manifest is the message `share`: [`RANGE_LEN`] each, the last the
/// remainder, in order.
pub fn ranges(digest: &str, share: &str, bytes: &[u8]) -> Vec<Range> {
    places(digest, share, bytes)
        .into_iter()
        .map(|(range, part)| Range { bytes: B64.encode(part), ..range })
        .collect()
}

/// `bytes` as the ranges of the share `share` with no bytes in them, each
/// beside the plaintext it is the place of — how a share to a group's ranges
/// are made, whose plaintext is sealed under the channel's key and rides as
/// the channel ciphertext, not in the range. [`RANGE_LEN`] each, in order.
pub fn places<'a>(digest: &str, share: &str, bytes: &'a [u8]) -> Vec<(Range, &'a [u8])> {
    bytes
        .chunks(RANGE_LEN)
        .enumerate()
        .map(|(i, chunk)| {
            let range = Range {
                digest: digest.to_string(),
                share: share.to_string(),
                size: bytes.len() as u64,
                offset: (i * RANGE_LEN) as u64,
                bytes: String::new(),
            };
            (range, chunk)
        })
        .collect()
}

/// How many ranges a stream of `size` bytes is.
pub fn range_count(size: u64) -> u64 {
    size.div_ceil(RANGE_LEN as u64)
}

/// Whether a stream may declare `size`: some bytes, and no more than
/// [`STREAM_MAX`].
fn stream_size_holds(size: u64) -> Result<(), String> {
    if size == 0 || size > STREAM_MAX as u64 {
        return Err(format!("it declares {size} bytes, and a share carries between one and {}", mib(STREAM_MAX as u64)));
    }
    Ok(())
}

/// Whether `s` is a SHA-256 digest as [`digest_of`] writes one.
fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A media type for `name`, from its extension; `application/octet-stream`
/// when the extension says nothing this knows.
pub fn mime_for(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "zip" => "application/zip",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}

/// What [`Plain::new`] refuses, said once, so the sender's refusal and the
/// recipient's decline name the same rule.
pub const PLAIN_RULE: &str = "a name is one plain segment: not empty, no `/` or `\\`, no control \
    character, no space at either end, not `.` or `..`, and not beginning with `.`";

/// A word that may be one segment of a path in the person's tree, exactly as it
/// was given. The only way a name becomes part of where a share lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plain(String);

impl Plain {
    /// `word`, if it is one plain segment ([`PLAIN_RULE`]); refused otherwise.
    /// Nothing is dropped, trimmed or replaced: what is accepted is what was
    /// said, and what was not is not written anywhere.
    pub fn new(word: &str) -> Result<Self, String> {
        let plain = !word.is_empty()
            && word.trim() == word
            && word != "."
            && word != ".."
            && !word.starts_with('.')
            && !word.contains(['/', '\\'])
            && !word.chars().any(char::is_control);
        if plain {
            Ok(Self(word.to_owned()))
        } else {
            Err(format!("{word:?} is not a name a share may carry — {PLAIN_RULE}"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The folder under [`SHARED_WITH_YOU`] a share from `sender_did` lands in:
/// the name the recipient's card shows for them, or — for a card with no
/// usable name — the first eight characters of their AID, as the Devices
/// screen names an unnamed device by its fingerprint (the record's default).
///
/// **A card name [`Plain`] refuses is no usable name.** It is not cleaned
/// into one, which could name another contact's folder; it is set aside, and
/// the folder is named by a value nobody chose. The share is not refused for
/// it: the card's name is this person's record of the sender, not the
/// sender's word, and a stray space in it must not cost them every share.
/// Only an AID that is itself not [`Plain`] names no folder at all.
pub fn sender_folder(card_name: Option<&str>, sender_did: &str) -> Result<Plain, String> {
    card_name
        .and_then(|name| Plain::new(name).ok())
        .map_or_else(|| Plain::new(&aid_prefix(sender_did)), Ok)
}

/// The first eight characters of `did`'s AID — how a sender with no card name
/// is named, in a folder and in a refusal.
pub fn aid_prefix(did: &str) -> String {
    did.rsplit(':').next().unwrap_or(did).chars().take(8).collect()
}

/// The folder a share from someone named `folder` lands in, relative to the
/// Personal tree's root: `Shared with you/<folder>`.
pub fn folder_path(folder: &Plain) -> String {
    format!("{SHARED_WITH_YOU}/{}", folder.as_str())
}

/// Where a share called `name` lands in `folder`, given the names the folder
/// already holds: `Shared with you/<folder>/<name>`, suffixed where `taken`
/// already holds it ([`free_name`]). Both words are [`Plain`], so this is one
/// folder below *Shared with you*, and nowhere else.
pub fn landing(folder: &Plain, name: &Plain, taken: &[String]) -> String {
    format!("{}/{}", folder_path(folder), free_name(name.as_str(), taken))
}

/// `name`, or the first of `name 2`, `name 3`, … that nothing in `taken` is
/// called — the suffix before the extension, so `photo.jpg` becomes
/// `photo 2.jpg`. The rule the shell's hand-over to a device takes for *Inbox*
/// (`kotton-shell`'s `view::free_name`), the same here for *Shared with you*:
/// a share never lands on a file the person already holds.
pub fn free_name(name: &str, taken: &[String]) -> String {
    if !taken.iter().any(|t| t == name) {
        return name.to_owned();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (2u32..)
        .map(|n| format!("{stem} {n}{ext}"))
        .find(|candidate| !taken.iter().any(|t| t == candidate))
        .expect("an unbounded range runs out of nothing")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_carries_the_file_and_checks_it() {
        let bytes = b"\x89PNG not really".to_vec();
        let m = Manifest::of_file("beach.png", &bytes, Some("Photos/beach.png".into())).unwrap();
        assert_eq!(m.kind, "file");
        assert_eq!(m.mime, "image/png");
        assert_eq!(m.size, bytes.len() as u64);
        assert_eq!(m.bytes().unwrap(), bytes);
    }

    /// The recipient's manifest is the sender's without `origin`, and its
    /// serialised form names no field that is not the record's.
    #[test]
    fn the_recipients_manifest_carries_no_origin() {
        let m = Manifest::of_file("beach.png", b"x", Some("Photos/beach.png".into())).unwrap();
        let theirs = m.for_recipient();
        assert_eq!(theirs.origin, None);
        let json = serde_json::to_value(&theirs).unwrap();
        let mut keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["digest", "inline", "kind", "mime", "name", "size"]);
        assert!(!serde_json::to_string(&theirs).unwrap().contains("Photos"));
    }

    #[test]
    fn a_share_whose_bytes_do_not_hold_files_nothing() {
        let mut m = Manifest::of_file("a.txt", b"the milk", None).unwrap();
        m.inline = Some(B64.encode(b"the eggs"));
        assert!(m.bytes().unwrap_err().contains("digest"));
        let mut m = Manifest::of_file("a.txt", b"the milk", None).unwrap();
        m.digest = digest_of(b"something else");
        assert!(m.bytes().is_err());
    }

    /// Above the inline cap a share streams: its manifest carries `stream`,
    /// which is its digest, and no `inline`; above what the store files in one
    /// piece it is refused, with a sentence that says why.
    #[test]
    fn a_file_above_the_inline_cap_streams_and_one_above_what_the_store_holds_is_refused() {
        let at = Manifest::of_file("film.mov", &vec![1u8; INLINE_MAX], None).unwrap();
        assert!(at.inline.is_some() && at.stream.is_none() && !at.is_streamed());
        let above = vec![1u8; INLINE_MAX + 1];
        let streamed = Manifest::of_file("film.mov", &above, None).unwrap();
        assert_eq!(streamed.inline, None);
        assert_eq!(streamed.stream.as_deref(), Some(digest_of(&above).as_str()));
        assert!(streamed.is_streamed() && streamed.stream_holds().is_ok());
        assert!(streamed.bytes().is_err(), "a streamed share's bytes are not inside it");

        // Zeroed, so the allocation is never touched: the refusal reads the
        // length and nothing else.
        let huge = vec![0u8; STREAM_MAX + 1];
        let why = Manifest::of_file("film.mov", &huge, None).unwrap_err();
        assert!(why.contains("at most 256.0 MiB") && why.contains("nothing was sent"), "{why}");
    }

    /// **One rule, and the node refuses by it.** A share carries up to
    /// `STREAM_MAX` to a person and to a group alike, at the bound and not a
    /// byte past it, with the sentence the manifest is refused with — so the
    /// shell, which compiles this rule from the same file and asks it of a
    /// listing's size, says exactly what the node would. Between the inline
    /// cap and that bound a group's share streams, as a person's does
    /// (`TASK-a-share-to-a-group-above-the-inline-cap-is-a-stream-to-each-member`).
    /// A size past 4 GiB is named as itself, which a `usize` on the shell's
    /// 32-bit target could not hold.
    #[test]
    fn a_share_carries_up_to_the_stream_bound_to_a_person_or_a_group_and_is_refused_past_it_with_the_nodes_sentence() {
        for to in [To::Person, To::Group] {
            assert_eq!(carries(to, STREAM_MAX as u64), Ok(()), "{to:?}");
            assert_eq!(carries(to, STREAM_MAX as u64 + 1), Err(too_large(STREAM_MAX as u64 + 1)), "{to:?}");
            assert_eq!(carries(to, GROUP_INLINE_MAX as u64 + 1), Ok(()), "{to:?}: above the inline cap it streams");
        }

        // The manifest's refusals are this rule's, word for word, for both.
        let huge = vec![0u8; STREAM_MAX + 1];
        assert_eq!(Manifest::of_file("film.mov", &huge, None).unwrap_err(), too_large(huge.len() as u64));
        assert_eq!(Manifest::of_file_for_a_group("film.mov", &huge, None).unwrap_err(), too_large(huge.len() as u64));

        // A group's manifest is inline to its cap and streams above it.
        let at = Manifest::of_file_for_a_group("film.mov", &vec![1u8; GROUP_INLINE_MAX], None).unwrap();
        assert!(at.inline.is_some() && !at.is_streamed());
        let above = vec![1u8; GROUP_INLINE_MAX + 1];
        let streamed = Manifest::of_file_for_a_group("film.mov", &above, None).unwrap();
        assert!(streamed.is_streamed() && streamed.stream_holds().is_ok());
        assert_eq!(Manifest::of_channel_body(&streamed.channel_body()), Ok(streamed.clone()), "a group's streamed manifest opens");
        let neither = Manifest { stream: None, ..streamed };
        assert!(Manifest::of_channel_body(&neither.channel_body()).is_err(), "one with no bytes anywhere does not");

        let film = 5 * 1024 * 1024 * 1024u64;
        let why = carries(To::Person, film).unwrap_err();
        assert!(why.starts_with("this file is 5120.0 MiB") && why.contains("at most 256.0 MiB"), "{why}");
    }

    /// A group's ranges carry their place and no bytes, beside the plaintext
    /// their channel ciphertext seals; together the places are a person's
    /// ranges, and each holds its own plaintext.
    #[test]
    fn a_groups_ranges_are_places_beside_the_bytes_they_seal() {
        let bytes: Vec<u8> = (0..(RANGE_LEN + 77)).map(|i| (i % 253) as u8).collect();
        let digest = digest_of(&bytes);
        let places = places(&digest, "the share", &bytes);
        let theirs = ranges(&digest, "the share", &bytes);
        assert_eq!(places.len(), theirs.len());
        for ((place, part), range) in places.iter().zip(&theirs) {
            assert!(place.bytes.is_empty(), "a group's range carries no bytes beside its ciphertext");
            assert!(!serde_json::to_string(place).unwrap().contains("bytes"), "and names no field for them");
            assert_eq!(Range { bytes: range.bytes.clone(), ..place.clone() }, *range);
            place.holds_bytes(part).unwrap();
            assert!(place.holds_bytes(&part[1..]).is_err(), "short");
        }
    }

    /// A stream's ranges are fixed boundaries: every one `RANGE_LEN` but the
    /// last, in order, and together the bytes.
    #[test]
    fn a_stream_is_ranges_on_fixed_boundaries_that_make_the_whole() {
        let bytes: Vec<u8> = (0..(2 * RANGE_LEN + 12_345)).map(|i| (i % 251) as u8).collect();
        let digest = digest_of(&bytes);
        let ranges = ranges(&digest, "the share", &bytes);
        assert_eq!(ranges.len() as u64, range_count(bytes.len() as u64));
        let mut whole = Vec::new();
        for (i, r) in ranges.iter().enumerate() {
            assert_eq!((r.offset, r.size, r.digest.as_str()), ((i * RANGE_LEN) as u64, bytes.len() as u64, digest.as_str()));
            let part = r.holds().unwrap();
            assert_eq!(part.len(), if i < 2 { RANGE_LEN } else { 12_345 });
            whole.extend(part);
        }
        assert_eq!(whole, bytes);
    }

    /// A range that is not what its place in its stream holds is refused:
    /// what is wrong stays wrong.
    #[test]
    fn a_range_off_its_boundary_or_its_length_is_refused() {
        let bytes = vec![3u8; RANGE_LEN + 10];
        let good = ranges(&digest_of(&bytes), "the share", &bytes).remove(0);
        let refused = |r: Range| r.holds().is_err();
        assert!(refused(Range { offset: 1, ..good.clone() }), "off the boundary");
        assert!(refused(Range { offset: 2 * RANGE_LEN as u64, ..good.clone() }), "past the end");
        assert!(refused(Range { bytes: B64.encode([3u8; 9]), ..good.clone() }), "short");
        assert!(refused(Range { digest: "not a digest".into(), ..good.clone() }), "no digest");
        assert!(refused(Range { size: STREAM_MAX as u64 + 1, ..good.clone() }), "too large");
        assert!(refused(Range { size: 0, ..good.clone() }), "empty");
        assert!(refused(Range { share: String::new(), ..good.clone() }), "part of no share");
        assert!(good.holds().is_ok());
    }

    /// A word somebody else chose never climbs out of *Shared with you*.
    #[test]
    fn a_share_lands_under_shared_with_you_and_nowhere_else() {
        for (folder, name) in [
            ("Bea", "beach.jpg"),
            ("../..", "../../.ssh/authorized_keys"),
            ("Bea/../../Documents", "/etc/passwd"),
            ("..\\Documents", "..\\x.txt"),
            ("Bea", ".hidden"),
        ] {
            if let (Ok(folder), Ok(name)) = (Plain::new(folder), Plain::new(name)) {
                let at = landing(&folder, &name, &[]);
                let parts: Vec<&str> = at.split('/').collect();
                assert_eq!(parts.len(), 3, "{at}");
                assert_eq!(parts[0], SHARED_WITH_YOU, "{at}");
                assert!(parts[1..].iter().all(|p| !p.is_empty() && !p.starts_with('.')), "{at}");
            }
        }
        let (bea, beach) = (Plain::new("Bea").unwrap(), Plain::new("beach.jpg").unwrap());
        assert_eq!(landing(&bea, &beach, &[]), "Shared with you/Bea/beach.jpg");
        assert_eq!(landing(&bea, &beach, &["beach.jpg".into()]), "Shared with you/Bea/beach 2.jpg");
        assert!(Plain::new("..").is_err());
        // Refused, never cleaned: each of these is a word that is not one plain
        // segment, and a guard that cleans it lands it somewhere nobody chose.
        for hostile in HOSTILE {
            assert!(Plain::new(hostile).is_err(), "{hostile:?} was accepted as a name");
            assert!(Manifest::of_file(hostile, b"x", None).is_err(), "a share named {hostile:?} was made");
            assert_eq!(
                sender_folder(Some(hostile), "did:kel:EAbcdefghijk").unwrap().as_str(),
                "EAbcdefg",
                "a card named {hostile:?} named a folder of its own"
            );
        }
        // What is accepted is exactly what was said.
        assert_eq!(Plain::new("Bob from the bakery").unwrap().as_str(), "Bob from the bakery");
    }

    /// The names the assessor traced, and the shapes the guard exists for.
    const HOSTILE: [&str; 8] = [". ..", " . . ", ". .x", "..", "a/b", "a\\b", "be\u{7}ach.jpg", ""];

    #[test]
    fn a_contact_with_no_card_name_is_named_by_their_aid() {
        assert_eq!(sender_folder(Some("Bea"), "did:kel:EAbcdefghijk").unwrap().as_str(), "Bea");
        assert_eq!(sender_folder(None, "did:kel:EAbcdefghijk").unwrap().as_str(), "EAbcdefg");
        // A card name the rule refuses is no usable name: the AID names the folder.
        for refused in ["  ", ". .x", "Bea ", ".Bea", "B/ea"] {
            assert_eq!(sender_folder(Some(refused), "did:kel:EAbcdefghijk").unwrap().as_str(), "EAbcdefg", "{refused:?}");
        }
    }
}
