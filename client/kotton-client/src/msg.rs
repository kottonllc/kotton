// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `msg` domain — direct messages and the channels a household shares.
//!
//! ```no_run
//! # async fn example(client: &mut kotton::KottonClient) -> std::io::Result<()> {
//! let mut msg = client.msg("did:key:…");
//! let inbox = msg.poll_inbox().await?;
//! # let _ = inbox;
//! # Ok(())
//! # }
//! ```
//!
//! The decrypt verbs take ciphertext the caller already holds and open it with
//! the user's keys, which is why they are verbs here rather than something a
//! reader does for themselves: the keys never leave the daemon.

use std::io;

use serde_json::Value;

use super::{KottonClient, UserRequest, UserResponse};
use kotton_wire::ipc::Delivery;

impl KottonClient {
    // -- Peer messaging (peer_messaging sprint) --------------------------------

    /// Create a new channel and generate + store its symmetric key for the creator.
    ///
    /// The daemon generates a random 32-byte channel key, wraps it for the\n    /// creator's own DID, and stores a `sh.kotton.channel.key-grant` record.
    /// Returns the record ID of the stored key-grant.
    pub async fn message_channel_create(
        &mut self,
        user_id: &str,
        channel_did: &str,
    ) -> io::Result<String> {
        let request = UserRequest::MessageChannelCreate {
            user_id: user_id.to_owned(),
            channel_did: channel_did.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::ChannelCreated { channel_did } => Ok(channel_did),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Admit a member to a channel, rotating the channel key as it does.
    ///
    /// The daemon mints a new key epoch for the current membership plus the new
    /// member, so the member's reach begins at their admission: they hold no key
    /// for what came before. Pass `backfill` to also grant the earlier epochs
    /// and hand them the history deliberately.
    ///
    /// Returns the wrapped key-grant JSON blob for the new member. A member with
    /// a local account on this daemon also has it written into their record
    /// store; a member elsewhere receives theirs by sync.
    pub async fn message_channel_grant_key(
        &mut self,
        user_id: &str,
        channel_did: &str,
        member_did: &str,
        backfill: bool,
    ) -> io::Result<serde_json::Value> {
        let request = UserRequest::MessageChannelGrantKey {
            user_id: user_id.to_owned(),
            channel_did: channel_did.to_owned(),
            member_did: member_did.to_owned(),
            backfill,
        };
        match self.client.send(&request).await? {
            UserResponse::ChannelKeyGrantCreated { grant } => Ok(grant),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Remove a member from a channel: the admission's rotation with the member
    /// omitted.
    ///
    /// The daemon mints a new key epoch for every current member but
    /// `member_did`. They keep what they already hold — the conversation while
    /// they were in — and hold no key for anything sealed after this. Who may
    /// remove is who may admit; removing yourself is refused.
    pub async fn message_channel_remove_member(
        &mut self,
        user_id: &str,
        channel_did: &str,
        member_did: &str,
    ) -> io::Result<()> {
        let request = UserRequest::MessageChannelRemoveMember {
            user_id: user_id.to_owned(),
            channel_did: channel_did.to_owned(),
            member_did: member_did.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Leave a channel: post a `leave` notice into it, then let go of every
    /// key held for it.
    ///
    /// The notice is a channel message, handed to every current member as a
    /// post is; one remaining member — the one whose DID sorts first without
    /// the leaver — rotates to an epoch that omits them, and the rest wait for
    /// it. Afterwards the channel is not among the caller's groups, and
    /// nothing sealed after opens for them; the records they hold stay where
    /// they are. Unconditional: a member nothing reaches now is a notice waiting
    /// in the outbox. Answers the notice's id and each member's delivery.
    pub async fn message_channel_leave(
        &mut self,
        user_id: &str,
        channel_did: &str,
    ) -> io::Result<(String, Vec<kotton_wire::ipc::MemberDelivery>)> {
        let request = UserRequest::MessageChannelLeave {
            user_id: user_id.to_owned(),
            channel_did: channel_did.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::ChannelSent { message_id, fanout } => Ok((message_id, fanout)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Encrypt `body` as a DM to `recipient_did` and store the ciphertext as a
    /// `sh.kotton.message.v1` record.
    ///
    /// Returns the stable record ID (`message_id`) of the stored message.
    pub async fn message_send(
        &mut self,
        user_id: &str,
        recipient_did: &str,
        body: &str,
        thread_id: Option<String>,
    ) -> io::Result<String> {
        let request = UserRequest::MessageSend {
            user_id: user_id.to_owned(),
            recipient_did: recipient_did.to_owned(),
            body: body.to_owned(),
            thread_id,
        };
        match self.client.send(&request).await? {
            UserResponse::MessageSent { message_id, .. } => Ok(message_id),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// [`Self::message_send`], with what became of the recipient's copy.
    ///
    /// A send is two facts (`DEC-0055`): the sender's copy is written whatever
    /// happens, and the other copy either reached one of the recipient's nodes
    /// or did not. A caller that shows a person their sent messages wants the
    /// first; a caller that must not imply an arrival wants the second.
    pub async fn message_send_delivery(
        &mut self,
        user_id: &str,
        recipient_did: &str,
        body: &str,
        thread_id: Option<String>,
    ) -> io::Result<(String, Option<Delivery>)> {
        let request = UserRequest::MessageSend {
            user_id: user_id.to_owned(),
            recipient_did: recipient_did.to_owned(),
            body: body.to_owned(),
            thread_id,
        };
        match self.client.send(&request).await? {
            UserResponse::MessageSent { message_id, delivery } => Ok((message_id, delivery)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// What each direct message `user_id` sent `peer_did` reads as — *sent*,
    /// *delivered* or *waiting at home* — read again after the send
    /// (`TASK-a-message-stays-in-the-outbox-until-one-of-their-devices-signs-for-it`).
    pub async fn message_deliveries(
        &mut self,
        user_id: &str,
        peer_did: &str,
    ) -> io::Result<Vec<kotton_wire::ipc::DeliveryReading>> {
        let request = UserRequest::MessageDeliveries {
            user_id: user_id.to_owned(),
            peer_did: peer_did.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::MessageDeliveries { readings } => Ok(readings),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Encrypt `body` with the channel's symmetric key, store it, and hand a
    /// copy to every current member. Returns the stable `message_id`.
    ///
    /// For what became of each member's copy, use
    /// [`Self::message_channel_send_with_fanout`].
    pub async fn message_channel_send(
        &mut self,
        user_id: &str,
        channel_did: &str,
        body: &str,
    ) -> io::Result<String> {
        Ok(self
            .message_channel_send_with_fanout(user_id, channel_did, body)
            .await?
            .0)
    }

    /// [`Self::message_channel_send`], with where each member's copy went
    /// (`DEC-0055`).
    ///
    /// One entry per current member other than the sender. A member is never a
    /// failed send: the sender's copy exists regardless, so this returns `Ok`
    /// with somebody's copy `Unreachable` rather than an error.
    pub async fn message_channel_send_with_fanout(
        &mut self,
        user_id: &str,
        channel_did: &str,
        body: &str,
    ) -> io::Result<(String, Vec<kotton_wire::ipc::MemberDelivery>)> {
        let request = UserRequest::MessageChannelSend {
            user_id: user_id.to_owned(),
            channel_did: channel_did.to_owned(),
            body: body.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::ChannelSent { message_id, fanout } => Ok((message_id, fanout)),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return up to `limit` raw (still-encrypted) `sh.kotton.message.v1` records
    /// for `channel_did`, sorted by `sent_at` descending.
    ///
    /// Records are returned still-encrypted; callers must decrypt using the
    /// channel key retrieved via `record_query` on `sh.kotton.channel.key-grant`.
    pub async fn message_channel_history(
        &mut self,
        user_id: &str,
        channel_did: &str,
        before_id: Option<String>,
        limit: u32,
    ) -> io::Result<Vec<Value>> {
        let request = UserRequest::MessageChannelHistory {
            user_id: user_id.to_owned(),
            channel_did: channel_did.to_owned(),
            before_id,
            limit,
        };
        match self.client.send(&request).await? {
            UserResponse::MessageHistory { messages } => Ok(messages),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Return the 50 most recent `sh.kotton.message.v1` records addressed to
    /// `user_id`'s DID.
    ///
    /// Records are returned still-encrypted; callers decrypt using their own
    /// identity key (via `kotton_crypto::x25519::dm_decrypt`).
    pub async fn message_poll_inbox(&mut self, user_id: &str) -> io::Result<Vec<Value>> {
        let request = UserRequest::MessagePollInbox {
            user_id: user_id.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::MessageHistory { messages } => Ok(messages),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Decrypt an encrypted DM body in-process inside the daemon.
    ///
    /// Passes the base64-encoded `body`, `nonce`, and `ephemeral_pub` to the
    /// daemon, which derives the recipient's X25519 key from their `user_id`
    /// identity key and decrypts in-process.  Returns the UTF-8 plaintext.
    pub async fn message_decrypt_dm(
        &mut self,
        user_id: &str,
        body: &str,
        nonce: &str,
        ephemeral_pub: &str,
    ) -> io::Result<String> {
        let request = UserRequest::MessageDecryptDm {
            user_id: user_id.to_owned(),
            body: body.to_owned(),
            nonce: nonce.to_owned(),
            ephemeral_pub: ephemeral_pub.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::Decrypted { plaintext } => Ok(plaintext),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }

    /// Decrypt an encrypted channel message body using the channel key grant.
    ///
    /// The daemon looks up the `sh.kotton.channel.key-grant` record for
    /// `user_id` + `channel_did`, unwraps the wrapped channel key, and decrypts
    /// `body` with it.  Returns the UTF-8 plaintext.
    pub async fn message_decrypt_channel(
        &mut self,
        user_id: &str,
        channel_did: &str,
        body: &str,
        nonce: &str,
    ) -> io::Result<String> {
        let request = UserRequest::MessageDecryptChannel {
            user_id: user_id.to_owned(),
            channel_did: channel_did.to_owned(),
            body: body.to_owned(),
            nonce: nonce.to_owned(),
        };
        match self.client.send(&request).await? {
            UserResponse::Decrypted { plaintext } => Ok(plaintext),
            UserResponse::Error { message } => Err(io::Error::other(message)),
            got => Err(crate::protocol::unexpected(got)),
        }
    }
}

/// The `msg` domain, bound to one user.
pub struct Msg<'a> {
    client: &'a mut KottonClient,
    user_id: String,
}

impl KottonClient {
    /// Enter the `msg` domain for a user.
    pub fn msg(&mut self, user_id: &str) -> Msg<'_> {
        Msg { client: self, user_id: user_id.to_string() }
    }
}

impl Msg<'_> {
    /// Create a channel. See [`KottonClient::message_channel_create`].
    pub async fn create_channel(&mut self, channel_did: &str) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.message_channel_create(&u, channel_did).await
    }

    /// Admit a member to a channel. See [`KottonClient::message_channel_grant_key`].
    pub async fn grant_channel_key(
        &mut self,
        channel_did: &str,
        member_did: &str,
        backfill: bool,
    ) -> io::Result<serde_json::Value> {
        let u = self.user_id.clone();
        self.client.message_channel_grant_key(&u, channel_did, member_did, backfill).await
    }

    /// Remove a member from a channel. See [`KottonClient::message_channel_remove_member`].
    pub async fn remove_channel_member(&mut self, channel_did: &str, member_did: &str) -> io::Result<()> {
        let u = self.user_id.clone();
        self.client.message_channel_remove_member(&u, channel_did, member_did).await
    }

    /// Leave a channel. See [`KottonClient::message_channel_leave`].
    pub async fn leave_channel(
        &mut self,
        channel_did: &str,
    ) -> io::Result<(String, Vec<kotton_wire::ipc::MemberDelivery>)> {
        let u = self.user_id.clone();
        self.client.message_channel_leave(&u, channel_did).await
    }

    /// Send a direct message. See [`KottonClient::message_send`].
    pub async fn send(
        &mut self,
        recipient_did: &str,
        body: &str,
        thread_id: Option<String>,
    ) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.message_send(&u, recipient_did, body, thread_id).await
    }

    /// Send to a channel. See [`KottonClient::message_channel_send`].
    pub async fn send_channel(&mut self, channel_did: &str, body: &str) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.message_channel_send(&u, channel_did, body).await
    }

    /// Read back a channel. See [`KottonClient::message_channel_history`].
    pub async fn channel_history(
        &mut self,
        channel_did: &str,
        before_id: Option<String>,
        limit: u32,
    ) -> io::Result<Vec<Value>> {
        let u = self.user_id.clone();
        self.client.message_channel_history(&u, channel_did, before_id, limit).await
    }

    /// Collect waiting messages. See [`KottonClient::message_poll_inbox`].
    pub async fn poll_inbox(&mut self) -> io::Result<Vec<Value>> {
        let u = self.user_id.clone();
        self.client.message_poll_inbox(&u).await
    }

    /// Open a direct message. See [`KottonClient::message_decrypt_dm`].
    pub async fn decrypt_dm(
        &mut self,
        body: &str,
        nonce: &str,
        ephemeral_pub: &str,
    ) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.message_decrypt_dm(&u, body, nonce, ephemeral_pub).await
    }

    /// Open a channel message. See [`KottonClient::message_decrypt_channel`].
    pub async fn decrypt_channel(
        &mut self,
        channel_did: &str,
        body: &str,
        nonce: &str,
    ) -> io::Result<String> {
        let u = self.user_id.clone();
        self.client.message_decrypt_channel(&u, channel_did, body, nonce).await
    }
}
