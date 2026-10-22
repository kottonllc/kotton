// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton message` — direct messages and channels (RFC-0007).
//!
//! ```text
//! kotton message send <contact> <body>        --user <id> [--thread <id>]
//! kotton message inbox                        --user <id>
//! kotton message channel new <channel-id>     --user <id>
//! kotton message channel send <channel-id> <body> --user <id>
//! kotton message channel read <channel-id>    --user <id> [--limit <n>]
//! kotton message channel admit <channel-id> <contact> --user <id>
//! kotton message channel remove <channel-id> <contact> --user <id>
//! kotton message channel leave <channel-id>   --user <id>
//! ```
//!
//! **Decryption happens here, on the client.** The daemon stores and returns
//! ciphertext only — it never holds a plaintext body — so reading an inbox is a
//! two-step dance: fetch the records, then ask the daemon to decrypt each one
//! with the user's key. That is the design working, not an inconvenience, and
//! it is why this command exists rather than the daemon returning readable text.
//!
//! A contact is named here as everywhere in the terminal: as `kotton contact
//! list` shows them, or by DID, resolved by `contact::resolve`, and the DID it
//! stood for is printed.

use super::contact;
use clap::Subcommand;
use kotton::KottonClient;
use serde_json::Value;
use std::io;

#[derive(Subcommand)]
pub enum MessageCommand {
    /// Send a direct message to a contact.
    ///
    /// Name them as `kotton contact list` shows them, or by DID; the DID it
    /// went to is printed. The recipient must be someone you have paired with,
    /// or yourself — their public key has to be known locally to encrypt for
    /// them — and somebody else is refused, in the daemon's words.
    Send {
        /// A contact's name, as `kotton contact list` shows it, or their DID.
        contact: String,
        /// Message text.
        body: String,
        #[arg(long)]
        user: String,
        /// Group this message into an existing conversation.
        #[arg(long)]
        thread: Option<String>,
    },
    /// Show your inbox, decrypted.
    Inbox {
        #[arg(long)]
        user: String,
    },
    /// Channel sub-commands.
    #[command(subcommand)]
    Channel(ChannelCommand),
}

#[derive(Subcommand)]
pub enum ChannelCommand {
    /// Create a channel and grant yourself its key.
    New {
        /// Identifier for the channel — you choose it.
        channel_id: String,
        #[arg(long)]
        user: String,
    },
    /// Send a message to a channel you hold the key for.
    Send {
        channel_id: String,
        body: String,
        #[arg(long)]
        user: String,
    },
    /// Read a channel's history, decrypted.
    Read {
        channel_id: String,
        #[arg(long)]
        user: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Admit a contact to a channel you hold the key for.
    ///
    /// The channel moves to its next key, granted to everyone in it and to
    /// them: they read from here on, not what was said before. Name them as
    /// `kotton contact list` shows them, or by DID. Somebody you hold no key
    /// for is refused, and the refusal is the daemon's, as it said it.
    Admit {
        channel_id: String,
        /// A contact's name, as `kotton contact list` shows it, or their DID.
        contact: String,
        #[arg(long)]
        user: String,
    },
    /// Remove a member from a channel you hold the key for.
    ///
    /// The channel moves to its next key, granted to everyone in it but them:
    /// what is said from here on does not open for them. What they were in for
    /// stays theirs to read. Name them as `kotton contact list` shows them, or
    /// by DID. Yourself, or somebody who is not in the channel, is refused, and
    /// the refusal is the daemon's, as it said it.
    Remove {
        channel_id: String,
        /// A contact's name, as `kotton contact list` shows it, or their DID.
        contact: String,
        #[arg(long)]
        user: String,
    },
    /// Leave a channel: tell its members, then let go of its keys.
    ///
    /// Nothing said in it after this opens for you. Files shared with you
    /// stay yours; the conversation's text stays in your store and no longer
    /// opens, since its keys are gone.
    Leave {
        channel_id: String,
        #[arg(long)]
        user: String,
    },
}

impl MessageCommand {
    pub async fn execute(&self) -> io::Result<()> {
        // Reading and writing your own messages is acting as you: the cached
        // session, or a credential at the terminal (`connect_as`).
        let mut client = KottonClient::connect_as(self.user()).await?;

        match self {
            MessageCommand::Send {
                contact,
                body,
                user,
                thread,
            } => {
                let recipient = contact::resolve(&mut client, user, contact).await?;
                // `message_send_delivery`, not `message_send`: the second
                // answers only a record id, and the whole of `DEC-0056` is that
                // a sender is owed **one word** about where their message got
                // to. Without it this printed "Sent", which is true of every
                // send including the ones that arrived nowhere.
                let (id, delivery) = client
                    .message_send_delivery(user, &recipient.did, body, thread.clone())
                    .await?;
                match delivery {
                    Some(d) => println!("{} ({id})", d.word()),
                    // A send that answered without a delivery is not a send that
                    // failed, and it is not one that arrived either. Nothing is
                    // claimed rather than a word being guessed at.
                    None => println!("Sent ({id})"),
                }
                // The word stays the first line, alone: it is what a sender is
                // owed, and what a script reads.
                println!("to {recipient}");
                Ok(())
            }

            MessageCommand::Inbox { user } => {
                let inbox = client.message_poll_inbox(user).await?;
                if inbox.is_empty() {
                    println!("No messages.");
                    return Ok(());
                }
                for msg in &inbox {
                    let from = str_field(msg, "from_did").unwrap_or("unknown");
                    let text = match decrypt_dm(&mut client, user, msg).await {
                        Ok(t) => t,
                        // A message that will not open is worth showing as such
                        // rather than hiding: the usual cause is a contact who
                        // rotated their key, which the user can act on.
                        Err(e) => format!("<could not decrypt: {e}>"),
                    };
                    println!("from {}:\n  {text}", short(from));
                }
                Ok(())
            }

            MessageCommand::Channel(cmd) => cmd.execute(&mut client).await,
        }
    }
}

impl MessageCommand {
    /// Whose messages this command is about.
    fn user(&self) -> &str {
        match self {
            MessageCommand::Send { user, .. } | MessageCommand::Inbox { user } => user,
            MessageCommand::Channel(c) => c.user(),
        }
    }
}

impl ChannelCommand {
    fn user(&self) -> &str {
        match self {
            ChannelCommand::New { user, .. }
            | ChannelCommand::Send { user, .. }
            | ChannelCommand::Read { user, .. }
            | ChannelCommand::Admit { user, .. }
            | ChannelCommand::Remove { user, .. }
            | ChannelCommand::Leave { user, .. } => user,
        }
    }

    async fn execute(&self, client: &mut KottonClient) -> io::Result<()> {
        match self {
            ChannelCommand::New { channel_id, user } => {
                let created = client.message_channel_create(user, channel_id).await?;
                println!("Created channel {created}");
                Ok(())
            }
            ChannelCommand::Send {
                channel_id,
                body,
                user,
            } => {
                client.message_channel_send(user, channel_id, body).await?;
                println!("Sent to {channel_id}");
                Ok(())
            }
            ChannelCommand::Read {
                channel_id,
                user,
                limit,
            } => {
                let history = client
                    .message_channel_history(user, channel_id, None, *limit)
                    .await?;
                if history.is_empty() {
                    println!("No messages in {channel_id}.");
                    return Ok(());
                }
                for msg in &history {
                    let from = str_field(msg, "from_did").unwrap_or("unknown");
                    // A leave notice says it in its type; its body is empty.
                    if str_field(msg, "type") == Some("leave") {
                        println!("{} left the channel", short(from));
                        continue;
                    }
                    let text = match decrypt_channel(client, user, channel_id, msg).await {
                        Ok(t) => t,
                        Err(e) => format!("<could not decrypt: {e}>"),
                    };
                    println!("from {}:\n  {text}", short(from));
                }
                Ok(())
            }
            ChannelCommand::Admit {
                channel_id,
                contact,
                user,
            } => {
                // The name is resolved here because only here is it a name: the
                // daemon is handed a DID and decides everything else — who may
                // admit, and whether it holds a key for them. Its refusal is the
                // answer, passed on as it said it.
                let whom = contact::resolve(client, user, contact).await?;
                let grant = client
                    .message_channel_grant_key(user, channel_id, &whom.did, false)
                    .await?;
                match grant.get("epoch").and_then(Value::as_u64) {
                    Some(epoch) => println!("Admitted {whom} to {channel_id} at epoch {epoch}"),
                    None => println!("Admitted {whom} to {channel_id}"),
                }
                Ok(())
            }
            ChannelCommand::Remove {
                channel_id,
                contact,
                user,
            } => {
                // Resolved as `admit` resolves it, and for the same reason: the
                // daemon is handed a DID and decides the rest — who may remove,
                // and whether that DID is in the channel. Its refusal is the
                // answer, passed on as it said it.
                let whom = contact::resolve(client, user, contact).await?;
                client
                    .message_channel_remove_member(user, channel_id, &whom.did)
                    .await?;
                println!("Removed {whom} from {channel_id}");
                Ok(())
            }
            ChannelCommand::Leave { channel_id, user } => {
                let (_id, fanout) = client.message_channel_leave(user, channel_id).await?;
                println!("Left {channel_id}");
                for member in &fanout {
                    println!("  {}: {}", short(&member.member_did), member.delivery.word());
                }
                Ok(())
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn str_field<'a>(msg: &'a Value, key: &str) -> Option<&'a str> {
    msg.get(key).and_then(|v| v.as_str())
}

fn require<'a>(msg: &'a Value, key: &str) -> io::Result<&'a str> {
    str_field(msg, key).ok_or_else(|| io::Error::other(format!("message record missing `{key}`")))
}

async fn decrypt_dm(client: &mut KottonClient, user: &str, msg: &Value) -> io::Result<String> {
    client
        .message_decrypt_dm(
            user,
            require(msg, "body")?,
            require(msg, "nonce")?,
            require(msg, "ephemeral_pub")?,
        )
        .await
}

async fn decrypt_channel(
    client: &mut KottonClient,
    user: &str,
    channel_id: &str,
    msg: &Value,
) -> io::Result<String> {
    client
        .message_decrypt_channel(
            user,
            channel_id,
            require(msg, "body")?,
            require(msg, "nonce")?,
        )
        .await
}

/// Abbreviate a DID for display — the full string is unreadable in a list, and
/// the tail is the distinguishing part.
fn short(did: &str) -> String {
    if did.len() <= 24 {
        return did.to_string();
    }
    format!("{}…{}", &did[..12], &did[did.len() - 8..])
}
