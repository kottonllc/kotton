// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton contact` — the people you can message (RFC-0022, `DEC-0055`).
//!
//! ```text
//! kotton contact pair  --user <id> [--as <name>] [--wait <secs>]
//! kotton contact join  <code> --user <id> [--as <name>]
//! kotton contact list  --user <id>
//! ```
//!
//! **One way to name a contact.** Every verb that takes a contact takes them
//! as `kotton contact list` shows them, or by DID, and resolves the name here,
//! with [`resolve`]: the daemon is handed a DID and never sees a name. The DID
//! a name stood for is printed by whatever verb used it, because a name is what
//! the contact said at pairing and the DID is who they are.
//!
//! **Two humans, two confirmations, and a comparison in between.** One side
//! runs `pair` and reads three words aloud; the other runs `join` and types
//! them. Both then see the same six digits, and both answer. That is the whole
//! ceremony a person performs, and neither half can be skipped: the words keep
//! the relay from forging the meeting, and the digits are how the two people
//! check that it held (RFC-0022 CP1–CP3).
//!
//! The digits are printed on their own line, in the same grouped form the shell
//! uses, because they are read aloud and compared — by a person, or by a script
//! standing in for two of them.

use clap::Subcommand;
use kotton::KottonClient;
use kotton_wire::ipc::UserResponse;
use std::fmt;
use std::io::{self, BufRead, Write};

#[derive(Subcommand)]
pub enum ContactCommand {
    /// Start pairing: print a code to read to the other person, then wait.
    Pair {
        #[arg(long)]
        user: String,
        /// The name their screen will show for you. Defaults to your user id.
        #[arg(long = "as")]
        as_name: Option<String>,
        /// How long to wait for them, in seconds.
        #[arg(long, default_value_t = 180)]
        wait: u64,
    },
    /// Join a pairing with the code they read to you.
    Join {
        /// The three words, however you heard them.
        code: String,
        #[arg(long)]
        user: String,
        #[arg(long = "as")]
        as_name: Option<String>,
    },
    /// The people you have paired with.
    List {
        #[arg(long)]
        user: String,
    },
}

impl ContactCommand {
    fn user(&self) -> &str {
        match self {
            ContactCommand::Pair { user, .. }
            | ContactCommand::Join { user, .. }
            | ContactCommand::List { user } => user,
        }
    }

    pub async fn execute(&self) -> io::Result<()> {
        // Acting as someone: the cached session if there is one, else a
        // credential at the terminal. `connect_as` is the one place that
        // order lives (`TASK-the-cli-has-no-session-between-commands`).
        let mut client = KottonClient::connect_as(self.user()).await?;
        match self {
            ContactCommand::Pair {
                user,
                as_name,
                wait,
            } => {
                let rx = client
                    .contact_pair_start_stream(user, as_name.as_deref(), *wait)
                    .await?;
                drive(&client, user, rx).await
            }
            ContactCommand::Join {
                code,
                user,
                as_name,
            } => {
                let rx = client
                    .contact_pair_join_stream(user, code, as_name.as_deref())
                    .await?;
                drive(&client, user, rx).await
            }
            ContactCommand::List { user } => {
                let contacts = client.contact_list(user).await?;
                if contacts.is_empty() {
                    println!("No contacts yet. `kotton contact pair --user {user}` to add one.");
                    return Ok(());
                }
                for (did, label) in contacts {
                    match label {
                        Some(l) => println!("{l}  {did}"),
                        None => println!("{did}"),
                    }
                }
                Ok(())
            }
        }
    }
}

/// A contact as a verb was given them: the DID, and the name it was given by
/// if it was given a name.
///
/// Shown as `name (did)`, or the DID alone, so a verb that acts on a name says
/// which DID it acted on.
pub(super) struct Named {
    pub did: String,
    name: Option<String>,
}

impl fmt::Display for Named {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{name} ({})", self.did),
            None => f.write_str(&self.did),
        }
    }
}

/// The contact `user` means by `contact`, as [`contact_did`] reads it against
/// `user`'s contacts. Every verb that names a contact from the terminal comes
/// through here, so all of them take a name or a DID by the same rule.
///
/// A DID needs no contacts to be read, so none are fetched for one: a verb
/// given a DID asks the daemon nothing it did not ask before.
pub(super) async fn resolve(client: &mut KottonClient, user: &str, contact: &str) -> io::Result<Named> {
    let contacts = if is_did(contact) { Vec::new() } else { client.contact_list(user).await? };
    let did = contact_did(contact, &contacts).map_err(io::Error::other)?;
    Ok(Named {
        name: (did != contact).then(|| contact.to_string()),
        did: did.to_string(),
    })
}

/// The DID `name` stands for among `contacts` (`(did, label)`, as
/// `contact_list` answers): `name` itself if it is a DID; else the one contact
/// whose label is `name`; else `name`, for the daemon to take as a DID or
/// refuse.
///
/// A DID is never read as a label: a label is whatever a contact said at
/// pairing, and one that reads as somebody else's DID does not stand for them.
///
/// A label is the name a contact gave at pairing, so two contacts can give the
/// same one; then `name` is not one person, and which one is not guessed — the
/// error names every DID it could be. That is the one refusal made here, and
/// only because the daemon never sees a label to make it.
fn contact_did<'a>(name: &'a str, contacts: &'a [(String, Option<String>)]) -> Result<&'a str, String> {
    if is_did(name) {
        return Ok(name);
    }
    let named: Vec<&str> = contacts
        .iter()
        .filter(|(_, label)| label.as_deref() == Some(name))
        .map(|(did, _)| did.as_str())
        .collect();
    match named.as_slice() {
        [] => Ok(name),
        [did] => Ok(did),
        several => Err(format!(
            "{} of your contacts are named {name}; name the one you mean by DID: {}",
            several.len(),
            several.join(", ")
        )),
    }
}

/// Whether a verb was given a DID rather than a name.
fn is_did(contact: &str) -> bool {
    contact.starts_with("did:")
}

/// Follow one side of the ceremony to its end, answering the one question it
/// asks. Both sides are driven identically — in a meeting between two people
/// there is no side that only listens.
async fn drive(
    client: &KottonClient,
    user: &str,
    mut rx: tokio::sync::mpsc::Receiver<UserResponse>,
) -> io::Result<()> {
    while let Some(frame) = rx.recv().await {
        match frame {
            UserResponse::PairAdvertising { code, .. } => {
                println!("Read this to them, out loud:\n");
                println!("    {}\n", code.expose());
                println!("Waiting for them…");
            }
            UserResponse::PairConnecting => println!("Looking for them…"),
            UserResponse::PairConnected => println!("Found them."),
            UserResponse::PairShowCode {
                token,
                sas,
                peer_label,
            } => {
                let who = peer_label.as_deref().unwrap_or("they");
                println!("\nSix digits — check {who} sees the same:\n");
                println!("    {}\n", format_sas(sas));
                let matched = ask("Do they match? [y/N] ")?;
                client
                    .pair_confirm_code(user, token.expose(), matched)
                    .await
                    .map_err(|e| io::Error::other(format!("confirm: {e}")))?;
                if !matched {
                    println!("Cancelled — nothing was exchanged.");
                }
            }
            UserResponse::ContactPaired { did, label } => {
                println!("\nPaired with {label}.\n    {did}");
                return Ok(());
            }
            UserResponse::PairFailed { reason } => {
                return Err(io::Error::other(reason));
            }
            _ => {}
        }
    }
    Err(io::Error::other(
        "the ceremony ended without saying how — the daemon may have stopped",
    ))
}

/// `"472 913"` — grouped, because it is read aloud.
fn format_sas(sas: u32) -> String {
    let s = format!("{sas:06}");
    format!("{} {}", &s[..3], &s[3..])
}

fn ask(prompt: &str) -> io::Result<bool> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let a = line.trim().to_lowercase();
    Ok(a == "y" || a == "yes")
}

#[cfg(test)]
mod tests {
    use super::{contact_did, Named};

    fn contacts() -> Vec<(String, Option<String>)> {
        vec![
            ("did:kel:Esam".to_string(), Some("sam".to_string())),
            ("did:kel:Ejordan".to_string(), Some("jordan".to_string())),
            ("did:kel:Eunnamed".to_string(), None),
        ]
    }

    #[test]
    fn a_contacts_name_is_their_did() {
        assert_eq!(contact_did("sam", &contacts()), Ok("did:kel:Esam"));
    }

    #[test]
    fn a_did_is_passed_on_as_given() {
        assert_eq!(contact_did("did:kel:Eunnamed", &contacts()), Ok("did:kel:Eunnamed"));
    }

    /// A label is a contact's claim, so one shaped like somebody else's DID
    /// does not take that DID's place: the DID is who was named.
    #[test]
    fn a_did_is_never_read_as_a_label() {
        let mut posing = contacts();
        posing.push(("did:kel:Eposer".to_string(), Some("did:kel:Esam".to_string())));
        assert_eq!(contact_did("did:kel:Esam", &posing), Ok("did:kel:Esam"));
    }

    /// Not a contact's name is not refused here: whether somebody can be
    /// reached, admitted or removed is the daemon's to say, and it says so in
    /// its own words.
    #[test]
    fn a_name_no_contact_has_is_passed_on_for_the_daemon_to_answer() {
        assert_eq!(contact_did("casey", &contacts()), Ok("casey"));
    }

    #[test]
    fn a_name_two_contacts_share_is_refused_naming_both() {
        let mut both = contacts();
        both.push(("did:kel:Eothersam".to_string(), Some("sam".to_string())));
        let err = contact_did("sam", &both).expect_err("two people are named sam");
        assert!(err.contains("did:kel:Esam") && err.contains("did:kel:Eothersam"), "{err}");
    }

    /// What a verb prints for whom it acted on: the DID always, and the name
    /// beside it when it was given one.
    #[test]
    fn a_named_contact_is_shown_with_the_did_it_stood_for() {
        let named = Named { did: "did:kel:Esam".to_string(), name: Some("sam".to_string()) };
        assert_eq!(named.to_string(), "sam (did:kel:Esam)");
        let by_did = Named { did: "did:kel:Esam".to_string(), name: None };
        assert_eq!(by_did.to_string(), "did:kel:Esam");
    }
}
