// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton vfs` — raw VFS file operations.
//!
//! ```text
//! kotton vfs write <path> <content> [--user <id>]
//! kotton vfs read  <path>            [--user <id>]
//! kotton vfs ls    [<prefix>]        [--user <id>]
//! kotton vfs rm    <path>            [--user <id>]
//!
//! No store is named: the node places a path per the user's
//! `storage-mounts.toml` (RFC-0058).
//! ```

use clap::Subcommand;
use kotton::KottonClient;
use std::io;

#[derive(Subcommand)]
pub enum VfsCommand {
    /// Write a UTF-8 string to a file.
    ///
    /// Creates or overwrites the file.
    Write {
        /// File path (e.g. "/notes/hello.txt")
        path: String,
        /// File content (UTF-8 string)
        content: String,
        /// User ID to act on
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Read a file and print it to stdout.
    Read {
        /// File path (e.g. "/notes/hello.txt")
        path: String,
        /// User ID to act on
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// List files under an optional prefix.
    #[command(name = "ls")]
    List {
        /// Path prefix to filter by (default: list all)
        #[arg(default_value = "")]
        prefix: String,
        /// User ID to act on
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Delete a file from a storage mount.
    #[command(name = "rm")]
    Delete {
        /// File path within the mount
        path: String,
        /// User ID to act on
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Show files that have another version waiting from a concurrent edit.
    ///
    /// Replication keeps the losing write instead of destroying it (RFC-0071
    /// R3). This is where you find out one exists.
    Conflicts {
        /// User ID to act on
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Settle a conflict, releasing the version kept for it.
    Resolve {
        /// File path (e.g. "/notes/hello.txt")
        path: String,
        /// Content id of the retained version to keep. Omit to keep the current
        /// one. `kotton vfs conflicts` lists them.
        #[arg(long)]
        keep: Option<String>,
        /// User ID to act on
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
    /// Erase a file and its entire history.
    ///
    /// Unlike `delete`, nothing brings this back: it removes the record, not
    /// just the current version. Local only.
    Purge {
        /// File path (e.g. "/notes/hello.txt")
        path: String,
        /// Required. Erasing history is not recoverable.
        #[arg(long)]
        yes: bool,
        /// User ID to act on
        #[arg(long, env = "KOTTON_USER")]
        user: String,
    },
}

impl VfsCommand {
    pub async fn execute(&self) -> io::Result<()> {
        let user = match self {
            VfsCommand::Write { user, .. } => user,
            VfsCommand::Read { user, .. } => user,
            VfsCommand::List { user, .. } => user,
            VfsCommand::Delete { user, .. } => user,
            VfsCommand::Conflicts { user, .. } => user,
            VfsCommand::Resolve { user, .. } => user,
            VfsCommand::Purge { user, .. } => user,
        };
        let mut client = KottonClient::connect_as(user).await?;

        match self {
            VfsCommand::Write {
                path,
                content,
                user,
            } => {
                client.fs(user).write(path, content.as_bytes()).await?;
                println!("wrote {} bytes to {path}", content.len());
            }

            VfsCommand::Read {
                path, user } => {
                let data = client.fs(user).read(path).await?;
                let s = String::from_utf8(data)
                    .map_err(|_| io::Error::other("file contains non-UTF-8 data"))?;
                print!("{s}");
            }

            VfsCommand::List {
                prefix,
                user,
            } => {
                let files = client.fs(user).list(prefix).await?;
                if files.is_empty() {
                    println!("(empty)");
                } else {
                    for f in &files {
                        println!("{f}");
                    }
                }
            }

            VfsCommand::Delete {
                path, user } => {
                client.fs(user).delete(path).await?;
                println!("deleted {path}");
            }
            VfsCommand::Conflicts { user } => {
                let conflicts = client.fs(user).conflicts().await?;
                if conflicts.is_empty() {
                    println!("no conflicts");
                } else {
                    for (path, ids) in conflicts {
                        println!("{path}");
                        for id in ids {
                            println!("  kept: {id}");
                        }
                    }
                }
            }
            VfsCommand::Resolve { path, keep, user } => {
                client.fs(user).resolve(path, keep.as_deref()).await?;
                match keep {
                    Some(id) => println!("resolved {path}, kept {id}"),
                    None => println!("resolved {path}, kept the current version"),
                }
            }
            VfsCommand::Purge { path, yes, user } => {
                if !yes {
                    return Err(std::io::Error::other(format!(
                        "purge erases {path} and its entire history, and cannot be undone;                          pass --yes to confirm"
                    )));
                }
                client.fs(user).purge(path).await?;
                println!("purged {path} and its history");
            }
        }
        Ok(())
    }
}
