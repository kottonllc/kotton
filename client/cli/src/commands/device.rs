// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton device reset` — start this device fresh.
//!
//! Every other `device` subcommand is the REPL's, reached through
//! [`crate::bridge`], and runs inside a session against a daemon. This one is
//! not, and the difference is the whole design.
//!
//! ## Why it does not go through the daemon
//!
//! Kotton on a device is **two stores that can disagree**: the base directory
//! (`kotton_common::paths::base_dir`) and the secrets scoped to it, in the OS
//! keychain or in a file under it
//! (`kotton_secret::secrets_for_base_dir`). Nothing owned both, so "start fresh"
//! meant deleting a directory by hand and hoping the keychain agreed — and
//! `just nuke`, the only thing that tried, defaulted to the *development* base
//! dir while `just headless::run` uses the platform one. It exited zero having
//! wiped a directory the person had never written to. This verb is the missing
//! owner (`TASK-a-device-has-no-verb-to-start-fresh`, `DEC-0069` §6).
//!
//! Three consequences follow from that, and each is a rule here:
//!
//! - **It asks the product which directory.** The person never names one, so
//!   they cannot name the wrong one. `base_dir()` is the same resolver `kuserd`
//!   calls, which is what makes the answer the *install* rather than a guess at
//!   it.
//! - **It reads its listing off disk, with no key and no session.** The person
//!   reaching for a reset is often the person whose install will not start. A
//!   warning that needs a healthy daemon is absent exactly when it is needed.
//! - **It refuses while a daemon is up** rather than deleting the directory out
//!   from under one. The daemon holds open database handles; on Windows they
//!   make the delete fail, and on Unix they make it succeed and leave a running
//!   process writing into an unlinked tree, which is worse.
//!
//! ## The listing is the point, not the deletion
//!
//! An identity whose phrase was never written down is **gone** with the
//! directory. Nothing said so before the directory went, which is what the
//! record's `Security:` field names. So the listing runs first, per identity, and
//! `--yes` is refused until it has been printed.

use std::io;
use std::path::Path;

/// One identity on this device, as the disk describes it.
struct Resident {
    id: String,
    /// Recovery authorities with a sealed copy here. `0` means this identity
    /// does not survive the reset.
    authorities: usize,
}

/// Every identity with a directory under `base/users`.
///
/// The *directories* are the instrument, not `system/users.json`: a reset deletes
/// directories, so directories are what it must enumerate. A registry entry whose
/// directory is already gone has nothing left to delete, and a directory the
/// registry forgot is precisely the orphan a reset exists to clear. Reading the
/// registry instead would see the first and miss the second.
fn residents(base: &Path) -> Vec<Resident> {
    let mut found: Vec<Resident> = Vec::new();
    let Ok(entries) = std::fs::read_dir(base.join("users")) else {
        return found;
    };
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let authorities =
            kotton_identity::provisioning::recovery_authority_count(base, &id);
        found.push(Resident { id, authorities });
    }
    found.sort_by(|a, b| a.id.cmp(&b.id));
    found
}

/// Whether a `kuserd` answers at the socket this environment resolves.
///
/// Connecting is the probe rather than checking whether the socket file exists,
/// because a socket left behind by a killed daemon exists and answers nothing —
/// and refusing on that would make the verb unusable after exactly the crash
/// that makes someone want it. Bounded, so a half-dead daemon that accepts and
/// never replies cannot hang the command.
///
/// ## What it is not, stated because the obvious reading is wrong
///
/// This is **not** scoped to the base directory. `runtime_dir()`'s first two
/// tiers are `$XDG_RUNTIME_DIR/kotton` and `$TMPDIR/kotton`, and neither varies
/// with `KOTTON_BASE_DIR` — only `KUSERD_IPC_NAME` separates two daemons on one
/// machine. So the question answered here is *is a kuserd running under this
/// name*, and it can be wrong in both directions:
///
/// - **Over-refuses** when the default daemon is up and the reset targets an
///   isolated `KOTTON_BASE_DIR`. Costs a person one `just kill`.
/// - **Under-refuses** when a daemon *for this base dir* was started under a
///   different `KUSERD_IPC_NAME` than this process resolves. The reset then
///   proceeds under a live daemon.
///
/// The case it does catch is the one that matters and the one that is common:
/// resetting the install you are currently running. Making it exact needs a
/// marker in the base directory that a daemon holds while it is alive, which
/// does not exist today and is a change to `kuserd` rather than to this command.
async fn daemon_is_up() -> bool {
    let probe = kotton::KottonClient::connect();
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(3), probe).await,
        Ok(Ok(_))
    )
}

/// `reset`'s one word: the confirmation it refuses to delete without. `reset` is this door's
/// alone (the shell does not run it), so its word is spelled here, where [`reset`] reads it,
/// and the argument help for `device` prints it after the shell's grammar.
pub const YES_WORD: &str = "--yes";

/// `kotton device reset [--yes]`.
pub async fn reset(args: &[String]) -> io::Result<()> {
    let confirmed = args.iter().any(|a| a == YES_WORD);

    let base = kotton_common::paths::base_dir().map_err(|e| {
        io::Error::other(format!("cannot work out where Kotton keeps this device: {e}"))
    })?;

    if !base.exists() {
        println!("Nothing to reset — this device has no Kotton directory.");
        println!("  looked in: {}", base.display());
        return Ok(());
    }

    let residents = residents(&base);

    println!("This device: {}", base.display());
    println!();

    if residents.is_empty() {
        println!("  No identities. The directory holds device-level state only.");
    } else {
        for r in &residents {
            match r.authorities {
                0 => println!(
                    "  {:<16} recovery phrase: NONE — this identity does not come back",
                    r.id
                ),
                1 => println!("  {:<16} recovery phrase: set up on this device", r.id),
                n => println!(
                    "  {:<16} recovery phrase: {n} set up on this device",
                    r.id
                ),
            }
        }
    }
    println!();

    // Stated rather than silently omitted. Which nodes hold each identity's
    // sealed copy lives in `system/agent.db`'s `paired_nodes`, and reading it
    // means linking the peer daemon's storage into this thin client — a client
    // taking a daemon's reach for one line of a listing. Recovery needs the
    // authority *and* the locator, so the gap is real and it is named:
    // `TASK-a-device-reset-does-not-say-where-the-sealed-copies-went`.
    println!("  Where each identity's sealed copies went is NOT listed here.");
    println!("  Recovery needs the phrase and the node to ask. Run `peer list` and");
    println!("  keep its output before you reset, if you do not already have the card");
    println!("  `id add-recovery` printed.");
    println!();

    // Probed on both paths, not just under `--yes`. Learning that a daemon is in
    // the way *after* deciding to go ahead is a second round trip for a fact that
    // was knowable during the first.
    let daemon_up = daemon_is_up().await;

    println!("This will delete:");
    println!("  - {}", base.display());
    println!("  - this install's secrets (identity keys, CEK, FROST shares,");
    println!("    and this device's operational and operator keys)");
    println!();
    println!("It does NOT reach a node that keeps for you. A vault still holding your");
    println!("chain and a sealed copy will admit a device that proves the phrase,");
    println!("whether or not this one was reset — that is the product working.");
    println!();

    if daemon_up {
        println!("A Kotton daemon is running for this device. Stop it before resetting:");
        println!("Ctrl-C in the terminal running it, or `just kill`. Deleting the");
        println!("directory under a live daemon leaves it writing into a tree that is");
        println!("no longer there.");
        println!();
    }

    if !confirmed {
        println!("Refusing without {YES_WORD}. Re-run as: kotton device reset {YES_WORD}");
        // Exit rather than returning an `io::Error`: this is a refusal the person
        // asked for by not passing `--yes`, and it has already said everything it
        // has to say. Returning would print a second, uglier copy through
        // `main`'s `Debug` formatting. `std::process::exit` is what `bridge` uses
        // for the same reason, and stdout is flushed first because it is block-
        // buffered when this is piped.
        let _ = io::Write::flush(&mut io::stdout());
        std::process::exit(1);
    }

    if daemon_up {
        let _ = io::Write::flush(&mut io::stdout());
        std::process::exit(1);
    }

    // The directory first, then the keychain — the order `logout_user` already
    // uses. Both half-states are bad, and this is the one that fails safe: a
    // directory that would not go leaves the keychain intact behind it, so the
    // install still opens. The reverse would leave data nothing can unseal.
    kotton_common::fs::remove_dir_all_retrying(&base).map_err(|e| {
        io::Error::other(format!(
            "could not delete {}: {e}\n  \
             Close anything reading it (an editor, a file manager, a running daemon) \
             and run this again. Its secrets kept outside the directory were not touched.",
            base.display()
        ))
    })?;

    // Scoped to this base dir, which is what makes the deletion match the
    // directory just removed: `OsSecrets::for_base_dir` keeps the default
    // install on the legacy `"Kotton"` service and gives any other base dir
    // `"Kotton@<path>"`. A throwaway store resolves the same way and the purge
    // is a no-op it can absorb. A file-backed store (`KOTTON_SECRETS=file`)
    // kept its entries in `system/secrets.json`, inside the directory just
    // removed, so they are already gone; its delete of a label it does not
    // hold writes nothing (`FileSecrets::delete_secret`), so the purge does not
    // bring the directory back.
    let secrets = kotton_secret::secrets_for_base_dir(&base).map_err(io::Error::other)?;
    for r in &residents {
        kotton_identity::provisioning::delete_all_user_secrets(secrets.as_ref(), &r.id);
    }
    kotton_identity::provisioning::delete_all_device_secrets(secrets.as_ref());

    println!("Reset. {} is gone, with its secrets.", base.display());
    println!("`kotton` starts a new device from nothing.");
    Ok(())
}
