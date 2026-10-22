// SPDX-License-Identifier: AGPL-3.0-or-later
//! `docs-present-check`: the documents a reader is sent to say what is true, not what
//! happened, and name no governance record.
//!
//! The record set and its machinery are gone from the tree; `git log` is the archive. A page
//! that names a record (`RFC-…`, `DEC-…`, `TASK-…`, `IDEA-…`) or links into `governance/`
//! sends a reader to something that is not there, and a page that narrates a date
//! (*Measured 2026-…*, *since 2026-…*, a bare ISO date) is a page whose truth is a claim
//! about a day rather than about the code. A sweep is true the day it is done; this keeps it
//! true.
//!
//! **What it reads, for every rule.** Every `.md`, `.css`, `.html` and `.py` file under
//! `docs/`, `ui/` and `papers/`, and every `*.md` at the root.
//!
//! **And the app contract, for every rule** ([`CONTRACT`]): every `.wit` file in
//! `guest/sdk/kotton-app/wit/`, one level. Its comments are the prose an app author reads to
//! learn what each import is and what links it, so a record cited there sends them to nothing
//! and a date narrated there is a claim about a day, exactly as on a page. Every line is read:
//! the WIT around the comments is kebab-case names and types, which hold no record stem and
//! no date. Nothing date-shaped in the contract is a value, so nothing is excepted; a
//! timestamp format is named as *RFC 3339*, which is the IETF's spelling and not a record's.
//!
//! **What it reads for record names only** ([`NAMES_ONLY`]): the files a contributor meets
//! beside the documents — the root `Justfile`, `Cargo.toml`, `.gitignore`, `.env.example` and
//! `docker-compose.yml`, every `.github/workflows/*.yml`, every `.github/*.md` and every
//! `just/*.just`. Their comments are where a citation of a deleted record hides longest; their
//! dates are often versions and pins, so the date rules do not read them.
//!
//! **What it reads in string literals, for every rule** ([`RUST_TREES`]): every `.rs` file
//! under `xtask/src/`, which holds the lines `cargo xtask` prints — a gate's refusal, a tool's
//! hint, a file it writes. A gate's message is the sentence a contributor reads at the moment
//! it fails: a retired record cited there sends them to nothing, and a date narrated there is
//! a claim about a day, as on a page. It is read with `host-word-check`'s literal reader
//! ([`crate::host_word_check::string_literals`]), so an identifier is not read and the line
//! named is the literal's own.
//!
//! **What it reads in comments, for every rule** ([`COMMENT_TREES`]): every `.rs` file under
//! the trees `host-word-check` reads — `xtask/src/`, the shell, the CLI, the window, the relay
//! and every crate under `core/` but `kuid`, by its `src/` and its `tests/` — in its `//`,
//! `///`, `//!` and `/* */` comments. A comment is what the next contributor reads to learn
//! what the code is for, so a record cited there sends them to nothing and a date narrated
//! there is a claim about a day, as on a page. It is read with the same lexer as the literals
//! ([`crate::host_word_check::comments`]), so a `//` inside a string starts nothing and the
//! line named is the comment's own. The record rules and the date rules are the ones a literal
//! is read by, and a [`DATED_FIXTURES`] file's test modules are skipped for dates in its
//! comments as in its literals.
//!
//! The comments are swept in stages, and [`COMMENTS_NOT_READ`] names every file not swept yet.
//! A path joins the list only as a line in the diff, where a reviewer sees it, and
//! [`UNSWEPT_FILES`] beside it stops the list growing in length unnoticed: the check refuses the
//! two when they disagree. The check refuses a listed file that no longer needs listing, a
//! listed path that is not a `.rs` file under the trees, and an unlisted file that cites. The
//! count does not catch a swap — one file taken off and another put on in the same change — so
//! that is held by review alone.
//!
//! A literal also holds a test's fixtures, and a fixture that copies what a tool writes holds
//! that tool's timestamp. Every one under `xtask/src/` sits in a `#[cfg(test)] mod` block of a
//! file that also prints, so the exception is named by file in [`DATED_FIXTURES`] and narrowed
//! to those blocks ([`test_modules`]): the date rules skip a named file's test modules and read
//! the rest of it, every other `#[cfg(test)]` item included, and the record rules read all of
//! it. A date in any other test is refused until its file is named, with the reason.
//!
//! **What it does not read:**
//!
//! - `ISSUES.md`, which is transient (the issues to open when the repository goes public,
//!   deleted when they are), and `DCO.md`, which is a verbatim copy of someone else's text;
//!   `LICENSE` and `NOTICES` are not read;
//! - the drawings under `ui/ink/` (`*.html`), whose words are what a screen shows: a date on
//!   a drawn phone is a sample date, and the records app's drawings draw records;
//! - the files in [`NOT_READ`], literals and comments alike: this check's own tests, which
//!   plant record names and dates to hold that each is refused. A file whose subject is a
//!   record name joins it, with the reason, when its comments are swept; and, for dates
//!   only, the `#[cfg(test)] mod` blocks of the files in [`DATED_FIXTURES`];
//! - the comments of the files in [`COMMENTS_NOT_READ`], until each is swept; their literals
//!   are read as every other file's are.
//!
//! The ISO-date rule reads prose: a fenced code block in Markdown is skipped for dates
//! (it is a command or its output), never for record names or `governance/` links.
//!
//! It exits 1 naming the file and line of each finding, so the first is first.

use std::path::{Path, PathBuf};

/// Root Markdown that is not read: transient, or someone else's words.
const ROOT_EXCEPTED: &[&str] = &["ISSUES.md", "DCO.md"];

/// The directories read, recursively.
const TREES: &[&str] = &["docs", "ui", "papers"];

/// Files beside the documents, read for record names only: a root file by name, or a directory
/// and the extension of the files in it that are read (one level, not recursive).
pub const NAMES_ONLY: &[(&str, &str)] = &[
    ("Justfile", ""),
    ("Cargo.toml", ""),
    (".gitignore", ""),
    (".env.example", ""),
    ("docker-compose.yml", ""),
    (".github/workflows", "yml"),
    (".github", "md"),
    ("just", "just"),
];

/// Every file [`NAMES_ONLY`] names that exists, relative to `root`, sorted.
pub fn names_only_files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for (path, ext) in NAMES_ONLY {
        if ext.is_empty() {
            if root.join(path).is_file() {
                out.push(path.to_string());
            }
            continue;
        }
        let Ok(entries) = std::fs::read_dir(root.join(path)) else { continue };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path().is_file() && name.rsplit_once('.').is_some_and(|(_, x)| x == *ext) {
                out.push(format!("{path}/{name}"));
            }
        }
    }
    out.sort();
    out
}

/// Trees whose `.rs` files are read, in their string literals only, for every rule: the lines
/// `cargo xtask` prints, which a person reads as a gate's refusal or a tool's hint.
const RUST_TREES: &[&str] = &["xtask/src"];

/// Files under [`RUST_TREES`] or [`COMMENT_TREES`] whose literals or comments carry a record
/// name or a date as the subject, not as a citation or a claim. Neither is read in them.
pub const NOT_READ: &[&str] = &[
    // This check's own tests, which plant record names and dates to hold that each is refused.
    "xtask/src/docs_present_check.rs",
];

/// Trees whose `.rs` files are read in their comments, for every rule: the trees
/// `host-word-check` reads in their literals, so a crate is read for both or for neither.
pub const COMMENT_TREES: &[&str] = crate::host_word_check::RUST_TREES;

/// How many paths [`COMMENTS_NOT_READ`] holds. The check refuses a list whose length is not
/// this, so the list does not grow in length unnoticed; a stage that sweeps files lowers it by
/// as many. It does not catch a swap: one path off and another on leaves the length as it was.
pub const UNSWEPT_FILES: usize = 314;

/// Files under [`COMMENT_TREES`] whose comments still cite a record or narrate a date, and are
/// not read in them until they are swept. A path joins the list only as a line in the diff,
/// where a reviewer sees it, and [`UNSWEPT_FILES`] beside it stops the list growing in length
/// unnoticed. A file here whose comments no longer need listing is refused until it is taken
/// off, a path here that is not a `.rs` file under the trees is refused, and a file not here
/// that cites is refused. A swap — one path off, another on — keeps the count, and only review
/// catches it. Their literals are read as every other file's are.
pub const COMMENTS_NOT_READ: &[&str] = &[
    "client/cli/src/active_identity.rs",
    "client/cli/src/bridge.rs",
    "client/cli/src/commands/config.rs",
    "client/cli/src/commands/contact.rs",
    "client/cli/src/commands/device.rs",
    "client/cli/src/commands/extension.rs",
    "client/cli/src/commands/id.rs",
    "client/cli/src/commands/import.rs",
    "client/cli/src/commands/message.rs",
    "client/cli/src/commands/mod.rs",
    "client/cli/src/commands/model.rs",
    "client/cli/src/commands/net.rs",
    "client/cli/src/commands/records.rs",
    "client/cli/src/commands/vfs.rs",
    "client/cli/src/commands/whoami.rs",
    "client/cli/src/kctl.rs",
    "client/shell/src/commands/app.rs",
    "client/shell/src/commands/device.rs",
    "client/shell/src/commands/door.rs",
    "client/shell/src/commands/id.rs",
    "client/shell/src/commands/operated.rs",
    "client/shell/src/commands/peer.rs",
    "client/shell/src/commands/relay.rs",
    "client/shell/src/commands/whoami.rs",
    "client/shell/src/executor.rs",
    "client/shell/src/host.rs",
    "client/shell/src/state.rs",
    "core/app/src/daemon/apps.rs",
    "core/app/src/daemon/db/app_registry_db.rs",
    "core/app/src/daemon/db/mod.rs",
    "core/app/src/daemon/handlers_registry.rs",
    "core/app/src/daemon/mod.rs",
    "core/app/src/extension_host.rs",
    "core/app/src/extension_install.rs",
    "core/app/src/fetch_session.rs",
    "core/app/src/lib.rs",
    "core/app/src/provision.rs",
    "core/app/src/quarantine.rs",
    "core/common/src/base32.rs",
    "core/common/src/crypto.rs",
    "core/common/src/fs.rs",
    "core/common/src/lib.rs",
    "core/common/src/namespace.rs",
    "core/common/src/paths.rs",
    "core/common/src/time.rs",
    "core/context/src/lib.rs",
    "core/crypto/src/delivery_ack.rs",
    "core/crypto/src/key_health.rs",
    "core/crypto/src/lib.rs",
    "core/crypto/src/provider/cek_recovery.rs",
    "core/crypto/src/provider/daily_credential.rs",
    "core/crypto/src/provider/frost.rs",
    "core/crypto/src/provider/kdf.rs",
    "core/crypto/src/provider/kel_verify.rs",
    "core/crypto/src/provider/mod.rs",
    "core/crypto/src/provider/pair_handle.rs",
    "core/crypto/src/provider/path_blind.rs",
    "core/crypto/src/provider/pin_wrap.rs",
    "core/crypto/src/provider/recovery.rs",
    "core/crypto/src/provider/suite.rs",
    "core/crypto/src/provider/vault.rs",
    "core/crypto/src/provider/warm_key.rs",
    "core/crypto/src/provider/x25519.rs",
    "core/crypto/src/reach_note.rs",
    "core/diag/src/lib.rs",
    "core/diag/src/service/event.rs",
    "core/fs/src/lib.rs",
    "core/fs/src/provider/memory.rs",
    "core/fs/src/provider/os.rs",
    "core/fs/src/runtime/mod.rs",
    "core/grant/src/daemon/db/grant_db.rs",
    "core/grant/src/daemon/db/mod.rs",
    "core/grant/src/daemon/db/schema_grants_db.rs",
    "core/grant/src/daemon/grants.rs",
    "core/grant/src/daemon/membership.rs",
    "core/grant/src/daemon/mod.rs",
    "core/grant/src/daemon/schema_grants.rs",
    "core/grant/src/ephemeral.rs",
    "core/grant/src/lib.rs",
    "core/identity/src/host.rs",
    "core/identity/src/kel_store.rs",
    "core/identity/src/lib.rs",
    "core/identity/src/provisioning.rs",
    "core/identity/src/recovery.rs",
    "core/identity/src/retired_keys.rs",
    "core/infer/src/backend.rs",
    "core/infer/src/context.rs",
    "core/infer/src/ipc.rs",
    "core/infer/src/lib.rs",
    "core/infer/src/manifest.rs",
    "core/infer/src/stub.rs",
    "core/ipc/src/lib.rs",
    "core/ipc/src/provider/acceptor.rs",
    "core/ipc/src/provider/inherited.rs",
    "core/ipc/src/provider/log_capture.rs",
    "core/ipc/src/provider/memory.rs",
    "core/ipc/src/provider/mod.rs",
    "core/ipc/src/provider/os.rs",
    "core/ipc/src/provider/test_peer.rs",
    "core/kdeviced/src/db/operators_db.rs",
    "core/kdeviced/src/lib.rs",
    "core/kdeviced/src/system.rs",
    "core/khttpd/src/main.rs",
    "core/kinferd/src/main.rs",
    "core/kquicd/src/main.rs",
    "core/ksyncd/src/main.rs",
    "core/kvaultd/src/carry.rs",
    "core/kvaultd/src/control.rs",
    "core/kvaultd/src/doors.rs",
    "core/kvaultd/src/instance.rs",
    "core/kvaultd/src/lib.rs",
    "core/kvaultd/src/main.rs",
    "core/kvaultd/src/meter.rs",
    "core/kvaultd/src/operator.rs",
    "core/kvaultd/src/peer.rs",
    "core/kvaultd/src/reach.rs",
    "core/kvaultd/src/residency.rs",
    "core/kvaultd/src/settings.rs",
    "core/kvaultd/src/shelf.rs",
    "core/kvaultd/src/tenancy.rs",
    "core/kvaultd/tests/a_vault_is_created_with_its_operator.rs",
    "core/kvaultd/tests/a_verb_finds_the_installed_vault.rs",
    "core/kvaultd/tests/an_install_creates_the_vault_for_its_key.rs",
    "core/kvaultd/tests/the_vault_reads_its_settings_as_the_installer_and_systemd_do.rs",
    "core/msg/src/daemon/delivery.rs",
    "core/msg/src/daemon/filing.rs",
    "core/msg/src/daemon/messages.rs",
    "core/msg/src/daemon/mod.rs",
    "core/msg/src/daemon/outbox.rs",
    "core/msg/src/daemon/stream.rs",
    "core/msg/src/envelope.rs",
    "core/msg/src/lib.rs",
    "core/msg/src/read_marks.rs",
    "core/msg/src/share.rs",
    "core/msg/src/share/bounds.rs",
    "core/net/src/lib.rs",
    "core/net/src/provider/advertise.rs",
    "core/net/src/provider/discovery/mdns.rs",
    "core/net/src/provider/rendezvous/admission.rs",
    "core/net/src/provider/rendezvous/identity.rs",
    "core/net/src/provider/transport/quic/introduced.rs",
    "core/net/src/provider/transport/quic/knocked.rs",
    "core/net/src/provider/transport/quic/mod.rs",
    "core/net/src/provider/transport/quic/tls.rs",
    "core/net/src/provider/transport/relayed.rs",
    "core/org/src/daemon/db/mod.rs",
    "core/org/src/daemon/frost_orgs.rs",
    "core/org/src/daemon/mod.rs",
    "core/org/src/daemon/orgs.rs",
    "core/org/src/enrollment.rs",
    "core/org/src/frost_signing.rs",
    "core/org/src/lib.rs",
    "core/outbound/src/lib.rs",
    "core/outbound/src/policy.rs",
    "core/outbound/src/provider/mod.rs",
    "core/pair/src/browser.rs",
    "core/pair/src/channel.rs",
    "core/pair/src/handshake.rs",
    "core/pair/src/lib.rs",
    "core/pair/src/pake.rs",
    "core/pair/src/wire.rs",
    "core/proc/src/lib.rs",
    "core/proc/src/provider/sandbox/linux.rs",
    "core/proc/src/provider/sandbox/unsupported.rs",
    "core/proc/src/provider/sandbox/windows.rs",
    "core/proc/src/sandbox.rs",
    "core/proc/tests/sandbox.rs",
    "core/record/src/daemon/db/mod.rs",
    "core/record/src/daemon/import.rs",
    "core/record/src/daemon/mod.rs",
    "core/record/src/daemon/records.rs",
    "core/record/src/ics.rs",
    "core/record/src/import_cmds.rs",
    "core/record/src/lib.rs",
    "core/record/src/open.rs",
    "core/record/src/provider/record_store.rs",
    "core/record/src/provider/sqlite_record_store.rs",
    "core/record/src/record_cmds.rs",
    "core/record/src/registry.rs",
    "core/record/src/replication.rs",
    "core/record/src/roots.rs",
    "core/record/src/schema_cmds.rs",
    "core/schemas/src/app_manifest.rs",
    "core/schemas/src/capability.rs",
    "core/schemas/src/core.rs",
    "core/schemas/src/extension_manifest.rs",
    "core/schemas/src/field.rs",
    "core/schemas/src/membership.rs",
    "core/sealed/src/lib.rs",
    "core/sealed/src/runtime/mod.rs",
    "core/secret/src/lib.rs",
    "core/secret/src/provider/file.rs",
    "core/secret/src/provider/mod.rs",
    "core/secret/src/provider/sealed_custody.rs",
    "core/secret/src/provider/secure_enclave_binding.rs",
    "core/secret/src/provider/tpm_binding.rs",
    "core/session/src/lib.rs",
    "core/session/src/lock_policy.rs",
    "core/session/src/service/tokens.rs",
    "core/surface/src/commands.rs",
    "core/surface/src/lib.rs",
    "core/sync/src/engine.rs",
    "core/sync/src/host.rs",
    "core/sys/src/crypto/suite.rs",
    "core/sys/src/lib.rs",
    "core/sys/src/outbound.rs",
    "core/sys/src/secret/mod.rs",
    "core/sys/src/store/mod.rs",
    "core/time/src/lib.rs",
    "core/time/src/provider/os.rs",
    "core/wasm/src/auth_port.rs",
    "core/wasm/src/contact_port.rs",
    "core/wasm/src/device_port.rs",
    "core/wasm/src/error.rs",
    "core/wasm/src/extension.rs",
    "core/wasm/src/fetch_port.rs",
    "core/wasm/src/file_port.rs",
    "core/wasm/src/grant_check.rs",
    "core/wasm/src/grant_port.rs",
    "core/wasm/src/host_channel.rs",
    "core/wasm/src/infer_port.rs",
    "core/wasm/src/limits.rs",
    "core/wasm/src/message_port.rs",
    "core/wasm/src/operators_port.rs",
    "core/wasm/src/record_port.rs",
    "core/wasm/src/runner.rs",
    "core/wasm/src/sandbox.rs",
    "core/wasm/src/surface_port.rs",
    "core/wire/src/grant.rs",
    "core/wire/src/ipc/browser_inner.rs",
    "core/wire/src/ipc/contact_request.rs",
    "core/wire/src/ipc/request.rs",
    "core/wire/src/ipc/response.rs",
    "core/wire/src/ipc/types.rs",
    "core/wire/src/ipc/vault_request.rs",
    "core/wire/src/kel.rs",
    "core/wire/src/kuid_ipc.rs",
    "core/wire/src/line.rs",
    "core/wire/src/peer.rs",
    "core/wire/src/remote.rs",
    "core/wire/src/rendezvous.rs",
    "core/wire/src/runner.rs",
    "core/wire/src/surface.rs",
    "core/wire/src/sys_ipc.rs",
    "guest/apps/kotton-shell/logic/src/commands/mod.rs",
    "guest/apps/kotton-shell/logic/src/components/ask.rs",
    "guest/apps/kotton-shell/logic/src/components/dock.rs",
    "guest/apps/kotton-shell/logic/src/components/frame.rs",
    "guest/apps/kotton-shell/logic/src/components/gallery.rs",
    "guest/apps/kotton-shell/logic/src/components/glyph.rs",
    "guest/apps/kotton-shell/logic/src/components/lock.rs",
    "guest/apps/kotton-shell/logic/src/components/menubar.rs",
    "guest/apps/kotton-shell/logic/src/components/mod.rs",
    "guest/apps/kotton-shell/logic/src/components/notice.rs",
    "guest/apps/kotton-shell/logic/src/components/overlays/calendar.rs",
    "guest/apps/kotton-shell/logic/src/components/overlays/contacts.rs",
    "guest/apps/kotton-shell/logic/src/components/overlays/files.rs",
    "guest/apps/kotton-shell/logic/src/components/overlays/messages.rs",
    "guest/apps/kotton-shell/logic/src/components/overlays/settings.rs",
    "guest/apps/kotton-shell/logic/src/components/overlays/settings_raster.rs",
    "guest/apps/kotton-shell/logic/src/components/pairing.rs",
    "guest/apps/kotton-shell/logic/src/components/phone.rs",
    "guest/apps/kotton-shell/logic/src/components/phone_home.rs",
    "guest/apps/kotton-shell/logic/src/components/welcome.rs",
    "guest/apps/kotton-shell/logic/src/engine.rs",
    "guest/apps/kotton-shell/logic/src/lib.rs",
    "guest/apps/kotton-shell/logic/src/state.rs",
    "guest/apps/kotton-shell/logic/src/view.rs",
    "infra/relay/src/admission.rs",
    "infra/relay/src/circuit.rs",
    "infra/relay/src/identity.rs",
    "infra/relay/src/identity_tests.rs",
    "infra/relay/src/instance.rs",
    "infra/relay/src/instance_tests.rs",
    "infra/relay/src/main.rs",
    "infra/relay/src/operator_file_tests.rs",
    "infra/relay/src/rule_tests.rs",
    "infra/relay/src/server.rs",
    "infra/relay/src/stun.rs",
    "infra/relay/tests/an_install_tells_the_relay_its_address.rs",
    "infra/relay/tests/common/settings_corpus.rs",
    "infra/relay/tests/common/systemd_parser_cfg.rs",
    "infra/relay/tests/common/systemds_parser.rs",
    "xtask/src/actions_check.rs",
    "xtask/src/channel_check.rs",
    "xtask/src/compose_file_tests.rs",
    "xtask/src/config_key_check.rs",
    "xtask/src/contrast_check.rs",
    "xtask/src/doctor.rs",
    "xtask/src/infer_check.rs",
    "xtask/src/license_check.rs",
    "xtask/src/main.rs",
    "xtask/src/out.rs",
    "xtask/src/port_check.rs",
    "xtask/src/reclaim.rs",
    "xtask/src/relay_address_check.rs",
    "xtask/src/release.rs",
    "xtask/src/release_server.rs",
    "xtask/src/remote_request.rs",
    "xtask/src/request_domains.rs",
    "xtask/src/residency_check.rs",
    "xtask/src/rg.rs",
    "xtask/src/runbook_check.rs",
    "xtask/src/scope_check.rs",
    "xtask/src/seed.rs",
    "xtask/src/shot.rs",
    "xtask/src/signoff_check.rs",
    "xtask/src/token_block_check.rs",
    "xtask/src/tree.rs",
    "xtask/src/windows_check.rs",
    "xtask/src/wire_check.rs",
    "xtask/src/workspace_hack.rs",
    "xtask/src/worktrees.rs",
    "xtask/src/wx_check.rs",
];

/// Files under [`RUST_TREES`] whose test modules hand a test a date-shaped value: the timestamp
/// a real tool writes, copied so the code under test reads what it will meet. The date rules
/// skip those modules ([`test_modules`]) and read the rest of the file, which prints.
pub const DATED_FIXTURES: &[&str] = &[
    // `the_recipe_reads_the_lines_the_daemon_writes` hands the matcher a `tracing` line,
    // timestamp and all, because the matcher sees the formatting and not the bare message.
    "xtask/src/main.rs",
    // `a_link_or_a_device_is_refused_whatever_its_name` reads `tar -tv` listings, whose every
    // entry carries the date and time `tar` prints.
    "xtask/src/release.rs",
    // The C-library report's test passes the time of the comparison, which the report prints.
    "xtask/src/release_server.rs",
];

/// The `#[cfg(test)] mod <name> {` blocks of Rust source, as 1-based inclusive line ranges, and
/// nothing else: a `#[cfg(test)]` function, constant, field or `mod name;` is not one, and is
/// read in full.
///
/// A block runs from the attribute, past any doc comments and attributes after it, through a
/// line that is `mod <name> {` at the attribute's own indentation, to its close: the first line
/// after it that is not blank and is indented no deeper than the attribute. When that line is
/// not `}` at the attribute's indentation (the block was closed at another indentation, or a
/// multi-line string reaches that column), the block is not skipped and is read in full; a
/// string line that is `}` at that column ends the skip there, and the rest is read. So it errs
/// toward reading more, unless an item after the module is indented deeper than the module
/// itself, which no formatter writes.
pub fn test_modules(src: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let indent_of = |l: &str| l.len() - l.trim_start().len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() != "#[cfg(test)]" {
            i += 1;
            continue;
        }
        let indent = &lines[i][..indent_of(lines[i])];
        let mut head = i + 1;
        while lines.get(head).is_some_and(|l| {
            let t = l.trim_start();
            t.starts_with("#[") || t.starts_with("///")
        }) {
            head += 1;
        }
        let is_module = lines.get(head).and_then(|l| l.strip_prefix(indent)).is_some_and(|l| {
            l.strip_prefix("mod ")
                .and_then(|l| l.strip_suffix(" {"))
                .is_some_and(|name| !name.is_empty() && name.chars().all(is_word))
        });
        if !is_module {
            i += 1;
            continue;
        }
        let close = (head + 1..lines.len())
            .find(|&k| !lines[k].trim().is_empty() && indent_of(lines[k]) <= indent.len());
        match close {
            Some(k) if lines[k].trim_end().strip_prefix(indent) == Some("}") => {
                out.push((i + 1, k + 1));
                i = k + 1;
            }
            _ => i = head + 1,
        }
    }
    out
}

/// Every `.rs` file under [`RUST_TREES`] but [`NOT_READ`], relative to `root`, sorted.
pub fn rust_files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for tree in RUST_TREES {
        let mut found = Vec::new();
        walk(&root.join(tree), &mut found);
        for p in found {
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            if rel.ends_with(".rs") && !NOT_READ.contains(&rel.as_str()) {
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

/// Every `.rs` file under [`COMMENT_TREES`] but [`NOT_READ`], relative to `root`, sorted: the
/// files whose comments are read, and the files [`COMMENTS_NOT_READ`] may name.
pub fn comment_files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for tree in COMMENT_TREES {
        let mut found = Vec::new();
        walk(&root.join(tree), &mut found);
        for p in found {
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            if rel.ends_with(".rs") && !NOT_READ.contains(&rel.as_str()) {
                out.push(rel);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// What one Rust file's comments carry, as `line: what`, read for every rule: the date rules
/// skip the test modules of a file in [`DATED_FIXTURES`], as they do for its literals.
fn comment_findings(rel: &str, text: &str) -> Vec<(usize, String)> {
    let fixtures = if DATED_FIXTURES.contains(&rel) { test_modules(text) } else { Vec::new() };
    let mut out = Vec::new();
    for (start, note) in crate::host_word_check::comments(text) {
        for (i, line) in note.lines().enumerate() {
            let n = start + i;
            let fixture = fixtures.iter().any(|&(from, to)| (from..=to).contains(&n));
            if let Some(what) = finding(line, fixture) {
                out.push((n, what));
            }
        }
    }
    out
}

/// The app contract: directories whose `.wit` files are read for every rule, one level.
pub const CONTRACT: &[&str] = &["guest/sdk/kotton-app/wit"];

/// Every `.wit` file directly in a [`CONTRACT`] directory, relative to `root`, sorted.
pub fn contract_files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for dir in CONTRACT {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else { continue };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path().is_file() && name.ends_with(".wit") {
                out.push(format!("{dir}/{name}"));
            }
        }
    }
    out.sort();
    out
}

/// The extensions read under [`TREES`].
const EXTENSIONS: &[&str] = &["md", "css", "html", "py"];

/// The record kinds whose names a page may not carry.
const KINDS: &[&str] = &["RFC-", "DEC-", "TASK-", "IDEA-"];

/// Phrases that narrate a day.
const NARRATION: &[&str] = &["Written 20", "Measured 20", "Updated 20", "Indexed 20", "since 20"];

pub fn run(root: &Path) {
    let found = findings(root);
    if found.is_empty() {
        let wit = contract_files(root).len();
        println!(
            "docs-present-check: OK — {} files under docs/, ui/, papers/ and the root, {wit} .wit file{} of the app contract, the string literals of {} .rs files under xtask/src and the comments of {} .rs files under the trees host-word-check reads ({} more not yet swept) name no record and narrate no date, and {} beside them name no record",
            files(root).len(),
            if wit == 1 { "" } else { "s" },
            rust_files(root).len(),
            comment_files(root).len() - COMMENTS_NOT_READ.len(),
            COMMENTS_NOT_READ.len(),
            names_only_files(root).len()
        );
        return;
    }
    for f in &found {
        eprintln!("{f}");
    }
    eprintln!(
        "\ndocs-present-check: {} finding(s). A page says what is true; `git log` says when. \
         Say the claim in words, or drop the citation.",
        found.len()
    );
    std::process::exit(1);
}

/// Every file the check reads, relative to `root`, with `/` separators.
pub fn files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for tree in TREES {
        let mut found = Vec::new();
        walk(&root.join(tree), &mut found);
        for p in found {
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            let ext = rel.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
            if !EXTENSIONS.contains(&ext) {
                continue;
            }
            if rel.starts_with("ui/ink/") && ext == "html" {
                continue;
            }
            out.push(rel);
        }
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".md") && e.path().is_file() && !ROOT_EXCEPTED.contains(&name.as_str()) {
                out.push(name);
            }
        }
    }
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// `file:line: what` for every finding, in file order.
pub fn findings(root: &Path) -> Vec<String> {
    findings_in(root, COMMENTS_NOT_READ, UNSWEPT_FILES)
}

/// [`findings`], with `unswept` in the place of [`COMMENTS_NOT_READ`] and `count` in the
/// place of [`UNSWEPT_FILES`].
fn findings_in(root: &Path, unswept: &[&str], count: usize) -> Vec<String> {
    let mut out = Vec::new();
    if unswept.len() != count {
        out.push(format!(
            "xtask/src/docs_present_check.rs: COMMENTS_NOT_READ holds {} path(s) and UNSWEPT_FILES says {count}; \
             a path is added to the list only with the count beside it, and a swept file comes off both",
            unswept.len()
        ));
    }
    for rel in files(root) {
        let Ok(text) = std::fs::read_to_string(root.join(&rel)) else { continue };
        let markdown = rel.ends_with(".md");
        let mut fenced = false;
        for (i, line) in text.lines().enumerate() {
            if markdown && line.trim_start().starts_with("```") {
                fenced = !fenced;
                continue;
            }
            if let Some(what) = finding(line, fenced) {
                out.push(format!("{rel}:{}: {what}", i + 1));
            }
        }
    }
    for rel in contract_files(root) {
        let Ok(text) = std::fs::read_to_string(root.join(&rel)) else { continue };
        for (i, line) in text.lines().enumerate() {
            if let Some(what) = finding(line, false) {
                out.push(format!("{rel}:{}: {what}", i + 1));
            }
        }
    }
    for rel in names_only_files(root) {
        let Ok(text) = std::fs::read_to_string(root.join(&rel)) else { continue };
        for (i, line) in text.lines().enumerate() {
            if let Some(stem) = record_stem(line) {
                out.push(format!("{rel}:{}: names the record `{stem}`", i + 1));
            }
        }
    }
    for rel in rust_files(root) {
        let Ok(text) = std::fs::read_to_string(root.join(&rel)) else { continue };
        let fixtures = if DATED_FIXTURES.contains(&rel.as_str()) { test_modules(&text) } else { Vec::new() };
        for (start, lit) in crate::host_word_check::string_literals(&text) {
            for (i, line) in lit.lines().enumerate() {
                let n = start + i;
                let fixture = fixtures.iter().any(|&(from, to)| (from..=to).contains(&n));
                if let Some(what) = finding(line, fixture) {
                    out.push(format!("{rel}:{n}: {what}"));
                }
            }
        }
    }
    let read = comment_files(root);
    for rel in &read {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else { continue };
        let found = comment_findings(rel, &text);
        if unswept.contains(&rel.as_str()) {
            if found.is_empty() {
                out.push(format!(
                    "{rel}: its comments name no record and narrate no date, so it comes off COMMENTS_NOT_READ"
                ));
            }
            continue;
        }
        for (n, what) in found {
            out.push(format!("{rel}:{n}: {what}"));
        }
    }
    for rel in unswept {
        if !read.iter().any(|r| r == rel) {
            out.push(format!("{rel}: on COMMENTS_NOT_READ, and not a .rs file whose comments the check reads"));
        }
    }
    out
}

/// What is wrong with one line, if anything. `in_code` skips the date rules only: a fenced
/// block's command or output, or a named file's test fixture.
pub fn finding(line: &str, in_code: bool) -> Option<String> {
    if line.contains("governance/") {
        return Some("a path into governance/, which is not in the tree".into());
    }
    if let Some(stem) = record_stem(line) {
        return Some(format!("names the record `{stem}`"));
    }
    if in_code {
        return None;
    }
    for phrase in NARRATION {
        let mut from = 0;
        while let Some(at) = line[from..].find(phrase) {
            let at = from + at;
            from = at + phrase.len();
            // `20` is the phrase's own tail; the year is it and the two digits after.
            let year = &line[at + phrase.len() - 2..];
            let dated = starts_with_year(year) && (*phrase != "since 20" || year.as_bytes().get(4) == Some(&b'-'));
            if dated {
                return Some(format!("narrates a date (`{}{}`)", phrase, &year[2..4]));
            }
        }
    }
    if let Some(date) = iso_date(line) {
        return Some(format!("narrates a date (`{date}`)"));
    }
    None
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The first record name of a kind, on a word boundary, in one of three forms:
///
/// - the kind and a name: `RFC-`, `DEC-`, `TASK-` or `IDEA-` followed by a digit or a
///   lower-case letter (`RFC-0084`, `TASK-a-b`);
/// - the bare kind, its hyphen with no name after it (*a `DEC-`*, *an `RFC-…`*), which cites
///   the record set as surely as a number does;
/// - the kind's word, a space and a number (`DEC 85`, `TASK 12`). For `RFC` only a number
///   with a leading zero (`RFC 0084`): the IETF's are spelled `RFC 3339`, and are not records.
///
/// And `RFC` as a word of its own, with no hyphen and no number after it (*an RFC*, *the
/// RFC*): that is the record set cited by its kind, since the IETF's are always cited by
/// number. A capital after the hyphen (`IDEA-Tracker`) is not a record's shape, and is not
/// read.
pub fn record_stem(line: &str) -> Option<String> {
    for kind in KINDS {
        let mut from = 0;
        while let Some(at) = line[from..].find(kind) {
            let start = from + at;
            from = start + kind.len();
            if line[..start].chars().next_back().is_some_and(is_word) {
                continue;
            }
            match line[from..].chars().next() {
                Some(c) if c.is_ascii_digit() || c.is_ascii_lowercase() => {
                    let end = line[start..]
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                        .map_or(line.len(), |n| start + n);
                    return Some(line[start..end].to_owned());
                }
                Some(c) if c.is_ascii_alphanumeric() => {}
                _ => return Some((*kind).to_owned()),
            }
        }
        let word = &kind[..kind.len() - 1];
        let mut from = 0;
        while let Some(at) = line[from..].find(word) {
            let start = from + at;
            from = start + word.len();
            if line[..start].chars().next_back().is_some_and(is_word) {
                continue;
            }
            let Some(number) = line[from..].strip_prefix(' ') else { continue };
            let digits = number.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 || number[digits..].chars().next().is_some_and(is_word) {
                continue;
            }
            if word == "RFC" && !number.starts_with('0') {
                continue;
            }
            return Some(line[start..from + 1 + digits].to_owned());
        }
    }
    let mut from = 0;
    while let Some(at) = line[from..].find("RFC") {
        let start = from + at;
        from = start + 3;
        if line[..start].chars().next_back().is_some_and(is_word) {
            continue;
        }
        let rest = &line[from..];
        let cited = rest.strip_prefix(' ').is_some_and(|n| n.starts_with(|c: char| c.is_ascii_digit()));
        if rest.starts_with(|c: char| is_word(c) || c == '-') || cited {
            continue;
        }
        return Some("RFC".to_owned());
    }
    None
}

/// `20yy` at the start of `s`.
fn starts_with_year(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 4 && b[0] == b'2' && b[1] == b'0' && b[2].is_ascii_digit() && b[3].is_ascii_digit()
}

/// The first `20yy-mm-dd` on a word boundary.
pub fn iso_date(line: &str) -> Option<&str> {
    let b = line.as_bytes();
    if b.len() < 10 {
        return None;
    }
    for i in 0..=b.len() - 10 {
        let w = &b[i..i + 10];
        let digits = [0, 1, 2, 3, 5, 6, 8, 9].iter().all(|&k| w[k].is_ascii_digit());
        if !(digits && w[0] == b'2' && w[1] == b'0' && w[4] == b'-' && w[7] == b'-') {
            continue;
        }
        let before = i.checked_sub(1).map(|k| b[k] as char);
        let after = b.get(i + 10).map(|&c| c as char);
        if before.is_some_and(is_word) || after.is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        return line.get(i..i + 10);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The findings in a tree built for one test, with nothing listed as not yet swept: the
    /// real list names files a test's tree does not hold. The list itself is held by
    /// [`the_unswept_list_and_its_count_agree`].
    fn findings(root: &Path) -> Vec<String> {
        findings_in(root, &[], 0)
    }

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    const CLEAN: &[(&str, &str)] = &[
        ("README.md", "# Kotton\n\nYour things, kept somewhere that is yours.\n"),
        ("docs/README.md", "# docs\n\nFour ways in.\n"),
        ("docs/use/first-hour.md", "Run `kotton id create`.\n\n```\nCreated 2026-10-12\n```\n"),
        ("docs/design/decisions/README.md", "A decision is a numbered file: 0001-the-relay.md.\n"),
        ("ui/tokens.css", "/* The ground is warm. */\n:root { --color-bg: #111; }\n"),
        ("papers/README.md", "Why the project exists.\n"),
    ];

    #[test]
    fn a_clean_tree_passes() {
        let dir = tree(CLEAN);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
        assert_eq!(files(dir.path()).len(), CLEAN.len());
    }

    /// Each form the check refuses, planted alone in an otherwise clean tree, is named by
    /// file and line.
    #[test]
    fn each_form_is_refused_by_file_and_line() {
        let planted: &[(&str, &str, &str)] = &[
            ("docs/use/linux.md", "See [the ruling](../../governance/records/DEC-0085-x.md).", "governance/"),
            ("docs/README.md", "The tree is `governance/` no longer.", "governance/"),
            ("README.md", "Identity (RFC-0075) is self-issued.", "`RFC-0075`"),
            ("CONTRIBUTING.md", "As DEC-0091 says.", "`DEC-0091`"),
            ("papers/README.md", "Filed as TASK-the-papers-are-long.", "`TASK-the-papers-are-long`"),
            ("ui/README.md", "An IDEA-tracker-app note.", "`IDEA-tracker-app`"),
            ("docs/use/macos.md", "Written 2026-09-17 on a laptop.", "Written 2026"),
            ("ui/tokens.css", "/* Measured 2026-09-20 against the ground. */", "Measured 2026"),
            ("docs/use/wsl2.md", "Updated 2026-09-26.", "Updated 2026"),
            ("papers/ownership-thesis.md", "Indexed 2026-08-01.", "Indexed 2026"),
            ("SECURITY.md", "Published since 2026-09-30.", "since 2026"),
            ("docs/use/the-window.md", "The dock moved on 2026-09-21, and the bar with it.", "2026-09-21"),
        ];
        for (path, line, says) in planted {
            let mut files: Vec<(&str, String)> = CLEAN.iter().map(|(p, t)| (*p, t.to_string())).collect();
            match files.iter_mut().find(|(p, _)| p == path) {
                Some((_, t)) => t.push_str(&format!("\n{line}\n")),
                None => files.push((path, format!("# Page\n\n{line}\n"))),
            }
            let borrowed: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
            let dir = tree(&borrowed);
            let found = findings(dir.path());
            assert_eq!(found.len(), 1, "{path}: {line:?} gave {found:?}");
            assert!(found[0].starts_with(&format!("{path}:")), "{found:?}");
            assert!(found[0].contains(says), "{path}: {line:?} gave {found:?}, wanted {says:?}");
        }
    }

    /// The drawings, `ISSUES.md` and `DCO.md` are not read, and a date in a fenced block is a
    /// command's output, not narration — but a record name in one is still a record name.
    /// Nothing under `papers/` is excepted.
    #[test]
    fn the_exceptions_are_exactly_the_named_ones() {
        let dir = tree(&[
            ("ui/ink/Records.dc.html", "<span>RFC-0088 · 2026-09-23</span>"),
            ("ISSUES.md", "Scanned since 2026-09-30, from TASK-scan-history."),
            ("DCO.md", "Developer Certificate of Origin 2004-2006"),
            ("docs/use/first-hour.md", "```\nsynced 2026-10-12 10:00\n```\n"),
        ]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());

        let dir = tree(&[("docs/use/first-hour.md", "```\nkotton show RFC-0084\n```\n")]);
        assert_eq!(findings(dir.path()).len(), 1);
        for paper in ["papers/README.md", "papers/01-property.md", "papers/federalist-map.md"] {
            let dir = tree(&[(paper, "As DEC-0001 rules.")]);
            assert_eq!(findings(dir.path()).len(), 1, "{paper} is not read");
        }
        let dir = tree(&[("ui/README.md", "drawn 2026-09-23")]);
        assert_eq!(findings(dir.path()).len(), 1, "ui/'s own README is read");
    }

    /// **The files beside the documents are read for record names, and only for them.** A
    /// record planted in a recipe's comment, a workflow's comment or a manifest's comment is
    /// named by file and line; a date or a version there is not narration.
    #[test]
    fn the_files_beside_the_documents_are_read_for_record_names() {
        for (path, line) in [
            ("Justfile", "# the gate DEC-0062 asked for"),
            ("just/desktop.just", "# Paste the three lines it prints into RFC-0018."),
            (".github/workflows/release.yml", "# What it must never become (workflows/gates.md, TASK-ci)."),
            (".github/copilot-instructions.md", "core/ # domain-first (RFC-0080)"),
            ("Cargo.toml", "# filed as IDEA-a-thing"),
            (".gitignore", "# (DEC-0032)"),
            (".env.example", "# see TASK-x-y"),
            ("docker-compose.yml", "# RFC-0083"),
        ] {
            let dir = tree(&[(path, &format!("ok\n{line}\n"))]);
            let found = findings(dir.path());
            assert_eq!(found.len(), 1, "{path}: {found:?}");
            assert!(found[0].starts_with(&format!("{path}:2: names the record")), "{found:?}");
        }
        let dir = tree(&[
            ("Justfile", "# measured 2026-09-20 on the host, since 2026-09-21\n"),
            (".github/workflows/release.yml", "#   actions/checkout v4.4.0, resolved 2026-09-29\n"),
            ("just/nested/deep.just", "# RFC-0001, one level only\n"),
            ("tools/Justfile", "# RFC-0001, root only\n"),
        ]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
    }

    /// **The app contract is read for every rule, as a page is.** A record name and a narrated
    /// date planted in a `.wit` comment are each refused by file and line; a `.wit` outside the
    /// contract's directory, or below it, is not read.
    #[test]
    fn the_app_contract_is_read_for_records_and_dates() {
        let wit = "guest/sdk/kotton-app/wit/kotton-app.wit";
        let clean = "// SPDX-License-Identifier: Apache-2.0\npackage kotton:app;\n\n/// Linked for every app.\ninterface system {\n  /// An RFC 3339 timestamp.\n  now: func() -> string;\n}\n";
        let dir = tree(&[(wit, clean)]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
        assert_eq!(contract_files(dir.path()), vec![wit.to_string()]);

        for (line, says) in [
            ("  /// The layers only the designated app may draw (RFC-0087).", "names the record `RFC-0087`"),
            ("  /// `set-title` was removed on 2026-09-22.", "narrates a date (`2026-09-22`)"),
            ("  /// Linked since 2026-08-26 for the shell.", "narrates a date (`since 2026`)"),
            ("  /// See `TASK-the-launch-export-is-called-by-nothing`.", "names the record `TASK-the-launch-export-is-called-by-nothing`"),
        ] {
            let text = format!("{clean}{line}\n");
            let dir = tree(&[(wit, &text)]);
            assert_eq!(findings(dir.path()), vec![format!("{wit}:9: {says}")], "{line:?}");
        }

        let dir = tree(&[
            ("guest/sdk/kotton-app/wit/deps/wasi.wit", "/// RFC-0001, 2026-09-22\n"),
            ("guest/sdk/other/wit/x.wit", "/// RFC-0001, 2026-09-22\n"),
            ("guest/sdk/kotton-app/wit/notes.txt", "RFC-0001, 2026-09-22\n"),
        ]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
    }

    /// **xtask's printed lines are read for record names.** A record planted in a string
    /// literal under `xtask/src/` is refused by file and by the line it is on, a multi-line
    /// literal included; one in a function's name is not read, a literal outside `xtask/src/`
    /// is not, and neither is this file, whose tests plant them.
    #[test]
    fn xtask_literals_are_read_for_record_names() {
        let planted = "fn main() {\n    eprintln!(\n        \"blindness-check: refused.\\n\\\n         See RFC-0001 for why.\"\n    );\n}\n";
        let dir = tree(&[("xtask/src/main.rs", planted)]);
        assert_eq!(findings(dir.path()), vec!["xtask/src/main.rs:4: names the record `RFC-0001`".to_string()]);

        let dir = tree(&[("xtask/src/gate.rs", "fn f() {\n    let s = \"ok\";\n    eprintln!(\"see TASK-a-b\");\n}\n")]);
        assert_eq!(findings(dir.path()), vec!["xtask/src/gate.rs:3: names the record `TASK-a-b`".to_string()]);

        let dir = tree(&[
            ("xtask/src/gate.rs", "// No record in a comment.\nfn rfc_0001() {}\n"),
            ("xtask/src/docs_present_check.rs", "const X: &str = \"RFC-0001\";\n"),
            ("xtask/src/notes.md", "RFC-0001\n"),
            ("core/store/src/lib.rs", "const X: &str = \"RFC-0001\";\n"),
        ]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
        assert_eq!(rust_files(dir.path()), vec!["xtask/src/gate.rs".to_string()]);
    }

    #[test]
    fn a_stem_needs_a_boundary_and_a_name_after_it() {
        assert_eq!(record_stem("see RFC-0084."), Some("RFC-0084".into()));
        assert_eq!(record_stem("(`TASK-a-b`)"), Some("TASK-a-b".into()));
        assert_eq!(record_stem("an XRFC-0084 part"), None);
        assert_eq!(record_stem("RFC 8446 and RFC 3339"), None);
        assert_eq!(record_stem("IDEA-Tracker"), None);
        assert_eq!(iso_date("on 2026-09-21, then"), Some("2026-09-21"));
        assert_eq!(iso_date("v12026-09-21"), None);
        assert_eq!(iso_date("2026-09-2"), None);
        assert_eq!(iso_date("Copyright 2024-2026 Kotton"), None);
    }

    /// **The bare forms are record names.** The kind with its hyphen and nothing after it, the
    /// kind's word with a space and a number, and `RFC` as a word alone cite the record set as
    /// surely as a full name; `RFC` and a number is the IETF's spelling unless the number has a
    /// record's leading zero.
    #[test]
    fn the_bare_forms_are_record_names() {
        for (line, stem) in [
            ("filed as a DEC-", "DEC-"),
            ("an RFC- would have said so", "RFC-"),
            ("each `TASK-…` is gone", "TASK-"),
            ("(IDEA-)", "IDEA-"),
            ("as DEC 85 rules", "DEC 85"),
            ("see TASK 12, then", "TASK 12"),
            ("IDEA 3", "IDEA 3"),
            ("per RFC 0084.", "RFC 0084"),
            ("as an RFC says", "RFC"),
            ("rule 3 of the RFC, drawn", "RFC"),
            ("RFC", "RFC"),
        ] {
            assert_eq!(record_stem(line), Some(stem.to_owned()), "{line:?}");
        }
        for line in [
            "an RFC 3339 timestamp",
            "TLS 1.3 is RFC 8446",
            "the RFCs",
            "RFC-Tracker",
            "DECEMBER 5",
            "DEC 85x",
            "DEC-Alpha",
            "a XDEC- part",
            "TASKS 3",
            "the IDEA, in words",
        ] {
            assert_eq!(record_stem(line), None, "{line:?}");
        }

        let dir = tree(&[("xtask/src/gate.rs", "fn f() {\n    eprintln!(\"as an RFC- would say\");\n}\n")]);
        assert_eq!(findings(dir.path()), vec!["xtask/src/gate.rs:2: names the record `RFC-`".to_string()]);
        let dir = tree(&[("docs/README.md", "# docs\n\nAs DEC 85 rules.\n")]);
        assert_eq!(findings(dir.path()), vec!["docs/README.md:3: names the record `DEC 85`".to_string()]);
        let dir = tree(&[("ui/ink/README.md", "# Drawings\n\nrule 3 of the RFC, drawn.\n")]);
        assert_eq!(findings(dir.path()), vec!["ui/ink/README.md:3: names the record `RFC`".to_string()]);
    }

    /// **xtask's printed lines are read for narrated dates, as a page is.** A date planted in a
    /// gate's refusal is refused by file and line, a multi-line literal's continuation line
    /// included — and one in the comment above it is refused too, on its own line.
    #[test]
    fn xtask_literals_are_read_for_dates() {
        let planted = "fn refuse() {\n    // moved on 2026-08-23, which a comment may not say\n    eprintln!(\n        \"scope-check: refused. The usual cause is a \\\n         verb that moved on 2026-08-23.\"\n    );\n}\n";
        let dir = tree(&[("xtask/src/scope_check.rs", planted)]);
        assert_eq!(
            findings(dir.path()),
            vec![
                "xtask/src/scope_check.rs:5: narrates a date (`2026-08-23`)".to_string(),
                "xtask/src/scope_check.rs:2: narrates a date (`2026-08-23`)".to_string(),
            ]
        );

        let dir = tree(&[("xtask/src/license_check.rs", "const F: &str = \"in no archive since 2026-09-26\";\n")]);
        assert_eq!(findings(dir.path()), vec!["xtask/src/license_check.rs:1: narrates a date (`since 2026`)".to_string()]);
    }

    /// **A named file's test fixtures are skipped for dates, and nothing else is.** The same
    /// timestamp is passed inside a test module of a file in [`DATED_FIXTURES`], refused in
    /// that file's printed lines, refused in the test of a file not named, and a record name in
    /// a named file's test module is still a record name.
    #[test]
    fn only_a_named_files_test_modules_hold_a_date() {
        let named = DATED_FIXTURES[0];
        let fixture = "fn main() {\n    println!(\"ok\");\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn reads() {\n        let line = \"2026-09-22T00:00:00Z  INFO kuserd: left\";\n        assert!(!line.is_empty());\n    }\n}\n";
        let dir = tree(&[(named, fixture)]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());

        let printed = fixture.replace("println!(\"ok\")", "println!(\"ok as of 2026-09-26\")");
        let dir = tree(&[(named, &printed)]);
        assert_eq!(findings(dir.path()), vec![format!("{named}:2: narrates a date (`2026-09-26`)")]);

        let dir = tree(&[("xtask/src/gate.rs", fixture)]);
        assert_eq!(findings(dir.path()), vec!["xtask/src/gate.rs:9: narrates a date (`2026-09-22`)".to_string()]);

        let cited = fixture.replace("INFO kuserd: left", "see RFC-0001");
        let dir = tree(&[(named, &cited)]);
        assert_eq!(findings(dir.path()), vec![format!("{named}:9: names the record `RFC-0001`")]);
    }

    /// Only a test module's block is skipped: from the attribute, past doc comments and
    /// attributes, to the `}` that is the first line back at its indentation, nested or not. A
    /// `mod name;`, a function, and a module whose first line back at that indentation is not
    /// its `}` (or that is never closed) are not skipped.
    #[test]
    fn only_test_modules_are_skipped() {
        let src = "\
fn a() {}
#[cfg(test)]
mod x;
#[cfg(test)]
fn one_line() {}
#[cfg(test)]
/// doc
#[allow(dead_code)]
mod tests {
    use super::*;

    fn t() {}
}
mod outer {
    #[cfg(test)]
    mod inner {
        fn u() {}
    }
}
#[cfg(test)]
mod misclosed {
    fn v() {}
    }
fn w() {}
#[cfg(test)]
mod open {
    fn z() {}
";
        assert_eq!(test_modules(src), vec![(6, 13), (15, 18)]);
        assert_eq!(test_modules("fn a() {}\n"), Vec::<(usize, usize)>::new());
    }

    /// **A date in a test item that is not a module is refused, in a named file too.** A
    /// one-line function, a field, and a constant whose raw string holds a `{` are read in
    /// full, and so is the printing function after each.
    #[test]
    fn a_date_in_a_test_item_that_is_not_a_module_is_refused() {
        let named = "xtask/src/release.rs";
        assert!(DATED_FIXTURES.contains(&named));
        let prints = "\nfn release() {\n    println!(\"released as of 2026-08-23\");\n}\n";
        for (item, line) in [
            ("#[cfg(test)]\nfn helper() {}\n", 5),
            ("struct S {\n    #[cfg(test)]\n    at: &'static str,\n}\n", 7),
            ("#[cfg(test)]\nconst FIXTURE: &str = r#\"\n{ \"opened\": 1\n\"#;\n", 7),
        ] {
            let dir = tree(&[(named, &format!("{item}{prints}"))]);
            assert_eq!(findings(dir.path()), vec![format!("{named}:{line}: narrates a date (`2026-08-23`)")], "{item:?}");
        }
        let dated = "#[cfg(test)]\nfn helper() -> &'static str {\n    \"2026-09-25 18:00\"\n}\n";
        let dir = tree(&[(named, dated)]);
        assert_eq!(findings(dir.path()), vec![format!("{named}:3: narrates a date (`2026-09-25`)")]);
    }

    /// **A Rust comment under the trees `host-word-check` reads is read for every rule, as a
    /// page is.** Each comment form — `//`, `///`, `//!` and a `/* */` block over several
    /// lines — and each tree kind (`xtask/src`, a crate's `src/` and its `tests/`, the CLI, the
    /// relay's tests) is refused by file and by the line the finding is on: a record name in
    /// each of its forms, bare ones included, and a narrated date in each of its forms.
    #[test]
    fn comments_are_read_for_records_and_dates() {
        let planted: &[(&str, &str, &str)] = &[
            ("core/store/src/lib.rs", "// see RFC-0084", "names the record `RFC-0084`"),
            ("core/device/src/lib.rs", "/// The relay keeps nothing (DEC-0056).", "names the record `DEC-0056`"),
            ("core/peer/src/lib.rs", "//! A door (`TASK-a-relay-introduces-your-devices`).", "names the record `TASK-a-relay-introduces-your-devices`"),
            ("core/kuserd/src/lib.rs", "// filed as IDEA-a-thing", "names the record `IDEA-a-thing`"),
            ("core/device/tests/fresh.rs", "// as DEC 85 rules", "names the record `DEC 85`"),
            ("client/cli/src/main.rs", "// the RFC says so", "names the record `RFC`"),
            ("infra/relay/tests/install.rs", "/// a TASK- would have said", "names the record `TASK-`"),
            ("xtask/src/gate.rs", "// see governance/records/", "a path into governance/, which is not in the tree"),
            ("core/store/src/lib.rs", "// since 2026-08-30 the store packs", "narrates a date (`since 2026`)"),
            ("core/peer/src/lib.rs", "/// Measured 2026-09-15 on the owner's machine.", "narrates a date (`Measured 2026`)"),
            ("guest/apps/kotton-shell/logic/src/view.rs", "// Until 2026-08-26 this drew nothing.", "narrates a date (`2026-08-26`)"),
        ];
        for (path, line, says) in planted {
            let text = format!("fn a() {{}}\n{line}\nfn b() {{}}\n");
            let dir = tree(&[(path, &text)]);
            assert_eq!(findings(dir.path()), vec![format!("{path}:2: {says}")], "{line:?}");
        }

        // A block comment is named by the line the finding is on, not the line it opens on,
        // and a nested block is part of the one it sits in.
        let block = "fn a() {}\n/* The pack layer.\n   /* nested */ As RFC-0045 put it,\n   since 2026-09-01. */\nfn b() {}\n";
        let dir = tree(&[("core/store/src/stack.rs", block)]);
        assert_eq!(
            findings(dir.path()),
            vec![
                "core/store/src/stack.rs:3: names the record `RFC-0045`".to_string(),
                "core/store/src/stack.rs:4: narrates a date (`since 2026`)".to_string(),
            ]
        );
    }

    /// **Only a comment is read, and only where the rules say.** A `//` inside a string
    /// literal starts no comment; the IETF's `RFC 3339` is not a record; a literal outside
    /// `xtask/src/` is not read; and a trailing comment after code is read like any other.
    #[test]
    fn only_the_comment_is_read() {
        let src = "const URL: &str = \"https://example.org/RFC-0001\"; // an RFC 3339 timestamp\nconst C: char = '/';\nfn f() -> u8 { 1 } // fine\n";
        let dir = tree(&[("core/time/src/lib.rs", src)]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());

        let dir = tree(&[("core/time/src/lib.rs", "let x = 1; // since 2026-09-02\n")]);
        assert_eq!(findings(dir.path()), vec!["core/time/src/lib.rs:1: narrates a date (`since 2026`)".to_string()]);
    }

    /// **A comment outside the trees is not read**: the display server, which `host-word-check`
    /// leaves out, a crate's benches, a guest app other than the window, the scenarios, the
    /// root `tests/` and `system/`, a file that is not `.rs`, and this file, whose tests plant
    /// record names.
    #[test]
    fn a_comment_outside_the_trees_is_not_read() {
        let dir = tree(&[
            ("core/kuid/src/main.rs", "// RFC-0018\n"),
            ("core/store/benches/pack.rs", "// RFC-0045\n"),
            ("guest/apps/kotton-records/src/lib.rs", "// RFC-0088\n"),
            ("infra/scenarios/conductor/src/main.rs", "// since 2026-09-14\n"),
            ("tests/integration/src/lib.rs", "// TASK-a-b\n"),
            ("system/kdeviced/src/main.rs", "// DEC-0001\n"),
            ("core/store/src/notes.md", "// RFC-0001\n"),
            ("xtask/src/docs_present_check.rs", "// RFC-0001\n"),
        ]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());
        assert_eq!(comment_files(dir.path()), Vec::<String>::new());
    }

    /// **A named file's test modules are skipped for dates in their comments, as in their
    /// literals, and nothing else is.** A record name there is still refused, and so is a date
    /// in the comment of the code the file prints from.
    #[test]
    fn a_named_files_test_modules_skip_dates_in_comments_too() {
        let named = DATED_FIXTURES[0];
        let src = "// prints the line\nfn main() {}\n\n#[cfg(test)]\nmod tests {\n    // a tracing line, 2026-09-22T00:00:00Z and all\n    fn t() {}\n}\n";
        let dir = tree(&[(named, src)]);
        assert_eq!(findings(dir.path()), Vec::<String>::new());

        let cited = src.replace("a tracing line", "see RFC-0001, a tracing line");
        let dir = tree(&[(named, &cited)]);
        assert_eq!(findings(dir.path()), vec![format!("{named}:6: names the record `RFC-0001`")]);

        let dated = src.replace("// prints the line", "// prints the line since 2026-09-20");
        let dir = tree(&[(named, &dated)]);
        assert_eq!(findings(dir.path()), vec![format!("{named}:1: narrates a date (`since 2026`)")]);

        let dir = tree(&[("xtask/src/gate.rs", src)]);
        assert_eq!(findings(dir.path()), vec!["xtask/src/gate.rs:6: narrates a date (`2026-09-22`)".to_string()]);
    }

    /// **The list of files not yet swept cannot go stale.** A listed file whose comments cite
    /// is not read in them; a listed file whose comments pass is refused until it comes off; a
    /// listed path that is not a `.rs` file under the trees is refused; and a listed file's
    /// literals are still read.
    #[test]
    fn the_unswept_list_cannot_go_stale() {
        let cites = ("core/store/src/lib.rs", "// see RFC-0084\nfn a() {}\n");
        let clean = ("core/peer/src/lib.rs", "// The relay keeps nothing.\nfn a() {}\n");
        let dir = tree(&[cites, clean]);

        assert_eq!(findings_in(dir.path(), &["core/store/src/lib.rs"], 1), Vec::<String>::new());
        assert_eq!(
            findings_in(dir.path(), &["core/store/src/lib.rs", "core/peer/src/lib.rs"], 2),
            vec![
                "core/peer/src/lib.rs: its comments name no record and narrate no date, so it comes off COMMENTS_NOT_READ"
                    .to_string()
            ]
        );
        assert_eq!(
            findings_in(dir.path(), &["core/store/src/lib.rs", "core/store/src/gone.rs"], 2),
            vec!["core/store/src/gone.rs: on COMMENTS_NOT_READ, and not a .rs file whose comments the check reads".to_string()]
        );
        let dir = tree(&[cites, ("core/kuid/src/main.rs", "// RFC-0018\n")]);
        assert_eq!(
            findings_in(dir.path(), &["core/store/src/lib.rs", "core/kuid/src/main.rs"], 2),
            vec!["core/kuid/src/main.rs: on COMMENTS_NOT_READ, and not a .rs file whose comments the check reads".to_string()]
        );

        let dir = tree(&[("xtask/src/gate.rs", "// RFC-0001\nfn f() { eprintln!(\"see RFC-0002\"); }\n")]);
        assert_eq!(
            findings_in(dir.path(), &["xtask/src/gate.rs"], 1),
            vec!["xtask/src/gate.rs:2: names the record `RFC-0002`".to_string()]
        );
    }

    /// **The list and its count agree, and a list one longer than its count is refused.** The
    /// real list is as long as [`UNSWEPT_FILES`] says, sorted, one path a line, none twice, each
    /// a `.rs` file under the trees and none also on [`NOT_READ`]. A path added to a list whose
    /// count stayed — a cited file put back on it — is refused by name of the two constants,
    /// even though the file it lists cites; and so is a list one shorter than its count.
    ///
    /// **What the count does not catch: a swap.** One file swept and taken off, and a citation
    /// added to a swept file that is then listed in its place, leaves the list as long as the
    /// count and passes. A path that joins the list is a line in the diff, and review is what
    /// holds that case.
    #[test]
    fn the_unswept_list_and_its_count_agree() {
        assert_eq!(COMMENTS_NOT_READ.len(), UNSWEPT_FILES, "COMMENTS_NOT_READ and UNSWEPT_FILES disagree");
        let mut sorted = COMMENTS_NOT_READ.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, COMMENTS_NOT_READ, "COMMENTS_NOT_READ is sorted, one path a line, none twice");
        for path in COMMENTS_NOT_READ {
            assert!(path.ends_with(".rs"), "{path}");
            assert!(COMMENT_TREES.iter().any(|t| path.starts_with(&format!("{t}/"))), "{path} is under no tree read");
            assert!(!NOT_READ.contains(path), "{path} is on both lists");
        }
        assert_eq!(COMMENT_TREES, crate::host_word_check::RUST_TREES);

        let dir = tree(&[
            ("core/store/src/lib.rs", "// see RFC-0084\n"),
            ("core/peer/src/lib.rs", "// see DEC-0055\n"),
        ]);
        let both = ["core/peer/src/lib.rs", "core/store/src/lib.rs"];
        assert_eq!(findings_in(dir.path(), &both, 2), Vec::<String>::new());
        let refused = |found: Vec<String>| {
            assert_eq!(found.len(), 1, "{found:?}");
            assert!(found[0].contains("COMMENTS_NOT_READ holds") && found[0].contains("UNSWEPT_FILES says"), "{found:?}");
        };
        // A cited file put back on the list with the count left as it was.
        refused(findings_in(dir.path(), &both, 1));
        let found = findings_in(dir.path(), &["core/store/src/lib.rs"], 2);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("COMMENTS_NOT_READ holds 1 path(s) and UNSWEPT_FILES says 2"), "{found:?}");
    }
}
