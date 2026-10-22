// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a [`Profile`] becomes on Windows, as data: the AppContainer's name, the
//! access-control entries its SID is given, and the job object's limits.
//!
//! Pure on purpose. Everything in this file is a function of the profile and of
//! whether each granted path is a directory, so it compiles and is tested on the
//! Linux machines this repository is developed on, where nothing in
//! [`super::windows`] can run. What the Win32 half does with a [`Plan`] is
//! mechanical — one `SetEntriesInAclW` per entry, one `SetInformationJobObject`
//! per limit class — and the decisions a reviewer has to check are here.
//!
//! # The three mechanisms, and which Linux one each stands in for
//!
//! | Linux | Windows | Here |
//! |---|---|---|
//! | Landlock, `handled_access_fs` with nothing granted | an AppContainer SID: a token the user's own files do not name, so nothing is reachable until an entry says so | [`Plan::container`] |
//! | Landlock path rules | one explicit ACE per grant, for that SID, inherited beneath a directory | [`Plan::aces`] |
//! | seccomp refusing `socket(2)` and `io_uring` | the AppContainer is given **no capabilities**, and network access on Windows *is* a capability (`internetClient`, `privateNetworkClientServer`), so the platform's filters drop the traffic | nothing to plan: [`Plan`] has no field for a capability, and the Win32 half passes a count of zero |
//! | Landlock's signal scope; seccomp refusing `ptrace` and `process_vm_*` | other processes' DACLs do not name an AppContainer SID, so `OpenProcess` on a sibling is denied | nothing to plan |
//! | Landlock's abstract-socket scope | the job's UI restrictions: no other process's window handles, clipboard, atoms or desktop | [`JobLimits::ui`] |
//! | the child dies with its parent's pipe | the job kills everything in it when its last handle closes | [`JobLimits::flags`] |
//!
//! The capability row is the network half of `crate::sandbox`'s promise that the
//! type cannot express an address, restated for this platform: there is no
//! capability list to put one in.

use crate::sandbox::{Profile, Reach, SandboxError};
use std::io;
use std::path::{Path, PathBuf};

// ── Access rights ────────────────────────────────────────────────────────────
//
// Spelled out rather than taken from `windows-sys`, which is a Windows-only
// dependency and so absent where these tests run. The Win32 half asserts at
// compile time that each one equals the SDK's.

/// `FILE_READ_DATA` on a file, `FILE_LIST_DIRECTORY` on a directory.
pub(crate) const FILE_READ_DATA: u32 = 0x0001;
/// `FILE_WRITE_DATA` on a file, `FILE_ADD_FILE` on a directory.
pub(crate) const FILE_WRITE_DATA: u32 = 0x0002;
/// `FILE_APPEND_DATA` on a file, `FILE_ADD_SUBDIRECTORY` on a directory.
pub(crate) const FILE_APPEND_DATA: u32 = 0x0004;
/// `FILE_EXECUTE` on a file, `FILE_TRAVERSE` on a directory.
pub(crate) const FILE_EXECUTE: u32 = 0x0020;
/// Remove any child of this directory, whatever the child's own DACL says.
pub(crate) const FILE_DELETE_CHILD: u32 = 0x0040;
pub(crate) const DELETE: u32 = 0x0001_0000;
pub(crate) const WRITE_DAC: u32 = 0x0004_0000;
pub(crate) const WRITE_OWNER: u32 = 0x0008_0000;

/// `READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES`.
pub(crate) const FILE_GENERIC_READ: u32 = 0x0012_0089;
/// `READ_CONTROL | SYNCHRONIZE | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES`.
pub(crate) const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
/// `READ_CONTROL | SYNCHRONIZE | FILE_EXECUTE | FILE_READ_ATTRIBUTES`.
pub(crate) const FILE_GENERIC_EXECUTE: u32 = 0x0012_00a0;

// ACE inheritance.
pub(crate) const NO_INHERITANCE: u32 = 0;
pub(crate) const OBJECT_INHERIT_ACE: u32 = 0x1;
pub(crate) const CONTAINER_INHERIT_ACE: u32 = 0x2;

// ── Job limits ───────────────────────────────────────────────────────────────

pub(crate) const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
pub(crate) const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x0000_0400;
pub(crate) const JOB_OBJECT_LIMIT_BREAKAWAY_OK: u32 = 0x0000_0800;
pub(crate) const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK: u32 = 0x0000_1000;
pub(crate) const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

pub(crate) const JOB_OBJECT_UILIMIT_HANDLES: u32 = 0x0001;
pub(crate) const JOB_OBJECT_UILIMIT_READCLIPBOARD: u32 = 0x0002;
pub(crate) const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: u32 = 0x0004;
pub(crate) const JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: u32 = 0x0008;
pub(crate) const JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: u32 = 0x0010;
pub(crate) const JOB_OBJECT_UILIMIT_GLOBALATOMS: u32 = 0x0020;
pub(crate) const JOB_OBJECT_UILIMIT_DESKTOP: u32 = 0x0040;
pub(crate) const JOB_OBJECT_UILIMIT_EXITWINDOWS: u32 = 0x0080;

/// The longest name `CreateAppContainerProfile` accepts.
pub(crate) const CONTAINER_NAME_MAX: usize = 64;

/// Whether a granted path is a directory, which decides whether its entry is
/// inherited beneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    Directory,
    File,
}

/// One explicit access-control entry for the container's SID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ace {
    pub(crate) path: PathBuf,
    /// The access mask granted.
    pub(crate) mask: u32,
    /// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` on a directory, so the
    /// grant reaches beneath it as a Landlock path rule does; nothing on a
    /// file.
    pub(crate) inheritance: u32,
}

/// What the job object holds the child to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JobLimits {
    /// `JOBOBJECT_BASIC_LIMIT_INFORMATION::LimitFlags`.
    pub(crate) flags: u32,
    /// `JOBOBJECT_BASIC_LIMIT_INFORMATION::ActiveProcessLimit`.
    pub(crate) active_processes: u32,
    /// `JOBOBJECT_BASIC_UI_RESTRICTIONS::UIRestrictionsClass`.
    pub(crate) ui: u32,
}

/// A profile, translated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The AppContainer's name, unique to this spawn.
    pub(crate) container: String,
    /// One entry per grant, in the order the caller wrote them.
    pub(crate) aces: Vec<Ace>,
    pub(crate) job: JobLimits,
}

/// Translate `profile`, naming the container from `pid`, `nonce` and `seq`.
///
/// `target_of` answers whether a granted path is a directory, and is
/// `std::fs::metadata` outside a test. A path it reports missing is
/// [`SandboxError::NoSuchGrant`] for the same reason it is on Linux: an entry
/// names an object, and one that is not there cannot be named without widening
/// to whichever ancestor is.
pub(crate) fn plan(
    profile: &Profile,
    pid: u32,
    nonce: u64,
    seq: u64,
    target_of: impl Fn(&Path) -> io::Result<Target>,
) -> Result<Plan, SandboxError> {
    let mut aces = Vec::with_capacity(profile.grants().len());
    for grant in profile.grants() {
        let target = target_of(&grant.path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                SandboxError::NoSuchGrant {
                    purpose: profile.purpose().to_string(),
                    path: grant.path.clone(),
                }
            } else {
                SandboxError::Refused {
                    purpose: profile.purpose().to_string(),
                    step: "reading a granted path",
                    source: e,
                }
            }
        })?;
        aces.push(Ace {
            path: grant.path.clone(),
            mask: access_for(grant.reach, target),
            inheritance: inheritance_for(target),
        });
    }
    Ok(Plan {
        container: container_name(profile.purpose(), pid, nonce, seq),
        aces,
        job: job_limits(),
    })
}

/// What a [`Reach`] means as a file access mask.
///
/// None of them carries `WRITE_DAC` or `WRITE_OWNER`: a confined process that
/// could rewrite an object's DACL could grant itself anything its SID can be
/// named in. None but `Execute` carries `FILE_EXECUTE`, which on a directory
/// is traverse — left out because an entry inherited by the files beneath would
/// make every image in a read grant runnable, and the AppContainer token keeps
/// the bypass-traverse privilege, so reading `dir\file` does not need it.
pub(crate) fn access_for(reach: Reach, target: Target) -> u32 {
    match reach {
        Reach::Read => FILE_GENERIC_READ,
        // `FILE_DELETE_CHILD` rather than `DELETE`, and only on a directory.
        // On the directory it removes anything beneath, which is what SQLite's
        // `-journal` and `-wal` files need; `DELETE` would also let the child
        // remove the granted directory itself, which a Landlock rule beneath
        // it does not. On a file there is no child, and deleting the file is a
        // right on its parent that a file grant does not hold on Linux either.
        Reach::Write => match target {
            Target::Directory => FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_DELETE_CHILD,
            Target::File => FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        },
        Reach::Execute => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        Reach::Device => FILE_GENERIC_READ | FILE_GENERIC_WRITE,
    }
}

/// Beneath a directory, as a Landlock path rule reaches; on a file, that file.
pub(crate) fn inheritance_for(target: Target) -> u32 {
    match target {
        Target::Directory => OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        Target::File => NO_INHERITANCE,
    }
}

/// The job every confined child is placed in.
///
/// - **Killed when the job's last handle closes.** The provider holds the only
///   handle, so a daemon that exits or crashes takes its confined children with
///   it rather than leaving a stranger's code running unowned.
/// - **One process.** Neither `kinferd` nor `kotton-runner` starts a process,
///   and on Linux the only image a confined child may `execve` is its own. A
///   limit of one says the same thing without depending on an image grant.
/// - **An unhandled exception ends the process** instead of raising the
///   error-reporting dialog, which would run outside the job on the child's
///   behalf.
/// - **No breakaway**, silent or requested: a child cannot leave the job.
/// - **Every UI restriction.** Another process's window handles are how one
///   process of a user reaches into another's on a desktop — the Windows form
///   of the sibling-reaching routes Landlock's scopes close — and the clipboard
///   is a channel no confined process is given.
pub(crate) fn job_limits() -> JobLimits {
    JobLimits {
        flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
        active_processes: 1,
        ui: JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS,
    }
}

/// A container name for one spawn: `kotton.<purpose>.<pid>.<nonce>.<seq>`.
///
/// **Unique per spawn, and that is a security property, not tidiness.** The SID
/// is derived from the name, so two spawns sharing a name share every entry
/// either was ever granted — the union of all their profiles, which is the
/// widening a per-spawn profile exists to prevent. `pid` and `seq` separate
/// spawns within one daemon; `nonce`, taken once per daemon from the clock,
/// separates a daemon from an earlier one that had the same pid and crashed
/// before revoking its entries.
///
/// The characters are the ones `CreateAppContainerProfile` accepts
/// (`[-_. A-Za-z0-9]`, at most 64); anything else in `purpose` becomes `_`, and
/// `purpose` is shortened before the fields that make the name unique are.
pub(crate) fn container_name(purpose: &str, pid: u32, nonce: u64, seq: u64) -> String {
    let tail = format!(".{pid}.{nonce:x}.{seq}");
    let room = CONTAINER_NAME_MAX - "kotton.".len() - tail.len();
    let purpose: String = purpose
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(room)
        .collect();
    format!("kotton.{purpose}{tail}")
}

/// Quote `program` and `args` into one command line, the way the Microsoft C
/// runtime and Rust's own `std::env::args` split it back apart.
///
/// `CreateProcessW` takes a single string and every child parses it itself;
/// this is the inverse of that parser. A double quote is escaped with a
/// backslash, and a run of backslashes is doubled only where it precedes a
/// quote — including the closing quote this adds.
pub(crate) fn command_line<'a>(program: &str, args: impl IntoIterator<Item = &'a str>) -> String {
    let mut line = String::new();
    // The program name is not parsed with the escaping rules — it ends at the
    // first quote — so it is quoted and must not contain one.
    line.push('"');
    line.push_str(program);
    line.push('"');
    for arg in args {
        line.push(' ');
        quote_into(&mut line, arg);
    }
    line
}

fn quote_into(line: &mut String, arg: &str) {
    let needs_quotes = arg.is_empty() || arg.contains([' ', '\t', '\n', '\u{b}', '"']);
    if !needs_quotes {
        line.push_str(arg);
        return;
    }
    line.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                line.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                line.push('"');
                backslashes = 0;
            }
            _ => {
                line.extend(std::iter::repeat_n('\\', backslashes));
                line.push(c);
                backslashes = 0;
            }
        }
    }
    line.extend(std::iter::repeat_n('\\', backslashes * 2));
    line.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(dirs: &'static [&'static str]) -> impl Fn(&Path) -> io::Result<Target> {
        move |p: &Path| {
            let s = p.to_str().expect("utf-8 test path");
            if s.contains("missing") {
                Err(io::Error::from(io::ErrorKind::NotFound))
            } else if dirs.contains(&s) {
                Ok(Target::Directory)
            } else {
                Ok(Target::File)
            }
        }
    }

    fn planned(profile: &Profile) -> Plan {
        plan(profile, 4242, 0xfeed, 7, fake(&["C:\\data", "C:\\roots\\a"])).expect("plannable")
    }

    #[test]
    fn a_profile_that_grants_nothing_plans_no_entry_at_all() {
        let p = planned(&Profile::nothing("kinferd"));
        assert!(p.aces.is_empty(), "{:?}", p.aces);
    }

    #[test]
    fn each_grant_is_one_entry_in_the_order_the_caller_wrote_it() {
        let profile = Profile::nothing("kotton-runner")
            .executing("C:\\bin\\kotton-runner.exe")
            .reading("C:\\bin\\app.wasm")
            .writing("C:\\data")
            .reading("C:\\roots\\a");
        let p = planned(&profile);
        let paths: Vec<_> = p.aces.iter().map(|a| a.path.to_str().unwrap()).collect();
        assert_eq!(
            paths,
            ["C:\\bin\\kotton-runner.exe", "C:\\bin\\app.wasm", "C:\\data", "C:\\roots\\a"]
        );
    }

    #[test]
    fn a_directory_grant_reaches_beneath_itself_and_a_file_grant_does_not() {
        let p = planned(
            &Profile::nothing("t")
                .writing("C:\\data")
                .reading("C:\\bin\\app.wasm"),
        );
        assert_eq!(p.aces[0].inheritance, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        assert_eq!(p.aces[1].inheritance, NO_INHERITANCE);
    }

    #[test]
    fn a_read_grant_carries_no_write_and_no_execute() {
        for target in [Target::Directory, Target::File] {
            let m = access_for(Reach::Read, target);
            assert_eq!(m & FILE_READ_DATA, FILE_READ_DATA);
            assert_eq!(m & (FILE_WRITE_DATA | FILE_APPEND_DATA), 0, "{target:?}");
            assert_eq!(m & FILE_EXECUTE, 0, "{target:?}: traverse inherited is execute");
            assert_eq!(m & (DELETE | FILE_DELETE_CHILD), 0, "{target:?}");
        }
    }

    #[test]
    fn a_write_grant_removes_beneath_a_directory_and_never_the_directory_itself() {
        let dir = access_for(Reach::Write, Target::Directory);
        assert_eq!(dir & FILE_DELETE_CHILD, FILE_DELETE_CHILD);
        assert_eq!(dir & DELETE, 0, "DELETE would let the child remove the granted directory");
        assert_eq!(dir & (FILE_WRITE_DATA | FILE_APPEND_DATA), FILE_WRITE_DATA | FILE_APPEND_DATA);
        assert_eq!(dir & FILE_EXECUTE, 0);

        let file = access_for(Reach::Write, Target::File);
        assert_eq!(file & (DELETE | FILE_DELETE_CHILD), 0);
        assert_eq!(file & FILE_WRITE_DATA, FILE_WRITE_DATA);
    }

    #[test]
    fn only_an_execute_grant_carries_execute() {
        let exe = access_for(Reach::Execute, Target::File);
        assert_eq!(exe & FILE_EXECUTE, FILE_EXECUTE);
        // An image is mapped by reading it; execute alone cannot load it.
        assert_eq!(exe & FILE_GENERIC_READ, FILE_GENERIC_READ);
        for reach in [Reach::Read, Reach::Write, Reach::Device] {
            for target in [Target::Directory, Target::File] {
                assert_eq!(access_for(reach, target) & FILE_EXECUTE, 0, "{reach:?} {target:?}");
            }
        }
    }

    #[test]
    fn no_grant_can_rewrite_a_dacl_or_an_owner() {
        for reach in [Reach::Read, Reach::Write, Reach::Execute, Reach::Device] {
            for target in [Target::Directory, Target::File] {
                assert_eq!(
                    access_for(reach, target) & (WRITE_DAC | WRITE_OWNER),
                    0,
                    "{reach:?} on a {target:?} could grant itself anything"
                );
            }
        }
    }

    #[test]
    fn a_grant_on_a_path_that_does_not_exist_is_refused_before_anything_is_created() {
        let err = plan(
            &Profile::nothing("sandbox-test").reading("C:\\missing\\grant"),
            1,
            1,
            1,
            fake(&[]),
        )
        .expect_err("a grant naming nothing is the caller's bug");
        match err {
            SandboxError::NoSuchGrant { path, purpose } => {
                assert_eq!(path, Path::new("C:\\missing\\grant"));
                assert_eq!(purpose, "sandbox-test");
            }
            other => panic!("expected NoSuchGrant, got {other}"),
        }
    }

    #[test]
    fn the_job_kills_on_close_holds_one_process_and_lets_nothing_break_away() {
        let j = job_limits();
        assert_eq!(j.flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE);
        assert_eq!(j.flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_ACTIVE_PROCESS);
        assert_eq!(j.active_processes, 1);
        assert_eq!(
            j.flags & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
            "a crash would raise the error-reporting dialog outside the job"
        );
        assert_eq!(
            j.flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK),
            0,
            "a child that can leave the job is not held by it"
        );
    }

    #[test]
    fn the_job_withholds_every_ui_route_to_another_process() {
        let ui = job_limits().ui;
        for bit in [
            JOB_OBJECT_UILIMIT_HANDLES,
            JOB_OBJECT_UILIMIT_READCLIPBOARD,
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
            JOB_OBJECT_UILIMIT_GLOBALATOMS,
            JOB_OBJECT_UILIMIT_DESKTOP,
            JOB_OBJECT_UILIMIT_EXITWINDOWS,
        ] {
            assert_eq!(ui & bit, bit, "UI limit {bit:#x} is not set");
        }
    }

    #[test]
    fn a_container_name_is_unique_per_spawn_and_fits_what_windows_accepts() {
        let a = container_name("kotton-runner", 4242, 0xfeed, 1);
        let b = container_name("kotton-runner", 4242, 0xfeed, 2);
        let c = container_name("kotton-runner", 4242, 0xbeef, 1);
        assert_ne!(a, b, "two spawns in one daemon share a SID");
        assert_ne!(a, c, "a spawn shares a SID with a crashed daemon's");

        let long = container_name(&"x".repeat(200), u32::MAX, u64::MAX, u64::MAX);
        assert!(long.len() <= CONTAINER_NAME_MAX, "{} chars: {long}", long.len());
        assert!(long.ends_with(&format!(".{}.{:x}.{}", u32::MAX, u64::MAX, u64::MAX)));

        let odd = container_name("a b/c\\d:é", 1, 1, 1);
        assert!(
            odd.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
            "{odd}"
        );
    }

    #[test]
    fn a_command_line_splits_back_into_the_arguments_it_was_built_from() {
        let args = [
            "--exact",
            "a b",
            "",
            "quote\"inside",
            "trailing\\",
            "back\\\\\"slash",
            "C:\\dir with space\\",
            "tab\there",
        ];
        let line = command_line("C:\\bin\\probe.exe", args);
        assert_eq!(split(&line), [&["C:\\bin\\probe.exe"][..], &args[..]].concat());
    }

    /// The MSVC runtime's argument parser, as `std::env::args` implements it on
    /// Windows — the reader [`command_line`] is written for. The program name
    /// ends at the next quote and takes no escapes.
    fn split(line: &str) -> Vec<String> {
        let mut chars = line.chars().peekable();
        let mut out = Vec::new();
        assert_eq!(chars.next(), Some('"'));
        out.push(chars.by_ref().take_while(|&c| c != '"').collect());
        loop {
            while matches!(chars.peek(), Some(' ' | '\t')) {
                chars.next();
            }
            if chars.peek().is_none() {
                return out;
            }
            let mut arg = String::new();
            let mut quoted = false;
            let mut backslashes = 0usize;
            while let Some(&c) = chars.peek() {
                match c {
                    '\\' => {
                        backslashes += 1;
                        chars.next();
                    }
                    '"' => {
                        arg.extend(std::iter::repeat_n('\\', backslashes / 2));
                        chars.next();
                        if backslashes % 2 == 1 {
                            arg.push('"');
                        } else {
                            quoted = !quoted;
                        }
                        backslashes = 0;
                    }
                    ' ' | '\t' if !quoted => break,
                    _ => {
                        arg.extend(std::iter::repeat_n('\\', backslashes));
                        backslashes = 0;
                        arg.push(c);
                        chars.next();
                    }
                }
            }
            arg.extend(std::iter::repeat_n('\\', backslashes));
            out.push(arg);
        }
    }
}
