// SPDX-License-Identifier: AGPL-3.0-or-later
// The `cfg` on this module's declaration in `mod.rs` is the real one; this is
// here because `windows-check` reads a file's first lines and cannot see a
// parent's `mod` line.
#![cfg(windows)]
// Everything below but `confine` is reached only by this file's own probes until
// the question escalated on
// `TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there` is
// answered — how the provider reaches a child that `confine` never sees. Scoped
// to non-test builds so the probes still prove every item is used.
#![cfg_attr(not(test), allow(dead_code))]
// Allowed for the whole module rather than per function as `linux.rs` does it,
// because here there is no function without a Win32 call in it; each `unsafe`
// block still carries its own SAFETY line.
#![allow(unsafe_code)]

//! Windows: an AppContainer with no capabilities, one ACE per grant for its SID,
//! and a job object — composed at `CreateProcessW`, around a child created
//! suspended.
//!
//! The translation from a [`Profile`] to those three is
//! [`super::appcontainer`], which is pure and tested on Linux. This file does
//! what it says, and nothing here decides anything a reviewer would need to
//! check twice.
//!
//! # Where the spawn differs from Unix
//!
//! Linux confines in the child: `pre_exec` runs between `fork` and `execve`, in
//! a copy of the parent that then becomes the guest. Windows has no `fork`, so
//! there is no moment in which the child is a copy of the parent that could
//! confine itself. The confinement is instead attached to the *creation*:
//!
//! 1. **In the parent, before anything is created**, every grant is checked to
//!    exist ([`SandboxError::NoSuchGrant`]), a per-spawn AppContainer is created
//!    and its SID derived, each grant becomes an explicit ACE for that SID on
//!    the granted path, and a job object is created with its limits.
//! 2. **`CreateProcessW` with a `STARTUPINFOEX`** whose attribute list carries
//!    `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`: the container's SID and a
//!    capability count of zero. The child's first token is the container's; it
//!    was never anything else. `CREATE_SUSPENDED`, so its first thread has not
//!    run an instruction; `bInheritHandles` false, so it inherits no handle
//!    the parent marked inheritable; and `DETACHED_PROCESS`, so it does not
//!    join the daemon's console, which would otherwise hand it working console
//!    handles without any inheritance. What `bInheritHandles` does not reach
//!    is not claimed: the probe `a_confined_process_has_no_console` measures
//!    the console half, and nothing here measures more.
//! 3. **The suspended child is assigned to the job, then resumed.** A failure
//!    at either step terminates it before it has run.
//! 4. **When it is gone**, its ACEs are revoked and the container deleted
//!    ([`Confined`]'s `Drop`), in that order, after the job — whose last handle
//!    closing kills anything still in it.
//!
//! # Why `confine` still refuses on Windows
//!
//! [`confine`] is handed a `tokio::process::Command` and returns before the
//! caller spawns it, which is exactly the shape step 2 cannot use: on stable
//! Rust, `std::process::Command` has no way to carry a `STARTUPINFOEX` attribute
//! list (`CommandExt::raw_attribute` is unstable, rust-lang/rust#114854), and
//! Tokio's own documentation shows the same attachment only behind
//! `tokio_unstable` and nightly. No attribute list means no AppContainer, and
//! an ACE for a SID the child does not carry confines nothing — so `confine`
//! returns [`SandboxError::Unsupported`] as it did before this file, and the
//! question of how the provider reaches the child is escalated on the record
//! above rather than answered here.
//!
//! # What this does not do
//!
//! - **It does not isolate GPU memory**, as on Linux (`DEC-0074` §3). A
//!   [`Reach::Device`](crate::sandbox::Reach::Device) grant is an ACE on a path,
//!   and a Windows graphics adapter is reached through DXGI, not a device node;
//!   the §3 split has no Windows form yet.
//! - **It serialises its own DACL edits, not other processes'.** Granting is a
//!   read-modify-write of a path's DACL, held under one lock per process; two
//!   daemons granting on the same path at once can lose one's entry, which
//!   surfaces as a refused open in the child, never as a wider grant.
//! - **Propagating an entry beneath a large directory is a walk of that tree.**
//!   `SetNamedSecurityInfoW` applies an inheritable entry to every existing
//!   child, which is what makes a grant reach files already beneath it, and
//!   costs one DACL write per file at spawn and again at revocation.

use super::appcontainer::{self, Plan, Target};
use crate::sandbox::{Profile, SandboxError};
use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL, WAIT_OBJECT_0};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile};
use windows_sys::Win32::Security::{
    FreeSid, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_CAPABILITIES,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
};

// The pure half spells the SDK's constants itself so it can compile on Linux.
// Each is held to the SDK's value here, where the SDK is present.
const _: () = {
    use windows_sys::Win32::Security as sec;
    use windows_sys::Win32::Storage::FileSystem as fs;
    use windows_sys::Win32::System::JobObjects as job;
    assert!(appcontainer::FILE_READ_DATA == fs::FILE_READ_DATA);
    assert!(appcontainer::FILE_WRITE_DATA == fs::FILE_WRITE_DATA);
    assert!(appcontainer::FILE_APPEND_DATA == fs::FILE_APPEND_DATA);
    assert!(appcontainer::FILE_EXECUTE == fs::FILE_EXECUTE);
    assert!(appcontainer::FILE_DELETE_CHILD == fs::FILE_DELETE_CHILD);
    assert!(appcontainer::DELETE == fs::DELETE);
    assert!(appcontainer::WRITE_DAC == fs::WRITE_DAC);
    assert!(appcontainer::WRITE_OWNER == fs::WRITE_OWNER);
    assert!(appcontainer::FILE_GENERIC_READ == fs::FILE_GENERIC_READ);
    assert!(appcontainer::FILE_GENERIC_WRITE == fs::FILE_GENERIC_WRITE);
    assert!(appcontainer::FILE_GENERIC_EXECUTE == fs::FILE_GENERIC_EXECUTE);
    assert!(appcontainer::NO_INHERITANCE == sec::NO_INHERITANCE);
    assert!(appcontainer::OBJECT_INHERIT_ACE == sec::OBJECT_INHERIT_ACE);
    assert!(appcontainer::CONTAINER_INHERIT_ACE == sec::CONTAINER_INHERIT_ACE);
    assert!(appcontainer::JOB_OBJECT_LIMIT_ACTIVE_PROCESS == job::JOB_OBJECT_LIMIT_ACTIVE_PROCESS);
    assert!(
        appcontainer::JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            == job::JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    );
    assert!(appcontainer::JOB_OBJECT_LIMIT_BREAKAWAY_OK == job::JOB_OBJECT_LIMIT_BREAKAWAY_OK);
    assert!(
        appcontainer::JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
            == job::JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
    );
    assert!(
        appcontainer::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == job::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    );
    assert!(appcontainer::JOB_OBJECT_UILIMIT_HANDLES == job::JOB_OBJECT_UILIMIT_HANDLES);
    assert!(appcontainer::JOB_OBJECT_UILIMIT_READCLIPBOARD == job::JOB_OBJECT_UILIMIT_READCLIPBOARD);
    assert!(
        appcontainer::JOB_OBJECT_UILIMIT_WRITECLIPBOARD == job::JOB_OBJECT_UILIMIT_WRITECLIPBOARD
    );
    assert!(
        appcontainer::JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            == job::JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    );
    assert!(
        appcontainer::JOB_OBJECT_UILIMIT_DISPLAYSETTINGS == job::JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    );
    assert!(appcontainer::JOB_OBJECT_UILIMIT_GLOBALATOMS == job::JOB_OBJECT_UILIMIT_GLOBALATOMS);
    assert!(appcontainer::JOB_OBJECT_UILIMIT_DESKTOP == job::JOB_OBJECT_UILIMIT_DESKTOP);
    assert!(appcontainer::JOB_OBJECT_UILIMIT_EXITWINDOWS == job::JOB_OBJECT_UILIMIT_EXITWINDOWS);
};

/// `confine` refuses on Windows until the escalation is answered; see the
/// module documentation. [`crate::sandbox::available`] says so.
pub(crate) const AVAILABLE: bool = false;

pub(crate) fn confine(
    _cmd: &mut tokio::process::Command,
    profile: &Profile,
) -> Result<(), SandboxError> {
    Err(SandboxError::Unsupported {
        purpose: profile.purpose().to_string(),
        os: std::env::consts::OS,
    })
}

// ── Preparing, in the parent ─────────────────────────────────────────────────

/// Everything the child will be confined by, created and held.
///
/// Field order is drop order, and it is the order the module documentation
/// gives: the job first (closing it kills whatever is still in it), then the
/// entries (revoked for the SID while the container still exists to name it),
/// then the container.
pub(crate) struct Prepared {
    job: OwnedHandle,
    /// Held for its `Drop`, which revokes.
    _grants: Grants,
    container: Container,
}

impl Prepared {
    pub(crate) fn for_profile(profile: &Profile) -> Result<Self, SandboxError> {
        let purpose = || profile.purpose().to_string();
        let plan = appcontainer::plan(profile, std::process::id(), nonce(), next_seq(), target_of)?;

        let container = Container::create(&plan.container).map_err(|source| SandboxError::Refused {
            purpose: purpose(),
            step: "creating the AppContainer",
            source,
        })?;
        let grants = Grants::apply(&plan, container.sid).map_err(|(path, source)| {
            if source.kind() == io::ErrorKind::NotFound {
                SandboxError::NoSuchGrant { purpose: purpose(), path }
            } else {
                SandboxError::Refused {
                    purpose: purpose(),
                    step: "adding an access-control entry",
                    source,
                }
            }
        })?;
        let job = create_job(&plan.job).map_err(|source| SandboxError::Refused {
            purpose: purpose(),
            step: "creating the job object",
            source,
        })?;

        Ok(Self {
            job,
            _grants: grants,
            container,
        })
    }

    /// Create `program` confined, run `args`, with `envs` added to this
    /// process's environment.
    ///
    /// A failure here is a failed spawn, as `Command::spawn` returns one — an
    /// image the container cannot open is `PermissionDenied`, as an image
    /// Landlock denies is on Linux.
    pub(crate) fn spawn(
        self,
        program: &Path,
        args: &[&str],
        envs: &[(&str, &str)],
    ) -> io::Result<Confined> {
        let program_str = program.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "the program path is not UTF-16 clean")
        })?;
        if program_str.contains('"') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a program path cannot contain a double quote",
            ));
        }
        let application = wide(program.as_os_str())?;
        let mut command_line = wide(OsStr::new(&appcontainer::command_line(
            program_str,
            args.iter().copied(),
        )))?;
        let environment = environment_block(envs)?;

        let attributes = AttributeList::with_container(self.container.sid)?;
        // SAFETY: zeroed is the documented initial state of both structs.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.as_ptr();
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // SAFETY: every pointer is to a buffer this frame owns and that
        // outlives the call — the two wide strings, the environment block, the
        // attribute list and the SID it points at (held by `self`), and the
        // two structs. `lpcommandline` is mutable because `CreateProcessW` may
        // write to it, and it is.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_SUSPENDED
                    | EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT
                    | DETACHED_PROCESS,
                environment.as_ptr().cast::<c_void>(),
                null(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `CreateProcessW` returned two fresh handles and nothing else
        // owns them.
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
        let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };

        // SAFETY: both handles are valid and owned here.
        if unsafe { AssignProcessToJobObject(raw(&self.job), raw(&process)) } == 0 {
            return Err(terminate(&process));
        }
        // SAFETY: the thread handle is valid; `u32::MAX` is the failure value.
        if unsafe { ResumeThread(raw(&thread)) } == u32::MAX {
            return Err(terminate(&process));
        }

        Ok(Confined {
            process,
            prepared: self,
        })
    }
}

/// A confined child and everything confining it.
pub(crate) struct Confined {
    process: OwnedHandle,
    prepared: Prepared,
}

impl Confined {
    /// Block until the child exits, and return its exit code.
    pub(crate) fn wait(&self) -> io::Result<u32> {
        // SAFETY: the handle is valid for as long as `self` is.
        if unsafe { WaitForSingleObject(raw(&self.process), INFINITE) } != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut code = 0u32;
        // SAFETY: as above, and `code` is a valid out-pointer.
        if unsafe { GetExitCodeProcess(raw(&self.process), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(code)
    }

    /// The container's SID, for a test to look for its entries after the
    /// child is gone.
    #[cfg(test)]
    fn sid_string(&self) -> String {
        self.prepared.container.sid_string()
    }
}

/// Kill a child that was created but could not be confined, and return why.
fn terminate(process: &OwnedHandle) -> io::Error {
    let why = io::Error::last_os_error();
    // SAFETY: the handle is valid; a failure to terminate a process that is
    // suspended and in no job leaves it suspended, which is still inert, and
    // the handle's drop does not resume it.
    unsafe { TerminateProcess(raw(process), 1) };
    why
}

fn raw(h: &OwnedHandle) -> HANDLE {
    h.as_raw_handle()
}

fn target_of(path: &Path) -> io::Result<Target> {
    Ok(if std::fs::metadata(path)?.is_dir() {
        Target::Directory
    } else {
        Target::File
    })
}

/// Taken once per daemon, so a container name never repeats one from an
/// earlier daemon that had this pid (`appcontainer::container_name`).
fn nonce() -> u64 {
    static NONCE: OnceLock<u64> = OnceLock::new();
    *NONCE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    })
}

fn next_seq() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// `s` as a NUL-terminated UTF-16 string, refusing an interior NUL — which
/// would silently end the string early and name a different object.
fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut w: Vec<u16> = s.encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "contains a NUL"));
    }
    w.push(0);
    Ok(w)
}

/// This process's environment with `envs` laid over it, as the
/// `CREATE_UNICODE_ENVIRONMENT` block: `KEY=VALUE\0` each, sorted by key
/// without case as the documentation asks, and a final `\0`.
fn environment_block(envs: &[(&str, &str)]) -> io::Result<Vec<u16>> {
    let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| !envs.iter().any(|(o, _)| k.eq_ignore_ascii_case(o)))
        .collect();
    vars.extend(envs.iter().map(|(k, v)| (OsString::from(k), OsString::from(v))));
    vars.sort_by_key(|(k, _)| k.to_ascii_uppercase());

    let mut block = Vec::new();
    for (k, v) in vars {
        let mut entry = k;
        entry.push("=");
        entry.push(v);
        block.extend(wide(&entry)?);
    }
    block.push(0);
    Ok(block)
}

// ── The container ────────────────────────────────────────────────────────────

/// An AppContainer profile and its SID, deleted when dropped.
struct Container {
    name: Vec<u16>,
    sid: PSID,
}

impl Container {
    fn create(name: &str) -> io::Result<Self> {
        let name = wide(OsStr::new(name))?;
        let mut sid: PSID = null_mut();
        // SAFETY: `name` is NUL-terminated and outlives the call; no
        // capabilities are passed, so the array pointer may be null with a
        // count of zero; `sid` is an out-pointer.
        let hr = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        // An existing profile under a name built to be unique is a leftover
        // whose entries are unknown, and reusing it would inherit them. It is
        // refused with the rest.
        if hr < 0 {
            // `HRESULT_FROM_WIN32` wraps a Win32 code as 0x8007xxxx; unwrap it
            // so the error's kind and message are the Win32 one's.
            let code = if (hr as u32) >> 16 == 0x8007 { hr & 0xffff } else { hr };
            return Err(io::Error::from_raw_os_error(code));
        }
        Ok(Self { name, sid })
    }

    #[cfg(test)]
    fn sid_string(&self) -> String {
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        let mut out: windows_sys::core::PWSTR = null_mut();
        // SAFETY: `self.sid` is valid; `out` is freed below with `LocalFree`.
        assert!(unsafe { ConvertSidToStringSidW(self.sid, &mut out) } != 0);
        let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
        unsafe { LocalFree(out as HLOCAL) };
        s
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // SAFETY: `sid` came from `CreateAppContainerProfile`, whose
        // documentation says to free it with `FreeSid`, and is freed once;
        // `name` is NUL-terminated.
        unsafe {
            FreeSid(self.sid);
            DeleteAppContainerProfile(self.name.as_ptr());
        }
    }
}

// ── The entries ──────────────────────────────────────────────────────────────

/// Every DACL edit this process makes, one at a time. See the module
/// documentation for what it does not cover.
static DACL_LOCK: Mutex<()> = Mutex::new(());

/// The paths an entry was added on, revoked when dropped.
struct Grants {
    sid: PSID,
    paths: Vec<PathBuf>,
}

impl Grants {
    /// Add every entry in `plan`, or none: a failure part-way revokes the ones
    /// already added before returning which path failed.
    fn apply(plan: &Plan, sid: PSID) -> Result<Self, (PathBuf, io::Error)> {
        let mut grants = Self {
            sid,
            paths: Vec::with_capacity(plan.aces.len()),
        };
        for ace in &plan.aces {
            set_entry(&ace.path, sid, GRANT_ACCESS, ace.mask, ace.inheritance)
                .map_err(|e| (ace.path.clone(), e))?;
            grants.paths.push(ace.path.clone());
        }
        Ok(grants)
    }
}

impl Drop for Grants {
    fn drop(&mut self) {
        for path in &self.paths {
            // Nothing to do with a failure but leave it: the entry names a SID
            // no process will carry again, since the name it derives from is
            // never reused.
            let _ = set_entry(path, self.sid, REVOKE_ACCESS, 0, appcontainer::NO_INHERITANCE);
        }
    }
}

/// Merge one entry for `sid` into `path`'s DACL — or, with `REVOKE_ACCESS`,
/// remove every entry for it.
fn set_entry(path: &Path, sid: PSID, mode: i32, mask: u32, inheritance: u32) -> io::Result<()> {
    let name = wide(path.as_os_str())?;
    let _serial = DACL_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `name` is NUL-terminated; the out-pointers are valid; the
    // returned DACL points into `descriptor`, which is freed after its last use
    // below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _descriptor = Local(descriptor);

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: mode,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let mut updated: *mut ACL = null_mut();
    // SAFETY: one entry, read from `entry`; `dacl` is the one just read (or
    // null, meaning no DACL); `updated` is an out-pointer freed below.
    let rc = unsafe { SetEntriesInAclW(1, &entry, dacl, &mut updated) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let _updated = Local(updated.cast());

    // SAFETY: `name` is NUL-terminated and `updated` is a valid ACL.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            updated,
            null(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// Memory the security APIs allocate and document as freed with `LocalFree`.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by the API that returned it, freed once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

// ── The job ──────────────────────────────────────────────────────────────────

fn create_job(limits: &appcontainer::JobLimits) -> io::Result<OwnedHandle> {
    // SAFETY: an anonymous job with default security.
    let h = unsafe { CreateJobObjectW(null(), null()) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh handle nothing else owns.
    let job = unsafe { OwnedHandle::from_raw_handle(h) };

    // SAFETY: zeroed is a valid "no limit" state for every other field.
    let mut extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    extended.BasicLimitInformation.LimitFlags = limits.flags;
    extended.BasicLimitInformation.ActiveProcessLimit = limits.active_processes;
    // SAFETY: the pointer and length describe `extended`, which outlives the call.
    let ok = unsafe {
        SetInformationJobObject(
            h,
            JobObjectExtendedLimitInformation,
            (&extended as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: limits.ui,
    };
    // SAFETY: as above, for `ui`.
    let ok = unsafe {
        SetInformationJobObject(
            h,
            JobObjectBasicUIRestrictions,
            (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

// ── The attribute list ───────────────────────────────────────────────────────

/// A `PROC_THREAD_ATTRIBUTE_LIST` holding one attribute: the container's SID
/// with no capabilities.
///
/// The list stores a pointer to the `SECURITY_CAPABILITIES` rather than a copy,
/// so that struct is boxed here and lives exactly as long as the list.
struct AttributeList {
    /// Points into `_buffer`, taken from it mutably once; the heap block does
    /// not move when this struct does.
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _buffer: Vec<usize>,
    _capabilities: Box<SECURITY_CAPABILITIES>,
}

impl AttributeList {
    fn with_container(sid: PSID) -> io::Result<Self> {
        let capabilities = Box::new(SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            // No capability, so no network: the whole of this sandbox's
            // network story is this null and the zero beside it.
            Capabilities: null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        });

        let mut size = 0usize;
        // SAFETY: a null list with a size out-pointer is the documented size
        // query; it fails with ERROR_INSUFFICIENT_BUFFER and sets `size`.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
        // `usize`-sized elements so the buffer is pointer-aligned.
        let mut buffer = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        let list: LPPROC_THREAD_ATTRIBUTE_LIST = buffer.as_mut_ptr().cast();
        // SAFETY: `buffer` is at least `size` bytes.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let this = Self {
            list,
            _buffer: buffer,
            _capabilities: capabilities,
        };
        // SAFETY: the list was initialised for one attribute; the value is the
        // boxed struct, which `this` keeps alive as long as the list.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                this.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&*this._capabilities as *const SECURITY_CAPABILITIES).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(this)
    }

    fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: initialised in `with_container`, deleted once.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

/// Measured against Windows, as `core/proc/tests/sandbox.rs` measures Linux:
/// each test spawns this test binary confined and asks the operating system
/// what it may do.
///
/// Here rather than in `tests/sandbox.rs` because the spawn they need is
/// crate-private until the escalation on
/// `TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there` is
/// answered, and an integration test can reach only the public surface. The
/// ops mirror that file's; where a Windows probe measures something other
/// than its Linux namesake, its comment says what and why.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    const EXIT_ALLOWED: u32 = 0;
    const EXIT_REFUSED: u32 = 3;
    /// A failure that was not a refusal, with the OS error in the low bits so
    /// the parent can print it — the child is given no stderr.
    const EXIT_UNCLEAR: u32 = 0x1000_0000;

    const PROBE_VAR: &str = "KOTTON_SANDBOX_PROBE";
    const PROBE_TEST: &str = "provider::sandbox::windows::tests::sandbox_probe";

    /// `ERROR_NOT_ENOUGH_QUOTA`, which is how a job's process limit refuses a
    /// `CreateProcess`.
    const ERROR_NOT_ENOUGH_QUOTA: i32 = 1816;

    #[test]
    fn sandbox_probe() {
        let Ok(op) = std::env::var(PROBE_VAR) else {
            return;
        };
        let code = match run_probe(&op) {
            Ok(()) => EXIT_ALLOWED,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => EXIT_REFUSED,
            Err(e) => EXIT_UNCLEAR | (e.raw_os_error().unwrap_or(0xffff) as u32 & 0x0fff_ffff),
        };
        std::process::exit(code as i32);
    }

    fn run_probe(op: &str) -> io::Result<()> {
        use std::net::{TcpStream, UdpSocket};
        match op.split_once(':') {
            Some(("read", path)) => std::fs::read(path).map(|_| ()),
            Some(("write", path)) => std::fs::write(path, b"probe"),
            Some(("overwrite", path)) => {
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)?
                    .write_all(b"probe")
            }
            // To a listener the parent holds, so a success is a connection
            // that arrived, not one that merely did not fail.
            Some(("tcp", port)) => TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap()))
                .map(|_| ()),
            Some(("udp", port)) => {
                let s = UdpSocket::bind("127.0.0.1:0")?;
                s.send_to(b"probe", ("127.0.0.1", port.parse::<u16>().unwrap()))
                    .map(|_| ())
            }
            Some(("open-process", pid)) => {
                use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};
                // SAFETY: a plain query; the handle, if any, is closed at once.
                let h = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid.parse().unwrap()) };
                if h.is_null() {
                    return Err(io::Error::last_os_error());
                }
                drop(unsafe { OwnedHandle::from_raw_handle(h) });
                Ok(())
            }
            None => match op {
                // Windows' private pair: an anonymous pipe, joined to itself
                // and nameable by nothing. Allowed on purpose, as `socketpair`
                // is on Linux.
                "pair" => std::io::pipe().map(|_| ()),
                // Whether the child was handed the daemon's console. A null or
                // invalid standard handle is the answer wanted, reported as the
                // refusal it amounts to.
                "console" => {
                    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
                    use windows_sys::Win32::System::Console::{
                        GetConsoleWindow, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
                        STD_OUTPUT_HANDLE,
                    };
                    // SAFETY: plain queries with no pointers.
                    let handed = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
                        .into_iter()
                        .map(|which| unsafe { GetStdHandle(which) })
                        .any(|h| !h.is_null() && h != INVALID_HANDLE_VALUE)
                        || !unsafe { GetConsoleWindow() }.is_null();
                    if handed {
                        Ok(())
                    } else {
                        Err(io::Error::from(ErrorKind::PermissionDenied))
                    }
                }
                // The job's one-process limit. A refusal of it is a quota, not
                // an access check, and is reported as the refusal it is.
                "spawn" => match std::process::Command::new(std::env::current_exe()?)
                    .arg("--list")
                    .status()
                {
                    Err(e) if e.raw_os_error() == Some(ERROR_NOT_ENOUGH_QUOTA) => {
                        Err(io::Error::from(ErrorKind::PermissionDenied))
                    }
                    other => other.map(|_| ()),
                },
                other => panic!("unknown probe {other}"),
            },
            Some((other, _)) => panic!("unknown probe {other}"),
        }
    }

    fn test_binary() -> PathBuf {
        std::env::current_exe().expect("a test binary knows its own path")
    }

    fn bare() -> Profile {
        Profile::nothing("sandbox-test").executing(test_binary())
    }

    fn spawn(profile: &Profile, op: &str) -> io::Result<Confined> {
        let prepared = Prepared::for_profile(profile).expect("the profile is enforceable here");
        prepared.spawn(
            &test_binary(),
            &["--exact", PROBE_TEST, "--nocapture", "--test-threads=1"],
            &[(PROBE_VAR, op)],
        )
    }

    /// The probe's exit code, whatever it is.
    fn run(profile: Profile, op: &str) -> u32 {
        let child = spawn(&profile, op).expect(
            "the confined child started; a failure here is the sandbox refusing the spawn itself",
        );
        child.wait().expect("the child can be waited on")
    }

    /// The probe's exit code, which must be allowed or refused.
    fn probe(profile: Profile, op: &str) -> u32 {
        let code = run(profile, op);
        assert!(
            code & EXIT_UNCLEAR == 0,
            "probe {op} failed with OS error {} rather than being allowed or refused",
            code & 0x0fff_ffff
        );
        code
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kotton-sandbox-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        std::fs::write(dir.join("file"), b"contents").expect("scratch file");
        dir
    }

    // ── The network ──────────────────────────────────────────────────────────
    //
    // Linux refuses at `socket(2)`. Windows refuses the traffic: a socket can
    // be made in an AppContainer, and what the missing capabilities withhold is
    // any connection through it. So these measure the property — nothing
    // arrives — against a listener this process holds on loopback, which an
    // AppContainer is denied unless exempted. What they cannot measure on a
    // machine with no route out is the internet itself; that is the same
    // capability (`internetClient`) not being granted.

    #[test]
    fn a_confined_process_cannot_connect_to_a_tcp_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        // Which error a refused connect surfaces as is the platform's to
        // choose; what is asserted is that it did not succeed and nothing
        // arrived.
        let code = run(bare(), &format!("tcp:{port}"));
        assert_ne!(code, EXIT_ALLOWED, "the confined process connected");
        assert!(
            listener.accept().is_err(),
            "a connection from the confined process arrived (the probe exited {code:#x})"
        );
    }

    #[test]
    fn a_confined_process_cannot_send_a_datagram() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        let code = run(bare(), &format!("udp:{port}"));
        let mut buf = [0u8; 16];
        assert!(
            socket.recv_from(&mut buf).is_err(),
            "a datagram from the confined process arrived (the probe exited {code:#x})"
        );
    }

    #[test]
    fn a_confined_process_may_still_make_a_pair_with_itself() {
        assert_eq!(probe(bare(), "pair"), EXIT_ALLOWED);
    }

    /// The one handle route `bInheritHandles` does not close: a console child
    /// joins its parent's console. `DETACHED_PROCESS` withholds it.
    #[test]
    fn a_confined_process_has_no_console() {
        assert_eq!(probe(bare(), "console"), EXIT_REFUSED);
    }

    // ── Other processes ──────────────────────────────────────────────────────

    /// The Windows form of Linux's `ptrace` and `process_vm_readv` refusal: the
    /// daemon's DACL does not name the container's SID.
    #[test]
    fn a_confined_process_cannot_open_the_process_that_spawned_it() {
        let op = format!("open-process:{}", std::process::id());
        assert_eq!(probe(bare(), &op), EXIT_REFUSED);
    }

    #[test]
    fn a_confined_process_cannot_start_another() {
        assert_eq!(probe(bare(), "spawn"), EXIT_REFUSED);
    }

    // ── The filesystem ───────────────────────────────────────────────────────

    #[test]
    fn a_path_outside_every_grant_is_unreadable() {
        let file = scratch("ungranted").join("file");
        assert!(std::fs::read(&file).is_ok());
        assert_eq!(probe(bare(), &format!("read:{}", file.display())), EXIT_REFUSED);
    }

    #[test]
    fn a_granted_path_is_readable_and_still_not_writable() {
        let dir = scratch("read-grant");
        let file = dir.join("file");
        let profile = || bare().reading(&dir);
        assert_eq!(probe(profile(), &format!("read:{}", file.display())), EXIT_ALLOWED);
        assert_eq!(probe(profile(), &format!("write:{}", file.display())), EXIT_REFUSED);
        assert_eq!(probe(profile(), &format!("overwrite:{}", file.display())), EXIT_REFUSED);
    }

    #[test]
    fn a_write_grant_reaches_beneath_itself_and_no_further() {
        let granted = scratch("write-grant");
        let neighbour = scratch("write-neighbour");
        let profile = || bare().writing(&granted);
        assert_eq!(
            probe(profile(), &format!("write:{}", granted.join("new").display())),
            EXIT_ALLOWED
        );
        assert_eq!(
            probe(profile(), &format!("write:{}", neighbour.join("new").display())),
            EXIT_REFUSED
        );
        let sideways = granted
            .join("..")
            .join(neighbour.file_name().unwrap())
            .join("file");
        assert_eq!(probe(profile(), &format!("read:{}", sideways.display())), EXIT_REFUSED);
    }

    // ── The refusals that happen before a spawn ──────────────────────────────

    /// The Windows statement of `tests/sandbox.rs`'s
    /// `a_profile_that_grants_nothing_cannot_even_start_the_program`. There,
    /// `execve` is denied inside the forked child and the spawn returns
    /// `PermissionDenied`. Here there is no child to deny it in: the kernel
    /// checks the container's token against the image while creating the
    /// process, and `CreateProcessW` itself fails with `ERROR_ACCESS_DENIED`,
    /// which is `PermissionDenied`. Same assertion, one step earlier — and, as
    /// there, the test that fails if the container was silently not attached,
    /// since an unconfined child reads its own image without an entry.
    #[test]
    fn a_profile_that_grants_nothing_cannot_even_start_the_program() {
        let err = match spawn(&Profile::nothing("no-grants"), "pair") {
            Ok(child) => panic!(
                "a program with no grant on its own image was created (it exited {:?})",
                child.wait()
            ),
            Err(e) => e,
        };
        assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
    }

    #[test]
    fn a_grant_on_a_path_that_does_not_exist_is_refused_before_the_spawn() {
        let missing = Path::new("C:\\nonexistent\\kotton\\sandbox\\grant");
        match Prepared::for_profile(&bare().reading(missing)) {
            Err(SandboxError::NoSuchGrant { path, purpose }) => {
                assert_eq!(path, missing);
                assert_eq!(purpose, "sandbox-test");
            }
            Err(other) => panic!("expected NoSuchGrant, got {other}"),
            Ok(_) => panic!("a grant naming nothing was prepared"),
        }
    }

    /// Entries are the one thing this sandbox leaves on the person's disk, so
    /// their removal is measured rather than assumed.
    #[test]
    fn the_entries_are_gone_once_the_child_is() {
        let dir = scratch("revoked");
        let child = spawn(&bare().reading(&dir), "pair").expect("spawned");
        let sid = child.sid_string();
        assert!(dacl_names(&dir, &sid), "the grant was never written");
        assert_eq!(child.wait().unwrap(), EXIT_ALLOWED);
        drop(child);
        assert!(!dacl_names(&dir, &sid), "{sid} still has an entry on {}", dir.display());
    }

    /// Whether `path`'s DACL, in SDDL, names `sid`.
    fn dacl_names(path: &Path, sid: &str) -> bool {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
        };
        let name = wide(path.as_os_str()).unwrap();
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let rc = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);
        let _sd = Local(sd);
        let mut sddl: windows_sys::core::PWSTR = null_mut();
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                null_mut(),
            )
        };
        assert!(ok != 0);
        let _sddl = Local(sddl.cast());
        let len = (0..).take_while(|&i| unsafe { *sddl.add(i) } != 0).count();
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sddl, len) }).contains(sid)
    }
}
