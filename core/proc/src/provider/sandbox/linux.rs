// SPDX-License-Identifier: AGPL-3.0-or-later
// The narrower `cfg` is on this module's declaration in `mod.rs` and is the real
// one. This inner attribute is true as well, and is here because `windows-check`
// reads a file's first lines and cannot see a parent's `mod` line — the
// convention that check names for a split module.
#![cfg(unix)]

//! Linux: Landlock for what may be opened, seccomp-BPF for the calls that make
//! an endpoint.
//!
//! # Why two mechanisms and not one
//!
//! Landlock is an allow-list by construction — a ruleset names the access
//! rights it *handles*, grants some of them beneath particular inodes, and
//! everything else under those rights is denied for the rest of the process's
//! life and every child it forks. That is exactly the shape a profile wants for
//! the filesystem, and it is why the filesystem half of this file has no
//! deny-list in it at all.
//!
//! It is not that shape for the network. Landlock's network rights (ABI 4)
//! cover `bind` and `connect` over TCP and nothing else: no UDP, no raw
//! sockets, no `AF_UNIX`. Handling them and granting none of them is worth
//! doing and is done below, but a process that can still `socket(AF_INET,
//! SOCK_DGRAM)` is not a process with no network. So the calls that make an
//! endpoint are refused with a seccomp filter: `socket(2)` and the calls that
//! use one (`connect`, `bind`, `listen`, `accept`), and `io_uring_setup`,
//! `io_uring_enter` and `io_uring_register`, because a ring creates and
//! connects sockets inside the kernel where a filter on syscall numbers never
//! sees them. That second route is not hypothetical: it was open until
//! 2026-09-23, when a probe measured a confined process sending a datagram
//! through it (`DEC-0074`, "io_uring was a second door";
//! [`denied_syscalls`] has the detail). The one socket call allowed is
//! `socketpair(AF_UNIX, …)`, which reaches nothing outside the process. The
//! filter answers one question — *which address families is this process
//! granted?* — and the answer today is none, and [`crate::sandbox::Profile`]
//! has no way to say otherwise.
//!
//! A deny-list of syscalls is only as good as the enumeration of ways into the
//! kernel, which is why the `io_uring` route could be missed. What stands behind
//! it is measurement, not the list: `core/proc/tests/sandbox.rs` asks the kernel
//! whether each route is closed, including the one found late.
//! The allow-list form, built from a measured trace of each guest's calls, is filed as
//! `TASK-the-syscall-filter-is-a-deny-list-and-a-route-nobody-listed-is-allowed`.
//!
//! # Prepared in the parent, applied in the child
//!
//! Everything that can fail — parsing the profile, opening the granted paths,
//! building the ruleset, compiling the filter — happens in
//! [`Prepared::for_profile`], in the daemon, where a failure is a `Result` a
//! caller reads and refuses on. What runs between `fork` and `execve` is three
//! syscalls against things already in hand.
//!
//! That order is the point rather than an optimisation. The child never
//! executes an instruction unconfined, and the confined binaries — `kinferd`,
//! `kotton-runner` — contain no sandbox code at all, which is the only
//! arrangement where the sandbox does not depend on the confined process
//! cooperating.
//!
//! # What this does not do
//!
//! - **It does not isolate GPU memory.** `DEC-0074` §3 says so in as many
//!   words, and says it is a second mechanism. Nothing here should be read as
//!   covering it.
//! - **It does not close descriptors the parent leaked.** Landlock governs
//!   `open`, not an fd that is already open, so a descriptor inherited from the
//!   daemon crosses the boundary intact. Rust's own `O_CLOEXEC` discipline is
//!   what stands there today, which is a property of the parent's code rather
//!   than of this sandbox —
//!   `TASK-the-sandbox-cannot-close-what-the-parent-leaked`.

use crate::sandbox::{Profile, Reach, SandboxError};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

/// Landlock and seccomp are both present in every kernel this builds for; a
/// kernel too old for Landlock is caught at [`Prepared::for_profile`] and
/// refused there, by name.
pub(crate) const AVAILABLE: bool = true;

// ── Landlock uapi ────────────────────────────────────────────────────────────
//
// Written out rather than taken as a dependency. It is three syscall numbers
// and two structs whose layout is kernel ABI and therefore cannot change, and
// the crate that would supply them would sit in the dependency closure of the
// daemon that spawns the thing it confines. Numbers are identical on every
// architecture: Landlock arrived after the generic syscall table.

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_long = 1;

/// `struct landlock_ruleset_attr`. Three `__u64`s as of ABI 6; the kernel is
/// told how many of them it is being given through the `size` argument, which
/// is how one struct serves every ABI.
#[repr(C)]
#[derive(Default)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr`, which the kernel declares packed.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

// Filesystem access rights, ABI 1 unless noted.
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13; // ABI 2
const FS_TRUNCATE: u64 = 1 << 14; // ABI 3
const FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5

/// Rights that only mean anything on a directory. Landlock rejects a rule that
/// names one of them on a regular file, so a grant is masked by what its target
/// actually is.
const FS_DIRECTORY_ONLY: u64 = FS_READ_DIR
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_CHAR
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SOCK
    | FS_MAKE_FIFO
    | FS_MAKE_BLOCK
    | FS_MAKE_SYM
    | FS_REFER;

// Network access rights, ABI 4. Handled, granted to nothing.
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;

// Scopes, ABI 6. A scope is not a right that can be granted — it says the
// process may not reach *out* of its own domain that way. Abstract `AF_UNIX`
// names have no filesystem path, so nothing else here can deny them; signals
// are how a confined process would otherwise reach a sibling of the same user.
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

/// Where a dynamically linked program's loader looks.
///
/// Read and execute only, and only the directories that exist. Without it the
/// `execve` this sandbox is applied before is itself the first thing denied:
/// the kernel loads the interpreter, and the interpreter opens libc.
///
/// It is a real widening and it is stated here rather than hidden in a caller's
/// profile: a confined process can read the machine's public system libraries.
/// It cannot read the person's data, cannot write anywhere, and cannot reach
/// anything it was not handed. Removing even this is possible — a statically
/// linked child needs none of it — and is a property of how the binaries are
/// built, not of this file.
const LOADER_PATHS: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
];

/// The Landlock ABI this kernel speaks, or `None` if it does not speak it.
///
/// SAFETY: the version query takes no pointer — a null attribute with size 0
/// and this flag is precisely how the kernel is asked.
#[allow(unsafe_code)]
fn landlock_abi() -> Option<u32> {
    let r = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if r > 0 {
        Some(r as u32)
    } else {
        None
    }
}

/// Create a ruleset from `attr`, telling the kernel how many of its fields
/// this build filled in.
///
/// SAFETY: `attr` outlives the call by construction — it is borrowed — and
/// `size` bounds what the kernel may read out of it.
#[allow(unsafe_code)]
fn create_ruleset(attr: &RulesetAttr, size: usize) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, attr, size, 0u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a fresh descriptor and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// What a [`Reach`] means in Landlock's rights, before masking by ABI and by
/// whether the target is a directory.
fn rights_for(reach: Reach) -> u64 {
    match reach {
        Reach::Read => FS_READ_FILE | FS_READ_DIR,
        // Deliberately not `MAKE_CHAR`, `MAKE_BLOCK`, `MAKE_SOCK` or
        // `MAKE_FIFO`: a data directory needs files and directories, and a
        // confined process has no business minting a node of another kind
        // inside it.
        Reach::Write => {
            FS_READ_FILE
                | FS_WRITE_FILE
                | FS_READ_DIR
                | FS_REMOVE_FILE
                | FS_REMOVE_DIR
                | FS_MAKE_REG
                | FS_MAKE_DIR
                | FS_MAKE_SYM
                | FS_TRUNCATE
                | FS_REFER
        }
        Reach::Execute => FS_EXECUTE | FS_READ_FILE | FS_READ_DIR,
        Reach::Device => FS_READ_FILE | FS_WRITE_FILE | FS_IOCTL_DEV,
    }
}

/// The rights this kernel will accept in `handled_access_fs`.
fn handled_fs(abi: u32) -> u64 {
    let mut m = FS_EXECUTE
        | FS_WRITE_FILE
        | FS_READ_FILE
        | FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM;
    if abi >= 2 {
        m |= FS_REFER;
    }
    if abi >= 3 {
        m |= FS_TRUNCATE;
    }
    if abi >= 5 {
        m |= FS_IOCTL_DEV;
    }
    m
}

/// The confinement, built and ready. Held by the `pre_exec` closure, so it
/// lives exactly as long as the `Command` that will apply it.
struct Prepared {
    ruleset: OwnedFd,
    filter: Box<[SockFilter]>,
}

impl Prepared {
    fn for_profile(profile: &Profile) -> Result<Self, SandboxError> {
        let purpose = || profile.purpose().to_string();

        let abi = landlock_abi().ok_or_else(|| SandboxError::Unavailable {
            purpose: purpose(),
            reason: "this kernel has no Landlock, so a filesystem grant cannot be enforced; \
                     Kotton does not spawn a guest it cannot confine (DEC-0074 §1)"
                .to_string(),
        })?;

        let attr = RulesetAttr {
            handled_access_fs: handled_fs(abi),
            handled_access_net: if abi >= 4 {
                NET_BIND_TCP | NET_CONNECT_TCP
            } else {
                0
            },
            scoped: if abi >= 6 {
                SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
            } else {
                0
            },
        };
        // The kernel reads as many fields as `size` says it was given, so an
        // older kernel is told about the struct it knows and nothing more.
        let size = if abi >= 6 {
            24
        } else if abi >= 4 {
            16
        } else {
            8
        };

        let ruleset = create_ruleset(&attr, size).map_err(|source| SandboxError::Refused {
            purpose: purpose(),
            step: "creating the ruleset",
            source,
        })?;

        for grant in profile.grants() {
            add_path_rule(&ruleset, &grant.path, rights_for(grant.reach) & attr.handled_access_fs)
                .map_err(|e| grant_error(profile, &grant.path, e))?;
        }
        for path in LOADER_PATHS.iter().map(Path::new) {
            if !path.exists() {
                continue;
            }
            add_path_rule(
                &ruleset,
                path,
                rights_for(Reach::Execute) & attr.handled_access_fs,
            )
            .map_err(|e| grant_error(profile, path, e))?;
        }

        Ok(Self {
            ruleset,
            filter: socket_door_filter(),
        })
    }

    /// The whole of what runs between `fork` and `execve`.
    ///
    /// Three syscalls, no allocation, no locks, no `std` beyond an errno
    /// wrapper — the closure runs in a forked child of a multi-threaded
    /// process, where anything else is undefined behaviour waiting for a
    /// schedule that lands badly.
    ///
    /// SAFETY, for all three: `prctl` takes a constant option and no pointer;
    /// the ruleset descriptor is owned by `self`, which the closure holds; and
    /// `prog` points at `self.filter`, which outlives the call. The seccomp
    /// flags are 0 because a forked child has one thread and there is nothing
    /// to synchronise a filter across.
    #[allow(unsafe_code)]
    fn apply(&self) -> io::Result<()> {
        // seccomp refuses a filter from a process that could still gain
        // privilege through a setuid `execve`, and Landlock is inherited
        // across `execve` only under the same promise.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, self.ruleset.as_raw_fd(), 0u32) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let prog = libc::sock_fprog {
            len: self.filter.len() as u16,
            filter: self.filter.as_ptr() as *mut libc::sock_filter,
        };
        if unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0usize,
                &prog as *const libc::sock_fprog,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn grant_error(profile: &Profile, path: &Path, e: io::Error) -> SandboxError {
    if e.kind() == io::ErrorKind::NotFound {
        SandboxError::NoSuchGrant {
            purpose: profile.purpose().to_string(),
            path: path.to_path_buf(),
        }
    } else {
        SandboxError::Refused {
            purpose: profile.purpose().to_string(),
            step: "adding a path rule",
            source: e,
        }
    }
}

/// Grant `rights` beneath `path`.
///
/// `O_PATH` because the rule needs the inode and nothing else — the parent does
/// not read the file, and a grant on a write-only device should not require
/// opening it for read.
fn add_path_rule(ruleset: &OwnedFd, path: &Path, rights: u64) -> io::Result<()> {
    let parent = open_path(path)?;
    let is_dir = is_directory(&parent)?;

    let allowed = if is_dir {
        rights
    } else {
        rights & !FS_DIRECTORY_ONLY
    };
    if allowed == 0 {
        // Nothing left to grant is a caller error, not a silent no-op: a rule
        // that grants nothing reads in the profile as reach the child does not
        // have.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the grant leaves no access once masked to what this path can carry",
        ));
    }

    add_rule(ruleset, allowed, &parent)
}

/// Open `path` for its inode alone.
///
/// `O_PATH` because the rule needs the inode and nothing else — the parent does
/// not read the file, and a grant on a write-only device should not require
/// opening it for read.
///
/// SAFETY: `c` is a NUL-terminated path that outlives the call, and the
/// descriptor the kernel returns is unowned until this wraps it.
#[allow(unsafe_code)]
fn open_path(path: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL"))?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether the descriptor names a directory.
///
/// SAFETY: `fd` is a valid descriptor, and `AT_EMPTY_PATH` with an empty name
/// stats the descriptor itself — the only thing `O_PATH` permits.
#[allow(unsafe_code)]
fn is_directory(fd: &OwnedFd) -> io::Result<bool> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(fd.as_raw_fd(), c"".as_ptr(), &mut stat, libc::AT_EMPTY_PATH) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// Grant `allowed` beneath the inode `parent` names.
///
/// SAFETY: `attr` outlives the call and matches the kernel's packed layout.
#[allow(unsafe_code)]
fn add_rule(ruleset: &OwnedFd, allowed: u64, parent: &OwnedFd) -> io::Result<()> {
    let attr = PathBeneathAttr {
        allowed_access: allowed,
        parent_fd: parent.as_raw_fd(),
    };
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &attr,
            0u32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ── The socket door ──────────────────────────────────────────────────────────

/// `struct sock_filter`, spelled here so the program can be built in a `const`
/// -ish style and compared in a test without `libc`'s type appearing in every
/// signature. Layout is identical and it is transmuted by pointer at the one
/// place the kernel is handed it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// `seccomp_data`: `nr` at 0, `arch` at 4, `instruction_pointer` at 8, `args`
/// at 16. Little-endian, so the low word of `args[0]` is at 16.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0: u32 = 16;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Deny with `EPERM` rather than killing.
///
/// A refusal the caller can see is a refusal a caller can report, and every
/// syscall in this filter is one a library may reasonably probe for and fall
/// back from — `getaddrinfo`, a metrics exporter, a runtime that checks whether
/// it can open a socket before deciding not to. Killing turns each of those
/// into a crash with no explanation, and the property being defended is that
/// the call does not *succeed*.
fn deny() -> SockFilter {
    stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32))
}

/// The syscalls that create or name an endpoint, the three that hand the kernel
/// a queue of work to do on the caller's behalf, and the three that reach into
/// another process.
///
/// `socket(2)` is the only *syscall* that creates a socket, and `connect`,
/// `bind`, `listen` and `accept` are here because a descriptor inherited from
/// the parent is not covered by the first one — the sandbox does not yet close
/// what the parent leaked
/// (`TASK-the-sandbox-cannot-close-what-the-parent-leaked`).
///
/// `socket(2)` is not the only *way*. `io_uring` performs operations inside the
/// kernel without a syscall per operation, so a filter keyed on syscall numbers
/// never sees them: `IORING_OP_SOCKET` and `IORING_OP_CONNECT` create and
/// connect a socket that seccomp has refused at `socket(2)`. Measured
/// 2026-09-23 on Linux 6.18, before these three were denied — a confined
/// process opened an `AF_INET` socket through the ring and sent a datagram a
/// listener received, and opened an `AF_UNIX` one and connected to a pathname
/// socket outside every grant (`DEC-0074`, "io_uring was a second door").
/// Denying `io_uring_setup` alone would do, since a ring cannot be had any
/// other way; `enter` and `register` are denied as well so that a ring leaked
/// by a parent is not a way round it either.
///
/// `ptrace` and the two `process_vm_*` calls are not network. They are here
/// because Landlock's signal scope (ABI 6) stops a confined process signalling
/// a sibling of the same user and stops nothing about reading its memory, and a
/// guest that can attach to the daemon that spawned it is not confined at all.
fn denied_syscalls() -> Vec<u32> {
    let mut v = vec![
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept4,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
    ];
    // `accept` is x86-64 only; aarch64's syscall table has `accept4` alone.
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_accept);
    v.into_iter().map(|n| n as u32).collect()
}

/// The filter: wrong architecture is fatal, the denied calls return `EPERM`,
/// `socketpair` is allowed for `AF_UNIX` alone, everything else passes.
///
/// `socketpair(AF_UNIX, …)` is not a network call and is allowed with its
/// family checked. It returns two ends of a channel joined to each other and to
/// nothing else — it cannot be named, connected to, or reached from outside the
/// process — and Tokio's own signal and process machinery builds one. Refusing
/// it would buy nothing and would make the sandbox's first effect be breaking
/// the runtime of the thing it confines. Any other family goes to `EPERM` with
/// the rest.
fn socket_door_filter() -> Box<[SockFilter]> {
    // The prologue checks the architecture and then loads the syscall number.
    // A filter built for another architecture matches nothing, so a syscall
    // arriving under one is not a call to reason about — it is the filter not
    // applying. That is fatal rather than an errno.
    let mut p = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    ];

    // The x32 ABI reaches the same kernel with a different numbering, so a
    // filter that checked numbers alone could be walked straight through it.
    #[cfg(target_arch = "x86_64")]
    {
        const X32_SYSCALL_BIT: u32 = 0x4000_0000;
        p.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    // Two instructions each, so there is no jump arithmetic to get wrong: the
    // comparison either falls into the refusal below it or steps over it.
    for nr in denied_syscalls() {
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        p.push(deny());
    }

    // Last, because reading an argument clobbers the accumulator that every
    // comparison above it needs.
    p.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_socketpair as u32,
        0,
        3,
    ));
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
    p.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::AF_UNIX as u32,
        1,
        0,
    ));
    p.push(deny());
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    p.into_boxed_slice()
}

// ── The entry point ──────────────────────────────────────────────────────────

pub(crate) fn confine(
    cmd: &mut tokio::process::Command,
    profile: &Profile,
) -> Result<(), SandboxError> {
    let prepared = Prepared::for_profile(profile)?;
    install(cmd, prepared);
    Ok(())
}

/// Hang the confinement on the command, to be applied between `fork` and
/// `execve`.
///
/// SAFETY: the closure runs in the forked child before `execve`, where only
/// async-signal-safe work is permitted. [`Prepared::apply`] is three syscalls
/// and an errno read: no allocation, no lock, no reentrant `std`.
#[allow(unsafe_code)]
fn install(cmd: &mut tokio::process::Command, prepared: Prepared) {
    unsafe {
        cmd.pre_exec(move || prepared.apply());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel this suite runs on must be able to enforce a profile, or
    /// every confinement test below is measuring its own absence.
    #[test]
    fn the_kernel_speaks_landlock() {
        assert!(
            landlock_abi().is_some(),
            "no Landlock on this kernel, so nothing in core/proc's sandbox is being exercised"
        );
    }

    #[test]
    fn a_rule_never_asks_for_a_right_the_ruleset_does_not_handle() {
        // Landlock returns EINVAL for a rule outside `handled_access_fs`, so a
        // right this masking missed would surface as a refused spawn rather
        // than as a wider grant. Checked here anyway, at every ABI the masking
        // distinguishes, because a refused spawn is a bad way to find out.
        for abi in 1..=7u32 {
            let handled = handled_fs(abi);
            for reach in [Reach::Read, Reach::Write, Reach::Execute, Reach::Device] {
                let masked = rights_for(reach) & handled;
                assert_eq!(
                    masked & !handled,
                    0,
                    "{reach:?} asks for a right ABI {abi} does not handle"
                );
            }
        }
    }

    #[test]
    fn truncate_and_ioctl_are_dropped_on_a_kernel_that_lacks_them() {
        assert_eq!(handled_fs(2) & FS_TRUNCATE, 0);
        assert_eq!(handled_fs(4) & FS_IOCTL_DEV, 0);
        assert_eq!(handled_fs(5) & FS_IOCTL_DEV, FS_IOCTL_DEV);
        assert_eq!(handled_fs(1) & FS_REFER, 0);
        assert_eq!(handled_fs(2) & FS_REFER, FS_REFER);
    }

    #[test]
    fn the_filter_ends_in_a_verdict_and_every_jump_lands_inside_it() {
        let f = socket_door_filter();
        let len = f.len();
        for (i, insn) in f.iter().enumerate() {
            if insn.code & 0x07 == BPF_JMP {
                assert!(
                    (i + 1 + insn.jt as usize) < len,
                    "instruction {i} jumps past the end of the program"
                );
                assert!(
                    (i + 1 + insn.jf as usize) < len,
                    "instruction {i} jumps past the end of the program"
                );
            }
        }
        assert_eq!(
            f[len - 1].code,
            BPF_RET | BPF_K,
            "the program must end in a verdict"
        );
    }

    #[test]
    fn every_denied_syscall_is_reachable_in_the_filter() {
        let f = socket_door_filter();
        for nr in denied_syscalls() {
            assert!(
                f.iter().any(|i| i.code == (BPF_JMP | BPF_JEQ | BPF_K) && i.k == nr),
                "syscall {nr} is in the deny list and not in the filter"
            );
        }
    }
}
