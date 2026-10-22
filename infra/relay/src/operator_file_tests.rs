// SPDX-License-Identifier: AGPL-3.0-or-later
//! The operators' file belongs to whoever owns the state directory, whoever typed
//! the verb (`TASK-a-relay-operator-verb-typed-as-root-locks-every-operator-out-until-the-relay-restarts`).
//!
//! The relay runs as its own user and reads `operators` on every operator request;
//! the verbs that write it are typed at a terminal, by root as often as not. These
//! tests stand a state directory up as another uid and type the verbs as root, and
//! as a third uid that can write the directory and is not its owner.
//!
//! They need root to own a directory as another uid. Run as anyone else they say
//! so on stderr and prove nothing; the relay's `bind-check` line runs them as root
//! in the build container.
//!
//! Unix-only whole: uids, `chown` and mode bits have no Windows meaning. The guard
//! is this file's own, where `cargo xtask windows-check` reads it.

#![cfg(unix)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::admission;

/// Stands in for `kotton-relay`, the user the unit runs the relay as.
const OWNER: u32 = 64100;
/// Someone else on the host who can write the directory and does not own it.
const STRANGER: u32 = 64200;
/// Where the parent tells the child which directory to type the verb at.
const CHILD_DIR: &str = "KOTTON_RELAY_TEST_STRANGER_DIR";
/// Which verb [`the_owner_types`] types, by its name in [`verb`].
const CHILD_VERB: &str = "KOTTON_RELAY_TEST_VERB";

const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// The operator the relay is created for, so the set [`KEY`] is enrolled into
/// and revoked from is never empty (RFC-0084 V19).
const FIRST: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// A state directory owned by [`OWNER`] with `mode`, or `None` when this process
/// cannot give a directory away — it is not root.
fn owned_dir(mode: u32) -> Option<PathBuf> {
    let d = std::env::temp_dir().join(format!("kotton-relay-owner-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&d).unwrap();
    if let Err(e) = std::os::unix::fs::chown(&d, Some(OWNER), Some(OWNER)) {
        let _ = std::fs::remove_dir_all(&d);
        eprintln!("skipped: giving a directory to uid {OWNER} needs root ({e})");
        return None;
    }
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
    Some(d)
}

/// `cat` as `uid`: whether the relay's own user can read what the verb wrote.
fn read_as(uid: u32, path: &Path) -> Result<String, String> {
    let out = Command::new("setpriv")
        .args([
            &format!("--reuid={uid}"),
            &format!("--regid={uid}"),
            "--clear-groups",
            "cat",
        ])
        .arg(path)
        .output()
        .expect("setpriv runs");
    if out.status.success() {
        Ok(String::from_utf8(out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn assert_the_owners(path: &Path) {
    let m = std::fs::metadata(path).unwrap();
    assert_eq!(
        (m.uid(), m.gid(), m.mode() & 0o777),
        (OWNER, OWNER, 0o600),
        "{} is not the directory owner's, 0600",
        path.display()
    );
}

#[test]
fn a_verb_typed_as_root_leaves_the_operators_file_the_directory_owners() {
    let Some(dir) = owned_dir(0o700) else { return };
    let file = dir.join("operators");

    assert!(root_types(&dir, "create").unwrap().starts_with("kotton-instance:relay:"));
    assert_the_owners(&file);
    assert_the_owners(&dir.join("identity.key"));
    assert_eq!(read_as(OWNER, &file).unwrap(), format!("{FIRST}\n"));

    assert_eq!(root_types(&dir, "enrol").unwrap(), "enrolled");
    assert_the_owners(&file);
    assert_eq!(read_as(OWNER, &file).unwrap(), format!("{FIRST}\n{KEY}\n"));

    assert_eq!(root_types(&dir, "revoke <key>").unwrap(), "revoked 1");
    assert_the_owners(&file);
    assert_eq!(read_as(OWNER, &file).unwrap(), format!("{FIRST}\n"));

    assert_eq!(root_types(&dir, "enrol").unwrap(), "enrolled");
    assert_eq!(root_types(&dir, "revoke --all").unwrap(), "revoked 1");
    assert_the_owners(&file);
    assert_eq!(read_as(OWNER, &file).unwrap(), format!("{KEY}\n"), "every one but the key kept");

    let mut left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["identity.key", "instance.lock", "operators"], "a temporary file was left behind");
    let _ = std::fs::remove_dir_all(dir);
}

/// The verb named `name`, at [`KEY`].
fn verb(name: &str) -> admission::Verb<'static> {
    match name {
        "create" => admission::Verb::Create { operator: FIRST, advertise: "" },
        "enrol" => admission::Verb::Enrol(KEY),
        "revoke <key>" => admission::Verb::Revoke(KEY),
        "revoke --all" => admission::Verb::RevokeAllBut(KEY),
        _ => unreachable!("{name}"),
    }
}

/// `name` typed by this process at `dir`, where it must not be handed to anyone.
fn types_here(dir: &Path, name: &str) -> anyhow::Result<String> {
    admission::type_verb(dir, verb(name), || {
        unreachable!("{name} at {} was handed to the owner", dir.display())
    })
}

/// `name` typed as root at `dir`, the way the terminal types it: when the
/// directory is another user's, [`admission::type_verb`] types it again as them,
/// here by [`the_owner_types`] where the binary would run itself.
fn root_types(dir: &Path, name: &str) -> Result<String, String> {
    admission::type_verb(dir, verb(name), || {
        let mut again = Command::new(std::env::current_exe()?);
        again
            .args([
                "--exact",
                "operator_file_tests::the_owner_types",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_DIR, dir)
            .env(CHILD_VERB, name);
        Ok(again)
    })
    .map_err(|e| e.to_string())
    .and_then(|out| {
        // The harness's own lines, then the verb's; a filter that matched nothing
        // would exit 0 having typed no verb at all.
        if !out.contains("1 passed") {
            return Err(format!("the owner's run did not run the verb:\n{out}"));
        }
        Ok(out
            .lines()
            // `--nocapture` prints the verb's line after the test's name, not under it.
            .find_map(|l| l.split_once("said: ").map(|(_, said)| said))
            .unwrap_or_default()
            .to_owned())
    })
}

/// Run by [`root_types`], as the directory's owner; alone it has no directory and
/// does nothing.
#[test]
#[ignore = "run by root's verb as the directory's owner"]
fn the_owner_types() {
    let (Some(dir), Some(name)) = (std::env::var_os(CHILD_DIR), std::env::var(CHILD_VERB).ok())
    else {
        return;
    };
    match types_here(Path::new(&dir), &name) {
        Ok(said) => println!("said: {said}"),
        // The whole chain, as `main` prints it.
        Err(e) => panic!("{e:#}"),
    }
}

/// A directory's files and what each holds, sorted.
type Held = Vec<(String, String)>;

/// Run the three verbs as `uid` against `dir`, by the ignored test `child`, and
/// return what the directory held before and after — read as root, since under
/// 0700 a stranger cannot list it.
fn types_the_verbs_as(uid: u32, child: &str, dir: &Path) -> (Held, Held) {
    let held = || {
        let mut v: Held = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let body = std::fs::read_to_string(e.path()).unwrap_or_default();
                (e.file_name().to_string_lossy().into_owned(), body)
            })
            .collect();
        v.sort();
        v
    };
    let before = held();
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("setpriv")
        .args([
            &format!("--reuid={uid}"),
            &format!("--regid={uid}"),
            "--clear-groups",
        ])
        .arg(&exe)
        .args([
            "--exact",
            &format!("operator_file_tests::{child}"),
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_DIR, dir)
        .output()
        .expect("setpriv runs the test binary");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "uid {uid}'s run at {} failed:\n{said}",
        dir.display()
    );
    assert!(
        said.contains("1 passed"),
        "uid {uid}'s test did not run:\n{said}"
    );
    (before, held())
}

/// Every shape a stranger's verb meets, each empty and holding `operators`: the
/// unit's own 0700 directory; 0755, which `mkdir` makes and the stranger can read
/// and not write; and 0777, which the stranger can write. In each, `enrol`,
/// `revoke <key>` and `revoke --all` refuse naming the owner, and nothing in the
/// directory changes.
#[test]
fn a_verb_typed_by_a_stranger_is_refused_naming_the_owner_and_changes_nothing() {
    for (mode, holding) in [
        (0o700, false),
        (0o700, true),
        (0o755, false),
        (0o755, true),
        (0o777, false),
        (0o777, true),
    ] {
        let Some(dir) = owned_dir(mode) else { return };
        if holding {
            // Typed as root, so the file is already the owner's.
            assert!(root_types(&dir, "create").unwrap().starts_with("kotton-instance:relay:"));
        }
        let (before, after) = types_the_verbs_as(STRANGER, "the_stranger_types_the_verbs", &dir);
        assert_eq!(
            before, after,
            "a refused verb changed a {mode:o} directory holding operators={holding}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Run by the test above, as [`STRANGER`]; alone it has no directory and does nothing.
#[test]
#[ignore = "run by its parent test under another uid"]
fn the_stranger_types_the_verbs() {
    let Some(dir) = std::env::var_os(CHILD_DIR).map(PathBuf::from) else {
        return;
    };
    let said = ["enrol", "revoke <key>", "revoke --all"].map(|v| (v, types_here(&dir, v)));
    for (verb, r) in said {
        let said = r.map_err(|e| e.to_string()).unwrap_err();
        assert!(
            said.contains(&format!("uid {OWNER}"))
                && (said.contains("runuser -u") || said.contains(&format!("--reuid={OWNER}"))),
            "{verb} at {}: the refusal does not name the user to run as: {said}",
            dir.display()
        );
    }
}

/// The three verbs at `dir`, each refused; what each said.
fn the_three_verbs_refused_at(dir: &Path) -> Vec<(&'static str, String)> {
    ["enrol", "revoke <key>", "revoke --all"]
        .into_iter()
        .map(|v| {
            (
                v,
                types_here(dir, v).map_err(|e| e.to_string()).expect_err(v),
            )
        })
        .collect()
}

/// **Neither verb makes the state directory**
/// (`TASK-a-relay-state-directory-an-older-release-left-roots-is-handed-back-only-by-systemd-and-nobody-ran-it`).
/// The relay makes it as its own user; a verb that made it made it the typist's,
/// and root's `enrol` on a fresh host left a root directory the relay could not read.
/// Typed by whoever runs this test — root in the build container — each verb at a
/// directory that is not there refuses, names the start, and makes nothing.
#[test]
fn neither_verb_makes_the_state_directory_and_each_names_the_start() {
    let dir = std::env::temp_dir().join(format!("kotton-relay-absent-{}", rand::random::<u64>()));
    for (verb, said) in the_three_verbs_refused_at(&dir) {
        assert!(
            said.contains("does not exist") && said.contains("systemctl start kotton-relay"),
            "{verb} at a missing directory did not name the start: {said}"
        );
        assert!(!dir.exists(), "{verb} made {}", dir.display());
    }
}

/// Not an operator key: a line of a root-only file the relay's user must never read.
const ROOTS_LINE: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// What `path` is, without following it: owner, mode, and what it holds.
fn stat_and_body(path: &Path) -> (u32, u32, String) {
    let m = std::fs::symlink_metadata(path).unwrap();
    (m.uid(), m.mode(), std::fs::read_to_string(path).unwrap())
}

/// **Root's verb does not read by a path the relay's user controls**
/// (`TASK-a-relay-operator-verb-typed-as-root-reads-operators-by-a-path-the-relays-user-controls`).
/// The directory's owner — the relay's user, which reads bytes strangers wrote —
/// plants `operators` as a symlink to a root-only file holding one 64-hex line,
/// then root types each verb. That line reaches nothing the owner can read, and
/// the file it points at is unchanged.
#[test]
fn a_verb_typed_as_root_does_not_follow_operators_the_owner_planted() {
    let mut wrong = Vec::new();
    for verb in ["enrol", "revoke <key>", "revoke --all"] {
        let Some(dir) = owned_dir(0o700) else { return };
        let target =
            std::env::temp_dir().join(format!("kotton-relay-roots-{}", rand::random::<u64>()));
        std::fs::write(&target, format!("{ROOTS_LINE}\n")).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            read_as(OWNER, &target).is_err(),
            "the owner can read root's file before any verb"
        );
        let planted = Command::new("setpriv")
            .args([
                &format!("--reuid={OWNER}"),
                &format!("--regid={OWNER}"),
                "--clear-groups",
                "ln",
                "-s",
            ])
            .arg(&target)
            .arg(dir.join("operators"))
            .status()
            .expect("setpriv runs");
        assert!(planted.success(), "the owner could not plant the symlink");
        let before = stat_and_body(&target);

        let said = root_types(&dir, verb);

        // Root's file is not the owner's to read, so neither is it the verb's: a
        // verb that answered counted lines it had no business reading.
        // Refused as the owner, who cannot read it — not refused for some other
        // reason that would make this test pass without typing the verb at all.
        match &said {
            Err(e) if e.contains("Permission denied") => {}
            _ => wrong.push(format!(
                "{verb} answered {said:?} through the owner's symlink"
            )),
        }
        for e in std::fs::read_dir(&dir).unwrap() {
            let path = e.unwrap().path();
            if read_as(OWNER, &path).is_ok_and(|body| body.contains(ROOTS_LINE)) {
                wrong.push(format!(
                    "{verb} left root's line in {}, which the owner reads",
                    path.display()
                ));
            }
        }
        if stat_and_body(&target) != before {
            wrong.push(format!("{verb} changed the file the symlink named"));
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&target);
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The owner's verbs are not root's: called in this root process at a directory
/// another uid owns, each is refused before it opens anything there, so the only
/// way root types one is [`admission::type_verb`], which runs it as the owner.
#[test]
fn the_owners_verbs_refuse_root_in_process() {
    let Some(dir) = owned_dir(0o700) else { return };
    std::os::unix::fs::symlink("/nonexistent/kotton-relay-probe", dir.join("operators")).unwrap();
    let said = [
        admission::enrol_operator(&dir, KEY).map(|_| ()),
        admission::revoke_operator(&dir, admission::Revoke::One(KEY)).map(|_| ()),
        admission::revoke_operator(&dir, admission::Revoke::AllBut(KEY)).map(|_| ()),
    ];
    for r in said {
        let e = r.map_err(|e| e.to_string()).unwrap_err();
        assert!(e.contains(&format!("uid {OWNER}")), "{e}");
    }
    assert!(
        std::fs::symlink_metadata(dir.join("operators"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "root's in-process verb replaced the owner's symlink"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// **A file root left is given back.** An `operators` file a verb typed as root
/// left root's 0600 inside the owner's directory — a build from before verbs ran
/// as the owner — is given back holding its lines by root's next verb, and the
/// owner's verb then works. A root file the owner hard-linked in is not: its
/// second link says it is also somewhere else, and giving it would give that away.
#[test]
fn a_file_root_left_is_given_back_holding_its_lines_and_the_owners_verb_then_works() {
    let Some(dir) = owned_dir(0o700) else { return };
    let file = dir.join("operators");
    std::fs::write(&file, format!("{ROOTS_LINE}\n")).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        read_as(OWNER, &file).is_err(),
        "root's file is readable before"
    );

    assert_eq!(root_types(&dir, "enrol").unwrap(), "enrolled");
    assert_the_owners(&file);
    assert_eq!(
        read_as(OWNER, &file).unwrap(),
        format!("{ROOTS_LINE}\n{KEY}\n")
    );

    // The owner's own verb, typed as them rather than handed to them.
    let (_, after) = types_the_verbs_as(OWNER, "the_owner_revokes", &dir);
    assert_eq!(after, [("operators".to_owned(), format!("{ROOTS_LINE}\n"))]);
    let _ = std::fs::remove_dir_all(&dir);

    let Some(dir) = owned_dir(0o700) else { return };
    let elsewhere =
        std::env::temp_dir().join(format!("kotton-relay-linked-{}", rand::random::<u64>()));
    std::fs::write(&elsewhere, format!("{ROOTS_LINE}\n")).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&elsewhere, dir.join("operators")).unwrap();
    let before = stat_and_body(&elsewhere);
    let said = root_types(&dir, "enrol");
    assert!(
        said.as_ref()
            .is_err_and(|e| e.contains("Permission denied")),
        "enrol answered {said:?} through a hard link to root's file"
    );
    assert_eq!(
        stat_and_body(&elsewhere),
        before,
        "root gave away a file linked from elsewhere"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&elsewhere);
}

/// Run by the test above, as [`OWNER`]; alone it has no directory and does nothing.
#[test]
#[ignore = "run by its parent test under another uid"]
fn the_owner_revokes() {
    let Some(dir) = std::env::var_os(CHILD_DIR).map(PathBuf::from) else {
        return;
    };
    assert_eq!(types_here(&dir, "revoke <key>").unwrap(), "revoked 1");
}

/// What a FIFO the verb met still holds, read without waiting — through `held`,
/// the writer that has kept it open, when there is one, since a pipe's bytes go
/// with its last descriptor. `None` when it is no longer a FIFO at all.
fn fifo_holds(path: &Path, held: Option<std::fs::File>) -> Option<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _};
    if !std::fs::symlink_metadata(path).ok()?.file_type().is_fifo() {
        return None;
    }
    // Read and write, so the open waits for no writer and a read with nothing
    // there says so rather than waiting.
    let mut f = match held {
        Some(f) => f,
        None => std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .ok()?,
    };
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("reading {}: {e}", path.display()),
        }
    }
    Some(got)
}

/// `run` on another thread, for at most a second. Past that, `unblock` is called
/// until `run` returns — so a verb that waits on the FIFO is freed and the test
/// fails saying so, rather than hanging the suite — and the answer is `Err`.
fn within_a_second<T: Send + 'static>(
    run: impl FnOnce() -> T + Send + 'static,
    mut unblock: impl FnMut(),
) -> Result<T, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let t = std::thread::spawn(move || {
        let _ = tx.send(run());
    });
    let started = std::time::Instant::now();
    match rx.recv_timeout(std::time::Duration::from_secs(1)) {
        Ok(v) => {
            t.join().unwrap();
            Ok(v)
        }
        Err(_) => {
            while !t.is_finished() {
                unblock();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let _ = t.join();
            Err(format!(
                "did not return within a second (freed after {:?})",
                started.elapsed()
            ))
        }
    }
}

/// **A verb typed at a FIFO named `operators` refuses at once**
/// (`TASK-a-relay-operator-verb-typed-at-a-fifo-named-operators-waits-forever`).
/// The directory's owner makes `operators` a FIFO; each verb, typed as root and as
/// the owner, returns within a second refusing, names a FIFO and a regular file,
/// and reads and writes nothing: the FIFO is still there, still holding exactly
/// what a writer left in it, and nothing else is in the directory. Once with no
/// writer — the reviewer's probe — and once with one holding a line, so a verb
/// that read would take it.
#[test]
fn a_verb_typed_at_a_fifo_named_operators_refuses_at_once_and_reads_nothing() {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::sync::{Arc, Mutex};
    let mut wrong = Vec::new();
    for typist in ["root", "the owner"] {
        for held in [None, Some(ROOTS_LINE)] {
            for verb in ["enrol", "revoke <key>", "revoke --all"] {
                let Some(dir) = owned_dir(0o700) else { return };
                let fifo = dir.join("operators");
                let made = Command::new("setpriv")
                    .args([
                        &format!("--reuid={OWNER}"),
                        &format!("--regid={OWNER}"),
                        "--clear-groups",
                        "mkfifo",
                    ])
                    .arg(&fifo)
                    .status()
                    .expect("setpriv runs");
                assert!(made.success(), "the owner could not make the FIFO");
                assert_eq!(std::fs::symlink_metadata(&fifo).unwrap().uid(), OWNER);
                // Held open read-write for the whole verb, so it never sees EOF.
                let writer = Arc::new(Mutex::new(held.map(|line| {
                    let mut w = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&fifo)
                        .unwrap();
                    w.write_all(format!("{line}\n").as_bytes()).unwrap();
                    w
                })));
                let case = format!(
                    "{verb} typed as {typist} at a FIFO {}",
                    if held.is_some() {
                        "holding a line"
                    } else {
                        "with no writer"
                    }
                );

                let (d, path, w) = (dir.clone(), fifo.clone(), Arc::clone(&writer));
                let said = within_a_second(
                    move || match typist {
                        "root" => root_types(&d, verb),
                        _ => the_owner_types_at(&d, verb),
                    },
                    // A verb waiting to read is freed by the last writer closing.
                    move || {
                        if w.lock().unwrap().take().is_none() {
                            drop(
                                std::fs::OpenOptions::new()
                                    .write(true)
                                    .custom_flags(libc::O_NONBLOCK)
                                    .open(&path),
                            );
                        }
                    },
                );
                match said {
                    Err(e) => wrong.push(format!("{case}: {e}")),
                    Ok(Ok(out)) => wrong.push(format!("{case} answered {out:?}")),
                    Ok(Err(e)) if !(e.contains("FIFO") && e.contains("regular file")) => wrong
                        .push(format!(
                            "{case} did not name a FIFO and a regular file: {e}"
                        )),
                    Ok(Err(_)) => {}
                }
                let want = held
                    .map(|l| format!("{l}\n").into_bytes())
                    .unwrap_or_default();
                let writer = writer.lock().unwrap().take();
                match fifo_holds(&fifo, writer) {
                    None => wrong.push(format!("{case} left operators no longer a FIFO")),
                    Some(got) if got != want => wrong.push(format!(
                        "{case} left the FIFO holding {:?}, not {:?}",
                        String::from_utf8_lossy(&got),
                        String::from_utf8_lossy(&want)
                    )),
                    Some(_) => {}
                }
                let left: Vec<String> = std::fs::read_dir(&dir)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                if left != ["operators"] {
                    wrong.push(format!("{case} left {left:?} in the directory"));
                }
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// `name` typed at `dir` by the directory's owner as themselves — [`the_owner_types`]
/// run as [`OWNER`] — and what it said, or the refusal it panicked with.
fn the_owner_types_at(dir: &Path, name: &str) -> Result<String, String> {
    let out = Command::new("setpriv")
        .args([
            &format!("--reuid={OWNER}"),
            &format!("--regid={OWNER}"),
            "--clear-groups",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "operator_file_tests::the_owner_types",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DIR, dir)
        .env(CHILD_VERB, name)
        .output()
        .expect("setpriv runs the test binary");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(said)
    } else if said.contains("1 failed") {
        Err(said)
    } else {
        panic!(
            "the owner's run at {} did not run the verb:\n{said}",
            dir.display()
        )
    }
}
