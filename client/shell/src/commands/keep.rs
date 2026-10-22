// SPDX-License-Identifier: AGPL-3.0-or-later
//! `keep`: a folder on this computer, copied into the person's tree, and copied again when
//! the verb is run again — only what changed.
//!
//! **What changed is decided here, by size and modification time.** The store's writer
//! hashes what it is handed (the client sends each write's BLAKE3 so the daemon can refuse
//! a torn reassembly, and the packer dedupes chunks by digest), but it does not skip a write
//! of bytes it already holds: every write is carried over the connection, lands loose, and
//! enters the history log at the next pass, which sync then carries to every device. Asking
//! the tree for a file's hash would mean reading every file back out of it on every run. So
//! a file is left as it is when its size and modification time are what this computer's
//! filesystem reported when it was last copied, and it is still in the tree; anything else
//! is copied, read whole into memory as `cp` reads what it copies.
//!
//! **The record of what is kept is sealed in the tree**, at [`KEPT_DIR`]`/<device>.json`
//! ([`record_path`]), written through the same daemon write the files take. A device holds
//! nothing of the person's in the clear but its session token (`docs/design/threat-model.md`),
//! and the record names every kept file's path, its size and time, and which folder on this
//! computer each name in the tree is kept from. It is keyed by the device because its facts
//! are this device's filesystem's; it is synced as any file is, so another of the person's
//! devices can read it, and that is the person's own tree. `keep` on a device reads and
//! writes that device's record alone; nothing stops `cp` or `rm` reaching any device's, as
//! they reach any of the person's files.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use super::{Command, CommandOutput};
use crate::host::ShellHost;
use crate::out::Out;
use crate::state::ShellState;

pub struct KeepCommand;

#[async_trait]
impl Command for KeepCommand {
    fn help_text(&self) -> &'static str {
        HELP
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        // Asked of the daemon and let go before the tree is reached: the host shares the lock.
        let device = state.client.lock().await.get_node_identity().await;
        let record = match device {
            Ok((device_did, _)) => record_path(&device_did),
            Err(e) => {
                return Ok(CommandOutput::fail(
                    format!("keep: the daemon did not say which device this is: {e}"),
                    None,
                ))
            }
        };
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Ok(run(args, state.host.as_ref(), &record, &cwd, &state.current_dir).await)
    }
}

const HELP: &str = "\
keep — keep a folder of yours in your tree, and pick up its changes

USAGE:
  keep <folder> [as /<name>]
  keep

Copies every file under <folder>, a folder on this computer, into your
tree at /<name>, sealed on disk as cp seals what it copies. <name> is the
folder's own name unless you give one. A relative <folder> is from the
directory the command is run in, and ~ is your home folder. Each file is
read whole into memory as it is copied, as cp reads it.

Hidden files are copied too. Symbolic links are not followed: each is
skipped and counted in what keep prints.

Run it again to pick up changes. A file whose size and modification time
are what they were when it was last copied, and which is still in your
tree, is left as it is and makes no new version; changed and new files are
copied. A file deleted from the folder stays in your tree, and a change
made in your tree is not copied back to the folder.

What is kept is recorded in your tree, sealed as your files are, at
/.kept/<device>.json, one file for each device. keep on a device reads
and writes that device's record alone; every device's record is a file
of yours, which cp and rm reach as they reach any. A name kept from a folder that is gone from this computer is
taken by the next folder kept under it.

With no arguments, keep lists each folder kept from this device, where in
your tree it is, and whether the folder is gone.

EXAMPLES:
  keep ~/Photos
  keep ~/Documents/taxes as /taxes
  keep";

/// The directory of the tree what is kept is recorded in, one file per device. `keep` keeps
/// no folder under it.
pub(crate) const KEPT_DIR: &str = "/.kept";

/// Where in the tree the record of what this device keeps rests: [`KEPT_DIR`]`/<id>.json`,
/// `<id>` the device's own key, `z6Mk…`, from its `did:key`.
pub(crate) fn record_path(device_did: &str) -> String {
    let id = device_did.rsplit(':').next().unwrap_or(device_did);
    format!("{KEPT_DIR}/{id}.json")
}

// ── The record ────────────────────────────────────────────────────────────────

/// Every folder kept from one device, for one identity.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Kept {
    #[serde(default)]
    folders: Vec<KeptFolder>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeptFolder {
    /// Where the folder is in the person's tree: `/Photos`.
    name: String,
    /// The folder on this computer, as resolved when it was kept.
    from: PathBuf,
    /// Each file copied, by its path under the folder, as it stood when it was copied.
    #[serde(default)]
    files: BTreeMap<String, Seen>,
}

/// A file as this computer's filesystem reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Seen {
    size: u64,
    /// Nanoseconds since the epoch; `None` where the filesystem gives no time, and then the
    /// file is copied on every run, because nothing says it has not changed.
    modified_ns: Option<u64>,
}

impl Seen {
    fn of(meta: &std::fs::Metadata) -> Self {
        let modified_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| u64::try_from(d.as_nanos()).ok());
        Seen { size: meta.len(), modified_ns }
    }

    /// Whether a file seen as `self` now is the one recorded as `then`.
    fn unchanged_since(&self, then: &Seen) -> bool {
        self.modified_ns.is_some() && self == then
    }
}

/// The path the store lists an entry under, without the leading `/` a person types.
fn listed_key(path: &str) -> &str {
    path.trim_start_matches('/')
}

/// The record, out of the tree. A record that is not there is nothing kept yet; a read that
/// fails is told from one that is not there by listing [`KEPT_DIR`], because the daemon's
/// refusal names no kind (#308).
async fn load(host: &dyn ShellHost, record: &str) -> io::Result<Kept> {
    match host.read_file(record).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(read) => match host.list_files(&format!("{KEPT_DIR}/")).await {
            Ok(listed) if !listed.iter().any(|p| listed_key(p) == listed_key(record)) => Ok(Kept::default()),
            _ => Err(read),
        },
    }
}

/// The record, into the tree, whole: one write, the same the files take.
async fn save(host: &dyn ShellHost, record: &str, kept: &Kept) -> io::Result<()> {
    let text = serde_json::to_vec_pretty(kept).map_err(io::Error::other)?;
    host.write_file(record, &text).await
}

/// Whether the folder a name is kept from is gone from this computer: it no longer resolves,
/// or what is there is not a folder.
fn gone(from: &Path) -> bool {
    !std::fs::canonicalize(from).is_ok_and(|p| p.is_dir())
}

/// Every file the tree holds under `name`, at any depth. The person's own store lists every
/// depth under a prefix; a routed mount on a plain-keyed store lists one level and marks a
/// directory with a trailing `/`. So a directory entry is listed in turn, unless a file under
/// it was already listed, which says this listing reached its depth.
async fn held_under(host: &dyn ShellHost, name: &str) -> io::Result<HashSet<String>> {
    let mut held = HashSet::new();
    let mut asked = HashSet::new();
    let mut dirs = vec![format!("{}/", listed_key(name))];
    while let Some(dir) = dirs.pop() {
        if !asked.insert(dir.clone()) {
            continue;
        }
        let listed = host.list_files(&format!("/{dir}")).await?;
        let (subdirs, files): (Vec<&String>, Vec<&String>) = listed.iter().partition(|p| p.ends_with('/'));
        let files: Vec<String> = files.into_iter().map(|p| listed_key(p).to_string()).collect();
        for sub in subdirs {
            let sub = listed_key(sub).to_string();
            if sub != dir && !files.iter().any(|f| f.starts_with(&sub)) {
                dirs.push(sub);
            }
        }
        held.extend(files);
    }
    Ok(held)
}

// ── The folder ────────────────────────────────────────────────────────────────

/// What a walk of the folder found.
#[derive(Default)]
struct Walk {
    /// `(path under the folder, path on this computer, as seen)`, in walk order.
    files: Vec<(String, PathBuf, Seen)>,
    links: usize,
    /// Neither a file, a folder nor a link: a socket, a pipe, a device.
    others: usize,
    /// Names that are not UTF-8, which a path in the tree cannot spell.
    unspellable: usize,
    errors: Vec<String>,
}
fn walk(root: &Path) -> io::Result<Walk> {
    let mut found = Walk::default();
    let entries = std::fs::read_dir(root)?;
    walk_entries(entries, "", &mut found);
    found.files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

fn walk_entries(entries: std::fs::ReadDir, under: &str, found: &mut Walk) {
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                found.errors.push(format!("{under}: {e}"));
                continue;
            }
        };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            found.unspellable += 1;
            continue;
        };
        let rel = if under.is_empty() { name } else { format!("{under}/{name}") };
        // `DirEntry::file_type` does not follow a link, so a link is seen as one.
        let kind = match entry.file_type() {
            Ok(k) => k,
            Err(e) => {
                found.errors.push(format!("{}: {e}", entry.path().display()));
                continue;
            }
        };
        if kind.is_symlink() {
            found.links += 1;
        } else if kind.is_dir() {
            match std::fs::read_dir(entry.path()) {
                Ok(inner) => walk_entries(inner, &rel, found),
                Err(e) => found.errors.push(format!("{}: {e}", entry.path().display())),
            }
        } else if kind.is_file() {
            match entry.metadata() {
                Ok(meta) => found.files.push((rel, entry.path(), Seen::of(&meta))),
                Err(e) => found.errors.push(format!("{}: {e}", entry.path().display())),
            }
        } else {
            found.others += 1;
        }
    }
}

/// The folder a person named, on this computer: `~` is their home folder, and a relative
/// path is from `cwd`, the directory the command is run in.
fn resolve_folder(raw: &str, cwd: &Path) -> PathBuf {
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    let path = match raw.strip_prefix('~') {
        Some("") => home().unwrap_or_else(|| PathBuf::from(raw)),
        Some(rest) if rest.starts_with('/') => match home() {
            Some(h) => h.join(rest.trim_start_matches('/')),
            None => PathBuf::from(raw),
        },
        _ => PathBuf::from(raw),
    };
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

/// The name a folder is kept under in the tree: `as`'s, resolved against the shell's current
/// directory, or the folder's own name at the root.
fn tree_name(given: Option<&str>, folder: &Path, tree_cwd: &str) -> Result<String, CommandOutput> {
    let name = match given {
        Some(n) if n.starts_with('/') => crate::utils::normalize_path(n),
        Some(n) => crate::utils::normalize_path(&format!("{tree_cwd}/{n}")),
        None => match folder.file_name().and_then(|n| n.to_str()) {
            Some(n) => format!("/{n}"),
            None => {
                return Err(CommandOutput::fail(
                    format!("keep: {} has no name to keep it under", folder.display()),
                    Some(format!("keep {} as /<name>", folder.display())),
                ))
            }
        },
    };
    if name == "/" {
        return Err(CommandOutput::fail(
            "keep: a folder is kept under a name in your tree, not at its root",
            Some(format!("keep {} as /<name>", folder.display())),
        ));
    }
    if name == KEPT_DIR || name.starts_with(&format!("{KEPT_DIR}/")) {
        return Err(CommandOutput::fail(
            format!("keep: {KEPT_DIR} is where what is kept is recorded, one file for each device"),
            Some(format!("keep {} as /<name>", folder.display())),
        ));
    }
    Ok(name)
}

// ── The verb ──────────────────────────────────────────────────────────────────

/// `keep` with its arguments, against `host` (the person's tree), `record` (where in the tree
/// what this device keeps is recorded), `cwd` (the directory the command is run in) and
/// `tree_cwd` (the shell's current directory in the tree).
pub(crate) async fn run(
    args: &[String],
    host: &dyn ShellHost,
    record: &str,
    cwd: &Path,
    tree_cwd: &str,
) -> CommandOutput {
    let (folder, given) = match args {
        [] => return list(host, record).await,
        [folder] => (folder, None),
        [folder, as_, name] if as_ == "as" => (folder, Some(name.as_str())),
        _ => {
            return CommandOutput::fail(
                "keep: usage: keep <folder> [as /<name>]",
                Some("keep ~/Photos".to_string()),
            )
        }
    };
    let named = resolve_folder(folder, cwd);
    let folder = match std::fs::canonicalize(&named) {
        Ok(p) if p.is_dir() => p,
        Ok(p) => {
            return CommandOutput::fail(
                format!("keep: {} is a file, and keep copies a folder", p.display()),
                Some(format!("cp host:{} /<path>", p.display())),
            )
        }
        Err(e) => return CommandOutput::fail(format!("keep: {}: {e}", named.display()), None),
    };
    let name = match tree_name(given, &folder, tree_cwd) {
        Ok(n) => n,
        Err(refusal) => return refusal,
    };
    keep(host, record, folder, name).await
}

async fn list(host: &dyn ShellHost, record: &str) -> CommandOutput {
    let kept = match load(host, record).await {
        Ok(k) => k,
        Err(e) => return unreadable(record, e),
    };
    if kept.folders.is_empty() {
        return CommandOutput::shapes(vec![
            Out::Note("nothing is kept from this device yet".into()),
            Out::Hint("try: keep <folder>".into()),
        ]);
    }
    // Pairs and not a table: a table cuts a cell to fit the terminal, and the folder's
    // whole path is what this answers.
    CommandOutput::shapes(vec![Out::Record(
        kept.folders
            .iter()
            .map(|f| (f.name.clone(), listed(f)))
            .collect(),
    )])
}

/// One kept folder, as the listing says it: where it is from, how many files went in, and
/// whether the folder is gone from this computer.
fn listed(folder: &KeptFolder) -> String {
    let n = folder.files.len();
    let files = if n == 1 { "file" } else { "files" };
    if gone(&folder.from) {
        format!("from {}, gone from this computer, {n} {files}", folder.from.display())
    } else {
        format!("from {}, {n} {files}", folder.from.display())
    }
}

fn unreadable(record: &str, e: io::Error) -> CommandOutput {
    CommandOutput::fail(
        format!("keep: the record of what this device keeps, {record} in your tree, does not read: {e}"),
        Some(format!("rm {record}; the next keep of each folder copies every file again")),
    )
}

async fn keep(host: &dyn ShellHost, record: &str, folder: PathBuf, name: String) -> CommandOutput {
    let mut kept = match load(host, record).await {
        Ok(k) => k,
        Err(e) => return unreadable(record, e),
    };
    // The record as it was, so a run that changes nothing writes nothing: no version, no log
    // entry, nothing for sync to carry.
    let was_recorded = serde_json::to_vec_pretty(&kept).ok();
    let mut out = Vec::new();
    // A name kept from another folder is that folder's while it is here; once it is gone, the
    // name is let go to the folder kept under it now, and what was recorded for it with it.
    if let Some(i) = kept.folders.iter().position(|f| f.name == name && f.from != folder) {
        if !gone(&kept.folders[i].from) {
            return CommandOutput::fail(
                format!("keep: {name} is kept from {}", kept.folders[i].from.display()),
                Some(format!("keep {} as /<another name>", folder.display())),
            );
        }
        let was = kept.folders.swap_remove(i);
        out.push(Out::Note(format!(
            "{name} was kept from {}, which is gone from this computer; it is kept from {} now",
            was.from.display(),
            folder.display()
        )));
    }
    let found = match walk(&folder) {
        Ok(w) => w,
        Err(e) => return CommandOutput::fail(format!("keep: {}: {e}", folder.display()), None),
    };
    let before = kept
        .folders
        .iter()
        .position(|f| f.name == name)
        .map(|i| kept.folders.swap_remove(i).files)
        .unwrap_or_default();

    // What the tree holds under the name, asked once: a file recorded as copied but gone
    // from the tree since is copied again. Not asked on a first run, when nothing is recorded.
    let held: HashSet<String> = if before.is_empty() {
        HashSet::new()
    } else {
        match held_under(host, &name).await {
            Ok(held) => held,
            Err(e) => return CommandOutput::fail(format!("keep: {name}: {e}"), None),
        }
    };

    let mut files = BTreeMap::new();
    let (mut copied, mut unchanged) = (0usize, 0usize);
    let mut errors = found.errors;
    for (rel, path, seen) in found.files {
        let target = format!("{name}/{rel}");
        let recorded = before.get(&rel).is_some_and(|then| seen.unchanged_since(then));
        if recorded && held.contains(listed_key(&target)) {
            unchanged += 1;
            files.insert(rel, seen);
            continue;
        }
        // Seen before it is read: a file that changes while it is read is recorded as it was
        // before, so the next run sees a time that differs and copies it again.
        match std::fs::read(&path) {
            Ok(data) => match host.write_file(&target, &data).await {
                Ok(()) => {
                    copied += 1;
                    files.insert(rel, seen);
                }
                Err(e) => errors.push(format!("{target}: {e}")),
            },
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }

    kept.folders.push(KeptFolder { name: name.clone(), from: folder, files });
    kept.folders.sort_by(|a, b| a.name.cmp(&b.name));

    out.push(Out::Confirm {
        action: format!(
            "copied {copied} {}, {unchanged} already there unchanged",
            if copied == 1 { "file" } else { "files" }
        ),
        subject: name,
    });
    if found.links > 0 {
        out.push(Out::Warn {
            what: format!("skipped {} symbolic {}", found.links, if found.links == 1 { "link" } else { "links" }),
            consequence: "keep copies files and does not follow links".into(),
        });
    }
    if found.others > 0 {
        out.push(Out::Warn {
            what: format!("skipped {} that {} not a file or a folder", found.others, if found.others == 1 { "is" } else { "are" }),
            consequence: "a socket, a pipe or a device has nothing to copy".into(),
        });
    }
    if found.unspellable > 0 {
        out.push(Out::Warn {
            what: format!("skipped {} whose name is not UTF-8", found.unspellable),
            consequence: "a path in your tree cannot spell it".into(),
        });
    }
    let mut failed = !errors.is_empty();
    for e in errors {
        out.push(Out::Fail { what: format!("keep: {e}"), try_: None });
    }
    let unchanged_record = serde_json::to_vec_pretty(&kept).ok().is_some_and(|now| Some(now) == was_recorded);
    let saved = if unchanged_record { Ok(()) } else { save(host, record, &kept).await };
    if let Err(e) = saved {
        failed = true;
        out.push(Out::Fail {
            what: format!("keep: what was copied is not recorded in {record}: {e}"),
            try_: Some("the next keep copies every file again".into()),
        });
    }
    let mut output = CommandOutput::shapes(out);
    if failed {
        output.exit_code = super::ExitCode::Code(1);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// The person's tree, in memory: what was written, and how many writes there were.
    #[derive(Default)]
    struct Tree {
        files: Mutex<BTreeMap<String, Vec<u8>>>,
        writes: AtomicUsize,
    }

    /// The store lists a path without its leading `/`, and so does this.
    fn key(path: &str) -> String {
        path.trim_start_matches('/').to_string()
    }

    #[async_trait]
    impl ShellHost for Tree {
        async fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
            self.files
                .lock()
                .unwrap()
                .get(&key(path))
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.to_string()))
        }
        async fn write_file(&self, path: &str, data: &[u8]) -> io::Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.files.lock().unwrap().insert(key(path), data.to_vec());
            Ok(())
        }
        async fn list_files(&self, prefix: &str) -> io::Result<Vec<String>> {
            let prefix = key(prefix);
            Ok(self.files.lock().unwrap().keys().filter(|k| k.starts_with(&prefix)).cloned().collect())
        }
        async fn delete_file(&self, path: &str) -> io::Result<()> {
            self.files.lock().unwrap().remove(&key(path));
            Ok(())
        }
    }

    /// A tree whose store lists one level under a prefix and marks a directory with a
    /// trailing `/`, as a routed mount on a plain-keyed store does.
    #[derive(Default)]
    struct OneLevel(Tree);

    #[async_trait]
    impl ShellHost for OneLevel {
        async fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
            self.0.read_file(path).await
        }
        async fn write_file(&self, path: &str, data: &[u8]) -> io::Result<()> {
            self.0.write_file(path, data).await
        }
        async fn list_files(&self, prefix: &str) -> io::Result<Vec<String>> {
            let prefix = key(prefix);
            let mut children: Vec<String> = self
                .0
                .files
                .lock()
                .unwrap()
                .keys()
                .filter_map(|k| k.strip_prefix(&prefix))
                .map(|rest| match rest.split_once('/') {
                    Some((dir, _)) => format!("{prefix}{dir}/"),
                    None => format!("{prefix}{rest}"),
                })
                .collect();
            children.dedup();
            Ok(children)
        }
        async fn delete_file(&self, path: &str) -> io::Result<()> {
            self.0.delete_file(path).await
        }
    }

    /// Where these tests' device records what it keeps.
    const RECORD: &str = "/.kept/z6MkThisDevice.json";

    /// A computer's folders, in one scratch directory.
    struct Here {
        dir: tempfile::TempDir,
    }

    impl Here {
        fn new() -> Self {
            Here { dir: tempfile::tempdir().unwrap() }
        }
        fn put(&self, rel: &str, body: &[u8]) {
            let path = self.dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        async fn keep(&self, tree: &dyn ShellHost, args: &[&str]) -> CommandOutput {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            run(&args, tree, RECORD, self.dir.path(), "/").await
        }
    }

    /// The record, as the tree holds it.
    fn record_in(tree: &Tree) -> serde_json::Value {
        let bytes = tree.files.lock().unwrap().get(key(RECORD).as_str()).cloned().expect("no record in the tree");
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The counts `keep` said, as `(copied, unchanged)`.
    fn said(out: &CommandOutput) -> (usize, usize) {
        assert_eq!(out.exit_code, super::super::ExitCode::Success, "{:?}", out.out);
        let action = out
            .out
            .iter()
            .find_map(|o| match o {
                Out::Confirm { action, .. } => Some(action.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("keep confirmed nothing: {:?}", out.out));
        let numbers: Vec<usize> = action
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().unwrap())
            .collect();
        (numbers[0], numbers[1])
    }

    fn photos(here: &Here) {
        here.put("Photos/beach.jpg", b"sand");
        here.put("Photos/2026/june/lake.jpg", b"water, deeper");
        here.put("Photos/.hidden", b"a dotfile");
    }

    #[tokio::test]
    async fn a_folder_goes_into_the_tree_under_its_own_name_hidden_files_and_all() {
        let here = Here::new();
        photos(&here);
        let tree = Tree::default();

        let out = here.keep(&tree, &["Photos"]).await;

        assert_eq!(said(&out), (3, 0));
        let files = tree.files.lock().unwrap();
        assert_eq!(files.get("Photos/beach.jpg").map(Vec::as_slice), Some(&b"sand"[..]));
        assert_eq!(files.get("Photos/2026/june/lake.jpg").map(Vec::as_slice), Some(&b"water, deeper"[..]));
        assert_eq!(files.get("Photos/.hidden").map(Vec::as_slice), Some(&b"a dotfile"[..]));
        assert!(matches!(&out.out[0], Out::Confirm { subject, .. } if subject == "/Photos"));
    }

    #[tokio::test]
    async fn a_second_run_copies_nothing() {
        let here = Here::new();
        photos(&here);
        let tree = Tree::default();
        here.keep(&tree, &["Photos"]).await;
        let writes = tree.writes.load(Ordering::SeqCst);

        let again = here.keep(&tree, &["Photos"]).await;

        assert_eq!(said(&again), (0, 3));
        assert_eq!(tree.writes.load(Ordering::SeqCst), writes, "an unchanged file, or the unchanged record, was written again");
    }

    #[tokio::test]
    async fn a_changed_file_is_copied_again_and_only_it() {
        let here = Here::new();
        photos(&here);
        let tree = Tree::default();
        here.keep(&tree, &["Photos"]).await;

        // The same size, so only the time says it changed.
        here.put("Photos/beach.jpg", b"dune");
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(here.dir.path().join("Photos/beach.jpg"))
            .unwrap()
            .set_modified(later)
            .unwrap();
        let writes = tree.writes.load(Ordering::SeqCst);

        let again = here.keep(&tree, &["Photos"]).await;

        assert_eq!(said(&again), (1, 2));
        // The file, and the record, which holds its new time.
        assert_eq!(tree.writes.load(Ordering::SeqCst), writes + 2);
        assert_eq!(tree.files.lock().unwrap().get("Photos/beach.jpg").map(Vec::as_slice), Some(&b"dune"[..]));
    }

    #[tokio::test]
    async fn a_new_file_is_copied() {
        let here = Here::new();
        photos(&here);
        let tree = Tree::default();
        here.keep(&tree, &["Photos"]).await;
        here.put("Photos/2026/new.jpg", b"fresh");

        let again = here.keep(&tree, &["Photos"]).await;

        assert_eq!(said(&again), (1, 3));
        assert!(tree.files.lock().unwrap().contains_key("Photos/2026/new.jpg"));
    }

    /// The record says a file went in; the tree no longer has it. It goes in again.
    #[tokio::test]
    async fn a_file_gone_from_the_tree_is_copied_again() {
        let here = Here::new();
        photos(&here);
        let tree = Tree::default();
        here.keep(&tree, &["Photos"]).await;
        tree.delete_file("/Photos/beach.jpg").await.unwrap();

        let again = here.keep(&tree, &["Photos"]).await;

        assert_eq!(said(&again), (1, 2));
        assert!(tree.files.lock().unwrap().contains_key("Photos/beach.jpg"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symbolic_link_is_skipped_and_said() {
        let here = Here::new();
        photos(&here);
        here.put("elsewhere/secret.txt", b"not in the folder");
        std::os::unix::fs::symlink(here.dir.path().join("elsewhere"), here.dir.path().join("Photos/out")).unwrap();
        std::os::unix::fs::symlink(here.dir.path().join("Photos/beach.jpg"), here.dir.path().join("Photos/again.jpg")).unwrap();
        let tree = Tree::default();

        let out = here.keep(&tree, &["Photos"]).await;

        assert_eq!(said(&out), (3, 0));
        assert!(
            out.out.iter().any(|o| matches!(o, Out::Warn { what, .. } if what == "skipped 2 symbolic links")),
            "{:?}",
            out.out
        );
        assert!(tree.files.lock().unwrap().keys().all(|k| !k.contains("secret") && !k.contains("again")));
    }

    #[tokio::test]
    async fn the_listing_names_each_folder_kept_and_where_it_is_from() {
        let here = Here::new();
        photos(&here);
        here.put("Documents/taxes/2025.pdf", b"numbers");
        let tree = Tree::default();
        here.keep(&tree, &["Photos"]).await;
        here.keep(&tree, &["Documents/taxes", "as", "/taxes"]).await;

        let listed = here.keep(&tree, &[]).await;

        let root = std::fs::canonicalize(here.dir.path()).unwrap();
        let Some(Out::Record(pairs)) = listed.out.first() else {
            panic!("keep listed nothing: {:?}", listed.out);
        };
        assert_eq!(
            pairs,
            &vec![
                ("/Photos".to_string(), format!("from {}, 3 files", root.join("Photos").display())),
                ("/taxes".to_string(), format!("from {}, 1 file", root.join("Documents/taxes").display())),
            ]
        );
        assert!(tree.files.lock().unwrap().contains_key("taxes/2025.pdf"));
    }

    #[tokio::test]
    async fn a_name_kept_from_another_folder_is_refused() {
        let here = Here::new();
        photos(&here);
        here.put("Other/Photos/x.jpg", b"x");
        let tree = Tree::default();
        here.keep(&tree, &["Photos"]).await;

        let out = here.keep(&tree, &["Other/Photos"]).await;

        assert_eq!(out.exit_code, super::super::ExitCode::Code(1));
        assert!(!tree.files.lock().unwrap().contains_key("Photos/x.jpg"));
    }

    #[test]
    fn the_record_is_named_by_the_devices_own_key() {
        assert_eq!(record_path("did:key:z6MkAbc"), "/.kept/z6MkAbc.json");
    }

    /// The record is in the tree, through the write the files take, and nothing is written
    /// on this computer beside the folder.
    #[tokio::test]
    async fn what_is_kept_is_recorded_in_the_tree_and_nowhere_on_this_computer() {
        let here = Here::new();
        photos(&here);
        let tree = Tree::default();
        let on_disk_before = walk(here.dir.path()).unwrap().files.len();

        here.keep(&tree, &["Photos"]).await;

        let record = record_in(&tree);
        let folders = record["folders"].as_array().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0]["name"], "/Photos");
        assert_eq!(folders[0]["files"].as_object().unwrap().len(), 3);
        assert_eq!(walk(here.dir.path()).unwrap().files.len(), on_disk_before, "keep wrote a file on this computer");
    }

    /// The folder a name was kept from is gone: the listing says so, and a folder kept under
    /// the name takes it, said in one line, and every file of it goes in.
    #[tokio::test]
    async fn a_name_whose_folder_is_gone_is_said_gone_and_taken_by_the_next_folder() {
        let here = Here::new();
        photos(&here);
        here.put("Moved/Photos/new.jpg", b"moved");
        let tree = Tree::default();
        here.keep(&tree, &["Photos"]).await;
        let old = std::fs::canonicalize(here.dir.path().join("Photos")).unwrap();
        std::fs::remove_dir_all(&old).unwrap();

        let listed = here.keep(&tree, &[]).await;
        let Some(Out::Record(pairs)) = listed.out.first() else {
            panic!("keep listed nothing: {:?}", listed.out);
        };
        assert_eq!(pairs, &vec![("/Photos".to_string(), format!("from {}, gone from this computer, 3 files", old.display()))]);

        let out = here.keep(&tree, &["Moved/Photos", "as", "/Photos"]).await;

        assert_eq!(said(&out), (1, 0));
        let new = std::fs::canonicalize(here.dir.path().join("Moved/Photos")).unwrap();
        let notes: Vec<&String> = out.out.iter().filter_map(|o| match o { Out::Note(n) => Some(n), _ => None }).collect();
        assert_eq!(
            notes,
            vec![&format!("/Photos was kept from {}, which is gone from this computer; it is kept from {} now", old.display(), new.display())]
        );
        let record = record_in(&tree);
        assert_eq!(record["folders"][0]["from"], new.to_str().unwrap());
        assert_eq!(record["folders"][0]["files"].as_object().unwrap().len(), 1);
    }

    /// A folder that is not there is refused before anything is written, the record included.
    #[tokio::test]
    async fn a_folder_that_is_gone_is_refused_and_nothing_is_written() {
        let here = Here::new();
        let tree = Tree::default();

        let out = here.keep(&tree, &["Nowhere"]).await;

        assert_eq!(out.exit_code, super::super::ExitCode::Code(1));
        assert_eq!(tree.writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_folder_is_not_kept_under_the_record_directory() {
        let here = Here::new();
        photos(&here);
        let tree = Tree::default();

        let out = here.keep(&tree, &["Photos", "as", "/.kept/Photos"]).await;

        assert_eq!(out.exit_code, super::super::ExitCode::Code(1));
        assert_eq!(tree.writes.load(Ordering::SeqCst), 0);
    }

    /// Where the tree lists one level at a time, what it holds is still found at every depth:
    /// a nested file gone from it is copied again, and the rest are not.
    #[tokio::test]
    async fn a_nested_file_gone_from_a_tree_that_lists_one_level_is_copied_again() {
        let here = Here::new();
        photos(&here);
        let tree = OneLevel::default();
        here.keep(&tree, &["Photos"]).await;
        tree.delete_file("/Photos/2026/june/lake.jpg").await.unwrap();
        let writes = tree.0.writes.load(Ordering::SeqCst);

        let again = here.keep(&tree, &["Photos"]).await;

        assert_eq!(said(&again), (1, 2));
        // The nested file alone: its size and time are what the record holds already.
        assert_eq!(tree.0.writes.load(Ordering::SeqCst), writes + 1);
        assert!(tree.0.files.lock().unwrap().contains_key("Photos/2026/june/lake.jpg"));
    }

    #[test]
    fn a_relative_folder_is_from_the_directory_the_command_is_run_in() {
        let cwd = Path::new("/work/here");
        assert_eq!(resolve_folder("Photos", cwd), PathBuf::from("/work/here/Photos"));
        assert_eq!(resolve_folder("/abs/Photos", cwd), PathBuf::from("/abs/Photos"));
        if let Some(home) = std::env::var_os("HOME") {
            assert_eq!(resolve_folder("~/Photos", cwd), PathBuf::from(home).join("Photos"));
        }
    }
}
