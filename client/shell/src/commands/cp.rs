// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use super::{Command, CommandOutput};
use crate::state::ShellState;

pub struct CpCommand;

#[async_trait]
impl Command for CpCommand {
    fn help_text(&self) -> &'static str {
        HELP
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.len() < 2 {
            return Ok(CommandOutput::error(
                1,
                "cp: missing operand.\nUsage: cp <src> <dst>".to_string(),
            ));
        }
        let src = parse_path(&args[0], &state.current_dir);
        let dst = parse_path(&args[1], &state.current_dir);

        match (src, dst) {
            (Path::Vfs(s), Path::Vfs(d)) => copy_vfs_to_vfs(s, d, state).await,
            (Path::Host(s), Path::Vfs(d)) => copy_host_to_vfs(s, d, state).await,
            (Path::Vfs(s), Path::Host(d)) => copy_vfs_to_host(s, d, state).await,
            (Path::Host(_), Path::Host(_)) => Ok(CommandOutput::error(
                1,
                "cp: both paths are host: paths — use the OS shell to copy between host locations"
                    .to_string(),
            )),
        }
    }
}

const HELP: &str = "\
cp — copy files or directories

USAGE:
  cp <src> <dst>

Paths are VFS paths by default.  Prefix with host: to reference the host
filesystem.

  cp /foo /bar              VFS → VFS
  cp host:./file.txt /bar   host → VFS
  cp /foo host:./file.txt   VFS → host

Directories are copied recursively.

EXAMPLES:
  cp /notes/a.txt /notes/b.txt
  cp host:./config.json /settings/config.json
  cp /exports host:./backup";

// ── Path kind ─────────────────────────────────────────────────────────────────

enum Path {
    Vfs(String),
    Host(PathBuf),
}

fn parse_path(raw: &str, vfs_cwd: &str) -> Path {
    if let Some(rest) = raw.strip_prefix("host:") {
        let p = PathBuf::from(rest);
        if p.is_absolute() {
            Path::Host(p)
        } else {
            Path::Host(
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(p),
            )
        }
    } else {
        Path::Vfs(resolve_vfs_path(vfs_cwd, raw))
    }
}

fn resolve_vfs_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{path}")
    } else {
        format!("{cwd}/{path}")
    }
}

// ── VFS → VFS ────────────────────────────────────────────────────────────────

async fn copy_vfs_to_vfs(
    src: String,
    dst: String,
    state: &mut ShellState,
) -> Result<CommandOutput> {
    let mut client = state.client.lock().await;
    let uid = state.user_id.clone();

    // Try listing src as a directory first.
    let mut fs = client.fs(&uid);
    let children = fs.list(&src).await.unwrap_or_default();

    if children.is_empty() {
        // Single file copy.
        let data = match fs.read(&src).await {
            Ok(d) => d,
            Err(e) => {
                return Ok(CommandOutput::error(
                    1,
                    format!("cp: {src}: {e}"),
                ))
            }
        };
        if let Err(e) = fs.write(&dst, &data).await {
            return Ok(CommandOutput::error(1, format!("cp: {dst}: {e}")));
        }
        return Ok(CommandOutput::success());
    }

    // Directory: copy each child, remapping prefix.
    let src_prefix = src.trim_end_matches('/');
    let dst_prefix = dst.trim_end_matches('/');
    let mut errors: Vec<String> = Vec::new();

    for child in &children {
        let rel = child.strip_prefix(src_prefix).unwrap_or(child.as_str());
        let target = format!("{dst_prefix}{rel}");
        match client.fs(&uid).read(child).await {
            Ok(data) => {
                if let Err(e) = client.fs(&uid).write(&target, &data).await {
                    errors.push(format!("{target}: {e}"));
                }
            }
            Err(e) => errors.push(format!("{child}: {e}")),
        }
    }

    if errors.is_empty() {
        Ok(CommandOutput::success())
    } else {
        Ok(CommandOutput::error(1, errors.join("\n")))
    }
}

// ── host → VFS ───────────────────────────────────────────────────────────────

async fn copy_host_to_vfs(
    src: PathBuf,
    dst: String,
    state: &mut ShellState,
) -> Result<CommandOutput> {
    if src.is_file() {
        let data = match std::fs::read(&src) {
            Ok(d) => d,
            Err(e) => {
                return Ok(CommandOutput::error(
                    1,
                    format!("cp: {}: {e}", src.display()),
                ))
            }
        };
        let mut client = state.client.lock().await;
        let uid = state.user_id.clone();
        if let Err(e) = client.fs(&uid).write(&dst, &data).await {
            return Ok(CommandOutput::error(1, format!("cp: {dst}: {e}")));
        }
        return Ok(CommandOutput::success());
    }

    if src.is_dir() {
        let files = match walk_host_dir(&src) {
            Ok(f) => f,
            Err(e) => {
                return Ok(CommandOutput::error(
                    1,
                    format!("cp: {}: {e}", src.display()),
                ))
            }
        };

        let mut client = state.client.lock().await;
        let uid = state.user_id.clone();
        let dst_prefix = dst.trim_end_matches('/');
        let mut errors: Vec<String> = Vec::new();

        for abs_path in &files {
            let rel = abs_path
                .strip_prefix(&src)
                .unwrap_or(abs_path.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            let vfs_target = format!("{dst_prefix}/{rel}");
            match std::fs::read(abs_path) {
                Ok(data) => {
                    if let Err(e) = client.fs(&uid).write(&vfs_target, &data).await {
                        errors.push(format!("{vfs_target}: {e}"));
                    }
                }
                Err(e) => errors.push(format!("{}: {e}", abs_path.display())),
            }
        }

        return if errors.is_empty() {
            Ok(CommandOutput::success())
        } else {
            Ok(CommandOutput::error(1, errors.join("\n")))
        };
    }

    Ok(CommandOutput::error(
        1,
        format!("cp: {}: no such file or directory", src.display()),
    ))
}

// ── VFS → host ───────────────────────────────────────────────────────────────

async fn copy_vfs_to_host(
    src: String,
    dst: PathBuf,
    state: &mut ShellState,
) -> Result<CommandOutput> {
    let mut client = state.client.lock().await;
    let uid = state.user_id.clone();

    let children = client.fs(&uid).list(&src).await.unwrap_or_default();

    if children.is_empty() {
        // Single file.
        let data = match client.fs(&uid).read(&src).await {
            Ok(d) => d,
            Err(e) => return Ok(CommandOutput::error(1, format!("cp: {src}: {e}"))),
        };
        if let Some(parent) = dst.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Ok(CommandOutput::error(
                    1,
                    format!("cp: {}: {e}", parent.display()),
                ));
            }
        }
        if let Err(e) = std::fs::write(&dst, &data) {
            return Ok(CommandOutput::error(1, format!("cp: {}: {e}", dst.display())));
        }
        return Ok(CommandOutput::success());
    }

    // Directory.
    let src_prefix = src.trim_end_matches('/');
    let mut errors: Vec<String> = Vec::new();

    for child in &children {
        let rel = child
            .strip_prefix(src_prefix)
            .unwrap_or(child.as_str())
            .trim_start_matches('/');
        let host_target = dst.join(rel);
        match client.fs(&uid).read(child).await {
            Ok(data) => {
                if let Some(parent) = host_target.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        errors.push(format!("{}: {e}", parent.display()));
                        continue;
                    }
                }
                if let Err(e) = std::fs::write(&host_target, &data) {
                    errors.push(format!("{}: {e}", host_target.display()));
                }
            }
            Err(e) => errors.push(format!("{child}: {e}")),
        }
    }

    if errors.is_empty() {
        Ok(CommandOutput::success())
    } else {
        Ok(CommandOutput::error(1, errors.join("\n")))
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn walk_host_dir(dir: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            result.extend(walk_host_dir(&path)?);
        } else {
            result.push(path);
        }
    }
    Ok(result)
}
