// SPDX-License-Identifier: AGPL-3.0-or-later
//! A git repository in a temp directory, for the checks that read history. Each test builds
//! the exact shape of branch it is about, so a check's verdict is measured on a history
//! rather than on a function's arguments.

use std::path::Path;
use std::process::Command;

pub struct Repo {
    pub dir: tempfile::TempDir,
}

impl Repo {
    pub fn new() -> Self {
        let r = Repo {
            dir: tempfile::tempdir().expect("a temp dir"),
        };
        r.git(&["init", "-q", "-b", "main"]);
        r.git(&["config", "user.email", "fixture@example.invalid"]);
        r.git(&["config", "user.name", "fixture"]);
        r.git(&["config", "commit.gpgsign", "false"]);
        r
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn git(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(self.path())
            .args(args)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    pub fn write(&self, path: &str, text: &str) {
        let p = self.path().join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    /// Stage everything and commit; returns the new commit's sha.
    pub fn commit(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["rev-parse", "HEAD"])
    }
}
