// SPDX-License-Identifier: AGPL-3.0-or-later
/// Tab completion for the kotton shell
use crate::commands::CommandRegistry;
use kotton::KottonClient;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;

/// kotton shell completer
pub struct KottonCompleter {
    registry: Arc<CommandRegistry>,
    client: Arc<Mutex<KottonClient>>,
    user_id: String,
    /// Shared current working directory — updated by `cd`, read during completion.
    cwd: Arc<RwLock<String>>,
    /// The colored prompt for the current line, set by the REPL each iteration.
    /// We pass rustyline a *plain* prompt (so it measures cursor width correctly —
    /// the Windows console width calc counts ANSI bytes) and return this colored
    /// version from `highlight_prompt` for display only.
    colored_prompt: Arc<RwLock<String>>,
}

impl KottonCompleter {
    pub fn new(
        registry: Arc<CommandRegistry>,
        client: Arc<Mutex<KottonClient>>,
        user_id: String,
        cwd: Arc<RwLock<String>>,
        colored_prompt: Arc<RwLock<String>>,
    ) -> Self {
        Self {
            registry,
            client,
            user_id,
            cwd,
            colored_prompt,
        }
    }

    /// Complete command names when no space yet
    fn complete_command(&self, line: &str, pos: usize) -> Vec<Pair> {
        let text = &line[..pos];
        if text.contains(' ') {
            return vec![];
        }
        let mut commands = self.registry.command_names();
        commands.sort();
        commands
            .iter()
            .filter(|cmd| cmd.starts_with(text))
            .map(|cmd| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect()
    }

    /// Complete arguments — command-specific first, then VFS path fallback
    fn complete_args(&self, line: &str, pos: usize) -> Vec<Pair> {
        let before_cursor = &line[..pos];
        let parts: Vec<&str> = before_cursor.split_whitespace().collect();
        if parts.is_empty() {
            return vec![];
        }

        // Account for a trailing space meaning a new blank argument
        let trailing_space = before_cursor.ends_with(char::is_whitespace);
        let command = parts[0];
        let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
        let current_arg = if trailing_space {
            "".to_string()
        } else {
            args.last().cloned().unwrap_or_default()
        };
        let arg_index = if trailing_space {
            args.len()
        } else {
            args.len().saturating_sub(1)
        };

        // Command-specific completions (flags etc.)
        let cmd_completions = self
            .registry
            .complete_for_command(command, &args, arg_index);
        if !cmd_completions.is_empty() {
            return cmd_completions
                .into_iter()
                .filter(|c| c.starts_with(&current_arg))
                .map(|c| Pair {
                    display: c.clone(),
                    replacement: c,
                })
                .collect();
        }

        // Absolute path or empty — complete from the given prefix
        if current_arg.starts_with('/') || current_arg.is_empty() {
            return self.complete_vfs_path(&current_arg);
        }

        // Relative path — resolve against CWD, then strip the CWD prefix
        // from the replacements so the user's relative typing is preserved.
        let cwd = self.cwd.read().unwrap().clone();
        let abs_partial = if cwd == "/" {
            format!("/{}", current_arg)
        } else {
            format!("{}/{}", cwd, current_arg)
        };
        let cwd_prefix = if cwd == "/" {
            "/".to_string()
        } else {
            format!("{}/", cwd)
        };
        self.complete_vfs_path(&abs_partial)
            .into_iter()
            .map(|p| {
                let rel = p
                    .replacement
                    .strip_prefix(&cwd_prefix)
                    .unwrap_or(&p.replacement)
                    .to_string();
                Pair {
                    display: p.display,
                    replacement: rel,
                }
            })
            .collect()
    }

    /// Complete a partial absolute VFS path by querying the daemon.
    ///
    /// For example `/notes/hel` → [`/notes/hello.txt`].
    /// Uses `block_in_place` so it can drive the async `list_files` call
    /// from inside rustyline's synchronous `complete()`.
    fn complete_vfs_path(&self, partial: &str) -> Vec<Pair> {
        // Determine the parent dir to list and the name fragment to filter
        let (parent, filter): (String, String) = if partial.is_empty() || partial == "/" {
            ("/".to_string(), String::new())
        } else if let Some(slash) = partial.rfind('/') {
            let p = &partial[..slash];
            let parent = if p.is_empty() { "/" } else { p };
            (parent.to_string(), partial[slash + 1..].to_string())
        } else {
            return vec![];
        };

        let parent_depth = if parent == "/" {
            0
        } else {
            parent.split('/').filter(|s| !s.is_empty()).count()
        };
        let target_depth = parent_depth + 1;

        let client = Arc::clone(&self.client);
        let user_id = self.user_id.clone();
        let parent_clone = parent.clone();

        // Drive the async call synchronously — safe because we're on a
        // multi-threaded tokio runtime spawned by #[tokio::main].
        let paths = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let mut client = client.lock().await;
                client
                    .list_files(&user_id, &parent_clone)
                    .await
                    .unwrap_or_default()
            })
        });

        let mut seen = HashSet::new();
        let mut completions = Vec::new();

        for path in &paths {
            let norm = path.replace('\\', "/");
            let parts: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
            if parts.len() >= target_depth {
                let name = parts[target_depth - 1];
                if name.starts_with(filter.as_str()) && seen.insert(name.to_string()) {
                    let full = if parent == "/" {
                        format!("/{}", name)
                    } else {
                        format!("{}/{}", parent, name)
                    };
                    completions.push(Pair {
                        display: name.to_string(),
                        replacement: full,
                    });
                }
            }
        }

        completions
    }
}

impl Completer for KottonCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        // Try command completion first
        if !line.contains(' ') {
            let candidates = self.complete_command(line, pos);
            return Ok((0, candidates));
        }

        // Try argument completion
        let arg_candidates = self.complete_args(line, pos);

        // Calculate the start position for replacement
        let before_cursor = &line[..pos];
        let start = before_cursor
            .rfind(char::is_whitespace)
            .map(|p| p + 1)
            .unwrap_or(0);

        Ok((start, arg_candidates))
    }
}

// Required trait implementations for Helper
impl Hinter for KottonCompleter {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<Self::Hint> {
        None
    }
}

impl Highlighter for KottonCompleter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Borrowed(line)
    }

    /// Display the colored prompt while rustyline measures the plain one it was
    /// given. rustyline only calls this when the terminal has colors enabled; if
    /// the cell is empty (or colors off) it falls back to the plain prompt — so
    /// the cursor is always correct, and color is applied when supported.
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        match self.colored_prompt.read() {
            Ok(c) if !c.is_empty() => Cow::Owned(c.clone()),
            _ => Cow::Borrowed(prompt),
        }
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _forced: bool) -> bool {
        false
    }
}

impl Validator for KottonCompleter {}

impl Helper for KottonCompleter {}
