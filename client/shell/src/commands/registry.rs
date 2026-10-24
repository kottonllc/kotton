// SPDX-License-Identifier: AGPL-3.0-or-later
//! Command registry for shell commands

use anyhow::Result;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use super::{Command, CommandOutput};
use crate::state::ShellState;

/// Registry for shell commands
pub struct CommandRegistry {
    commands: HashMap<String, Arc<dyn Command>>,
    /// Verbs of the `kotton` binary this shell does not run. Typing one is answered
    /// with the one-shot form to run instead, not `command not found` — the person
    /// typed a real verb, and the only thing they are missing is which door it is
    /// behind. Empty unless the caller has a `kotton` binary to name: the guest
    /// shell has none, so it registers none.
    one_shots: BTreeSet<String>,
}

impl CommandRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
            one_shots: BTreeSet::new(),
        }
    }

    /// Register `name` as a `kotton` verb this shell answers by naming its one-shot
    /// form. A name that is also a registered command stays the command's.
    pub fn register_one_shot(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.commands.contains_key(&name) {
            self.one_shots.insert(name);
        }
    }

    /// Whether `name` is a `kotton` verb this shell refuses by naming its one-shot form.
    pub fn is_one_shot(&self, name: &str) -> bool {
        self.one_shots.contains(name)
    }

    /// Register a command with the given name
    pub fn register<C: Command + 'static>(&mut self, name: impl Into<String>, command: C) {
        self.commands.insert(name.into(), Arc::new(command));
    }

    /// Execute a command by name
    pub async fn execute(
        &self,
        name: &str,
        args: &[String],
        state: &mut ShellState,
    ) -> Result<CommandOutput> {
        // `help` is rendered FROM the registry, so every registered command is
        // listed automatically — the listing can never drift from what's wired.
        if name == "help" {
            return Ok(CommandOutput::success_with_output(self.render_help(args)));
        }
        if let Some(cmd) = self.commands.get(name) {
            cmd.execute(args, state).await
        } else if self.one_shots.contains(name) {
            Ok(CommandOutput::error(1, one_shot_refusal(name, args)))
        } else {
            Ok(CommandOutput::error(
                127,
                format!("{}: command not found", name),
            ))
        }
    }

    /// Run `name` without a session, if it can run without one: see
    /// [`Command::execute_without_session`]. `None` when it needs a session, or when no
    /// such command is registered.
    pub async fn execute_without_session(
        &self,
        name: &str,
        args: &[String],
        named: Option<&str>,
    ) -> Option<Result<CommandOutput>> {
        self.commands.get(name)?.execute_without_session(args, named).await
    }

    /// Render `help`. `help <command>` shows that command's `help_text`; `help
    /// <topic>` shows a task guide (pairing / syncing / identity); bare `help` lists
    /// every registered command (from the registry — no hand-maintained list to
    /// drift) plus the task topics.
    fn render_help(&self, args: &[String]) -> String {
        if let Some(name) = args.first() {
            // Commands win over topics, so `help device` shows the verb's help.
            if let Some(cmd) = self.commands.get(name) {
                return cmd.help_text().to_string();
            }
            if let Some(guide) = help_topic(name) {
                return guide.to_string();
            }
            return format!(
                "help: no such command or topic '{name}' — run `help` to list both"
            );
        }
        let docs = self.command_docs(); // sorted (name, help_text)
        let width = docs.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        let mut out = String::from("commands  (run `help <command>` for details)\n\n");
        for (name, help) in &docs {
            let first = help.lines().next().unwrap_or("").trim();
            // Many help_texts start with "name — description"; show just the description.
            let summary = first.split_once(" — ").map(|(_, d)| d).unwrap_or(first);
            out.push_str(&format!("  {name:<width$}  {summary}\n"));
        }
        if !self.one_shots.is_empty() {
            out.push_str("\noutside the shell  (run `kotton <verb> …` from a terminal)\n\n  ");
            out.push_str(&self.one_shots.iter().cloned().collect::<Vec<_>>().join("  "));
            out.push('\n');
        }
        out.push_str("\ntopics  (run `help <topic>` for a task guide)\n\n");
        for (topic, _) in HELP_TOPICS {
            out.push_str(&format!("  {topic}\n"));
        }
        out
    }

    /// Check if a command is registered
    pub fn has_command(&self, name: &str) -> bool {
        self.commands.contains_key(name)
    }

    /// Get all command names for completion
    pub fn command_names(&self) -> Vec<String> {
        self.commands.keys().cloned().collect()
    }

    /// Get completions for a specific command's arguments
    pub fn complete_for_command(
        &self,
        command: &str,
        args: &[String],
        arg_index: usize,
    ) -> Vec<String> {
        self.commands
            .get(command)
            .map(|cmd| cmd.complete(args, arg_index))
            .unwrap_or_default()
    }

    /// Return (name, help_text) pairs for every registered command, sorted by name.
    /// Hidden commands (unfinished/dead stubs) are omitted — they stay runnable but
    /// out of the `help` listing and generated docs.
    pub fn command_docs(&self) -> Vec<(String, &'static str)> {
        let mut docs: Vec<(String, &'static str)> = self
            .commands
            .iter()
            .filter(|(_, cmd)| !cmd.hidden())
            .map(|(name, cmd)| (name.clone(), cmd.help_text()))
            .collect();
        docs.sort_by(|a, b| a.0.cmp(&b.0));
        docs
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The line a one-shot verb is answered with: the command to run instead, built from
/// what was typed, so it can be copied as it stands.
fn one_shot_refusal(name: &str, args: &[String]) -> String {
    let mut form = format!("kotton {name}");
    for a in args {
        form.push(' ');
        form.push_str(a);
    }
    format!("{name} is not answered inside the shell — run `{form}` outside it")
}

/// Task-indexed help: short guides that answer "how do I …?" without already
/// knowing the verb. Keyed by topic words that are **not** command names, so
/// `help <command>` always wins for real verbs.
const HELP_TOPICS: &[(&str, &str)] = &[
    (
        "pairing",
        "pairing — add another of your machines to your identity\n\
         \n\
         On the machine you already use:     device add\n\
         On the new machine, at a terminal:  kotton id join <name> <code>\n\
         \n\
         <code> is what `device add` printed; on the same network you can leave it\n\
         out and the new machine finds the other. The new machine shows six digits:\n\
         type them on the one you already use, and the new machine joins your\n\
         identity and acts as it.\n",
    ),
    (
        "syncing",
        "syncing — keep your files the same across your devices, by way of your drive\n\
         \n\
         sync                    sync this device's drives now\n\
         sync add <drive>        keep this device's rule for a drive (--push, --pull, --watch)\n\
         sync list               show this device's rules\n\
         \n\
         Your things live on a drive, and each device syncs with it: what one\n\
         device writes reaches your others by way of the drive, never directly.\n\
         Files are encrypted before they leave a device — only your own devices\n\
         can read them; the drive, the network and any relay see ciphertext.\n",
    ),
    (
        "identity",
        "identity — who you are, and switching between identities\n\
         \n\
         whoami          the identity your commands act as\n\
         id list         the identities on this device (`*` is current)\n\
         id use <name>   switch this session to another identity\n\
         \n\
         You ARE your key: an identity is a keypair, not an account on a server.\n\
         A new identity has no way back in — that is not an oversight, it is what\n\
         you get for being asked nothing at the start. Set recovery up when you\n\
         want it: `id add-recovery` mints a 24-word phrase and commits it, and\n\
         prints the card that says where a new device goes to use it. You can add more later; adding never retires one you already have.\n\
         Kotton cannot reset any of them.\n",
    ),
];

/// The guide for a task topic, if `name` is one.
fn help_topic(name: &str) -> Option<&'static str> {
    HELP_TOPICS
        .iter()
        .find(|(topic, _)| *topic == name)
        .map(|(_, guide)| *guide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_topics_resolve_and_dont_shadow_commands() {
        assert!(help_topic("pairing").is_some());
        assert!(help_topic("identity").is_some());
        assert!(help_topic("nonsense").is_none());
        // Topic words must be distinct from command names — commands win in
        // render_help, so a topic keyed on a real verb would be unreachable.
        for (topic, _) in HELP_TOPICS {
            assert!(
                !["device", "sync", "id", "whoami"].contains(topic),
                "topic '{topic}' shadows a command and would be unreachable"
            );
        }
    }

    #[test]
    fn bare_help_lists_commands_and_topics() {
        let out = CommandRegistry::new().render_help(&[]);
        assert!(out.contains("topics"), "bare help should list task topics");
        assert!(out.contains("pairing"), "bare help should name the pairing topic");
    }

    /// A `kotton` verb the shell does not run is answered with the command to run
    /// instead, built from what was typed — not `command not found`.
    #[test]
    fn a_one_shot_verb_is_refused_by_naming_its_one_shot_form() {
        let mut reg = CommandRegistry::new();
        reg.register_one_shot("schema");
        assert!(reg.is_one_shot("schema"));
        assert!(!reg.is_one_shot("frobnicate"));
        let line = one_shot_refusal("schema", &["list".to_string()]);
        assert!(line.contains("`kotton schema list`"), "{line}");
        assert!(reg.render_help(&[]).contains("outside the shell"));
    }

    #[test]
    fn help_unknown_names_command_or_topic() {
        let out = CommandRegistry::new().render_help(&["frobnicate".to_string()]);
        assert!(out.contains("no such command or topic"));
    }
}
