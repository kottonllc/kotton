// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shell state management

use crate::host::ShellHost;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Runtime state threaded through every command execution.
pub struct ShellState {
    pub current_dir: String,
    pub previous_dir: String,
    /// Shared reference to the current directory — also held by the tab completer (CLI)
    /// so it can resolve relative paths without a mutable borrow of `ShellState`.
    pub cwd: Arc<RwLock<String>>,
    pub env_vars: HashMap<String, String>,
    pub last_exit_code: i32,
    /// The logged-in user.
    pub user_id: String,
    /// The shell's only door to user data — all data commands go through this port
    /// (RFC-0028). The CLI backs it with the daemon IPC client; the guest backs it with
    /// the `files`/`schema` capabilities.
    pub host: Arc<dyn ShellHost>,
    /// Daemon IPC client for the CLI-only system commands (`app`/`issuer`/`peer`/…).
    /// Absent in the guest (WASM) build, where those commands are not compiled.
    #[cfg(feature = "cli")]
    pub client: Arc<tokio::sync::Mutex<kotton::KottonClient>>,
    /// Set by `id use <name>` to request an in-session identity switch; the REPL
    /// loop consumes it after the command returns and re-establishes the session as
    /// the new identity. `None` in normal operation.
    #[cfg(feature = "cli")]
    pub pending_identity_switch: Option<String>,
    /// Piped stdin from the previous command (cleared after each command reads it).
    pub stdin: Option<String>,
    /// Who answers a verb that asks in place — `enrol`'s *which* and its
    /// *keep your things here too* ([`Asking`]).
    #[cfg(feature = "cli")]
    pub asking: Asking,
}

/// Who answers a question a verb puts in place (the ruling of 2026-10-12 on
/// `IDEA-an-instance-is-set-up-in-three-pastes-and-nothing-is-typed-by-hand`:
/// *the REPL prompts in place*).
#[cfg(feature = "cli")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asking {
    /// A person at a terminal: the question is put, and the line typed answers.
    Terminal,
    /// Nobody: stdin is not a terminal — a pipe, a script — and a question
    /// would read its next line as the answer. The verb asks nothing and says
    /// what it would have offered as the command to type.
    Nobody,
    /// Answers given beforehand, in order; a question with none left is
    /// answered as nobody answers it. A test's.
    Given(std::collections::VecDeque<String>),
}

#[cfg(feature = "cli")]
impl Asking {
    /// Who is here to answer: a person when stdin is a terminal, else nobody.
    pub fn here() -> Self {
        use std::io::IsTerminal as _;
        if std::io::stdin().is_terminal() {
            Self::Terminal
        } else {
            Self::Nobody
        }
    }

    /// Answer a question whose answer is a secret — `None` when nobody is here
    /// to answer.
    ///
    /// At a terminal the answer is read by [`crate::secret::read_hidden`]: from
    /// the terminal device with echo off, between REPL lines, so the line editor
    /// never sees it and the history file it keeps never holds it. Given answers
    /// are trimmed as that read trims. Nobody here is `None`, never a read of
    /// stdin, which under a pipe would take the next line of a script as a secret.
    pub fn hidden(&mut self, question: &str) -> std::io::Result<Option<String>> {
        match self {
            Self::Nobody => Ok(None),
            Self::Given(answers) => Ok(answers.pop_front().map(|a| a.trim().to_string())),
            Self::Terminal => crate::secret::read_hidden(question).map(Some),
        }
    }

    /// [`Asking::hidden`], with what is to be said before the question: at a
    /// terminal `said` is rendered first, so the question follows it in place;
    /// otherwise it is left for the caller's answer.
    pub fn hidden_after(
        &mut self,
        said: &mut Vec<crate::out::Out>,
        question: &str,
    ) -> std::io::Result<Option<String>> {
        if *self == Self::Terminal {
            crate::out::render(&std::mem::take(said), None);
        }
        self.hidden(question)
    }

    /// Answer a question whose answer is not a secret, read as typed — `None`
    /// when nobody is here to answer. At a terminal `said` is rendered first and
    /// the question put in the margin every question has, then the line typed is
    /// the answer, untrimmed; a given answer is handed back as given.
    pub fn line_after(
        &mut self,
        said: &mut Vec<crate::out::Out>,
        question: &str,
    ) -> std::io::Result<Option<String>> {
        match self {
            Self::Nobody => Ok(None),
            Self::Given(answers) => Ok(answers.pop_front()),
            Self::Terminal => {
                use std::io::Write as _;
                crate::out::render(&std::mem::take(said), None);
                print!("{}", crate::ui::ask(question));
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                Ok(Some(line))
            }
        }
    }
}

#[cfg(feature = "cli")]
impl ShellState {
    /// Render a renderer shape **now** (the streaming half of Pillar 3). Simple
    /// commands return their shapes in `CommandOutput.out` and the REPL renders them
    /// after the call; long-running/streaming commands (`logs -f`, a pairing
    /// ceremony) emit frames *while executing* through this sink so they appear live
    /// — using the same shapes, so no side-channel `println!` dialect creeps in.
    pub fn emit(&self, out: crate::out::Out) {
        crate::out::render(std::slice::from_ref(&out), None);
    }
}

impl ShellState {
    fn default_env(user_id: &str) -> HashMap<String, String> {
        let mut env_vars = HashMap::new();
        env_vars.insert("HOME".to_string(), "/".to_string());
        env_vars.insert("PWD".to_string(), "/".to_string());
        env_vars.insert("OLDPWD".to_string(), "/".to_string());
        env_vars.insert("?".to_string(), "0".to_string());
        env_vars.insert("USER".to_string(), user_id.to_string());
        env_vars.insert("SHELL".to_string(), "Kotton".to_string());
        env_vars.insert("PATH".to_string(), "/bin:/usr/bin".to_string());
        env_vars
    }

    /// CLI constructor — derives the `ShellHost` from the daemon IPC client and retains
    /// the client for the system commands.
    #[cfg(feature = "cli")]
    pub fn new(
        user_id: String,
        client: Arc<tokio::sync::Mutex<kotton::KottonClient>>,
    ) -> Self {
        let host: Arc<dyn ShellHost> = Arc::new(crate::host::KottonClientHost {
            client: Arc::clone(&client),
            user_id: user_id.clone(),
        });
        Self {
            current_dir: "/".to_string(),
            previous_dir: "/".to_string(),
            cwd: Arc::new(RwLock::new("/".to_string())),
            env_vars: Self::default_env(&user_id),
            last_exit_code: 0,
            user_id,
            host,
            client,
            pending_identity_switch: None,
            stdin: None,
            asking: Asking::here(),
        }
    }

    /// Put `question` in place, and answer with what was typed — `None` when
    /// nobody is here to answer ([`Asking::Nobody`], or no answer left in
    /// [`Asking::Given`]). At a terminal, `said` — what the verb has to say
    /// before the question — is rendered first, so the question follows it in
    /// place; otherwise it is left for the verb's answer.
    #[cfg(feature = "cli")]
    pub fn ask(&mut self, said: &mut Vec<crate::out::Out>, question: &str) -> anyhow::Result<Option<String>> {
        Ok(self.asking.line_after(said, question)?)
    }

    /// [`ShellState::ask`] for a secret: the answer is read at a hidden prompt
    /// ([`Asking::hidden`]). At a terminal, `said` is rendered first, as `ask`
    /// renders it.
    #[cfg(feature = "cli")]
    pub fn ask_hidden(&mut self, said: &mut Vec<crate::out::Out>, question: &str) -> anyhow::Result<Option<String>> {
        Ok(self.asking.hidden_after(said, question)?)
    }

    /// Generic constructor — runs the engine against any `ShellHost`. Used by the guest
    /// (WASM) build with a capability-backed host.
    #[cfg(not(feature = "cli"))]
    pub fn with_host(user_id: String, host: Arc<dyn ShellHost>) -> Self {
        Self {
            current_dir: "/".to_string(),
            previous_dir: "/".to_string(),
            cwd: Arc::new(RwLock::new("/".to_string())),
            env_vars: Self::default_env(&user_id),
            last_exit_code: 0,
            user_id,
            host,
            stdin: None,
        }
    }
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::Asking;

    /// A given answer is taken in order and trimmed; none left is nobody answering.
    #[test]
    fn a_hidden_question_takes_given_answers_in_order_and_then_none() {
        let mut asking = Asking::Given(["  the phrase \n".to_string(), "pass".to_string()].into());
        assert_eq!(asking.hidden("phrase").unwrap().as_deref(), Some("the phrase"));
        assert_eq!(asking.hidden("passphrase").unwrap().as_deref(), Some("pass"));
        assert_eq!(asking.hidden("more").unwrap(), None);
    }

    /// Nobody here is no answer, not a read of stdin: under a pipe, stdin's next
    /// line is the script's, and taking it for a secret would act on it.
    #[test]
    fn a_hidden_question_with_nobody_here_has_no_answer() {
        assert_eq!(Asking::Nobody.hidden("phrase").unwrap(), None);
    }
}
