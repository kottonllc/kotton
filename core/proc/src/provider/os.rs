// SPDX-License-Identifier: AGPL-3.0-or-later
//! OS process runtime implementation using tokio::process and std::process

use anyhow::{Context, Result};
use async_trait::async_trait;
use kotton_sys::proc::{ExitStatus, Process, ProcessConfig, ProcessOutput};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

/// Standard OS process runtime implementation
#[derive(Debug, Clone)]
pub struct OsProcess {
    processes: Arc<Mutex<HashMap<u64, Child>>>,
}

impl OsProcess {
    /// Create a new OS process runtime
    pub fn new() -> Self {
        Self {
            processes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for OsProcess {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Process for OsProcess {
    async fn run(&self, config: ProcessConfig) -> Result<ProcessOutput> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args);

        if let Some(ref cwd) = config.working_dir {
            cmd.current_dir(cwd);
        }

        for (key, value) in &config.env {
            cmd.env(key, value);
        }

        if let Some(ref _stdin_data) = config.stdin {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let output = cmd
            .output()
            .await
            .with_context(|| format!("Failed to execute: {} {:?}", config.command, config.args))?;

        Ok(ProcessOutput {
            status: if output.status.success() {
                ExitStatus::Success
            } else {
                ExitStatus::Code(output.status.code().unwrap_or(-1))
            },
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    async fn spawn(&self, config: ProcessConfig) -> Result<u64> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref cwd) = config.working_dir {
            cmd.current_dir(cwd);
        }

        for (key, value) in &config.env {
            cmd.env(key, value);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn: {} {:?}", config.command, config.args))?;

        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("Failed to get process ID"))? as u64;

        self.processes.lock().unwrap().insert(pid, child);
        Ok(pid)
    }

    async fn is_running(&self, pid: u64) -> Result<bool> {
        let mut processes = self.processes.lock().unwrap();

        if let Some(child) = processes.get_mut(&pid) {
            // Try to get exit status without blocking
            match child.try_wait() {
                Ok(Some(_)) => {
                    // Process has exited
                    processes.remove(&pid);
                    Ok(false)
                }
                Ok(None) => {
                    // Process is still running
                    Ok(true)
                }
                Err(e) => Err(e).context("Failed to check process status"),
            }
        } else {
            // Not in our tracked processes, assume not running
            Ok(false)
        }
    }

    async fn kill(&self, pid: u64) -> Result<()> {
        let child_opt = {
            let mut processes = self.processes.lock().unwrap();
            processes.remove(&pid)
        };

        if let Some(mut child) = child_opt {
            child
                .kill()
                .await
                .with_context(|| format!("Failed to kill process {}", pid))?;
            Ok(())
        } else {
            // Try to kill by PID even if we didn't spawn it
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
                    .with_context(|| format!("Failed to kill process {}", pid))?;
                Ok(())
            }

            #[cfg(windows)]
            {
                // On Windows, we need the handle to kill
                anyhow::bail!("Process {} not found in tracked processes", pid)
            }
        }
    }

    async fn wait(&self, pid: u64) -> Result<ProcessOutput> {
        let mut child = {
            let mut processes = self.processes.lock().unwrap();
            processes
                .remove(&pid)
                .ok_or_else(|| anyhow::anyhow!("Process {} not found", pid))?
        };

        // Read stdout and stderr
        let mut stdout_data = Vec::new();
        let mut stderr_data = Vec::new();

        if let Some(mut stdout) = child.stdout.take() {
            stdout
                .read_to_end(&mut stdout_data)
                .await
                .with_context(|| format!("Failed to read stdout from process {}", pid))?;
        }

        if let Some(mut stderr) = child.stderr.take() {
            stderr
                .read_to_end(&mut stderr_data)
                .await
                .with_context(|| format!("Failed to read stderr from process {}", pid))?;
        }

        // Wait for process to exit
        let status = child
            .wait()
            .await
            .with_context(|| format!("Failed to wait for process {}", pid))?;

        Ok(ProcessOutput {
            status: if status.success() {
                ExitStatus::Success
            } else {
                ExitStatus::Code(status.code().unwrap_or(-1))
            },
            stdout: stdout_data,
            stderr: stderr_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_command() {
        let runtime = OsProcess::new();

        #[cfg(unix)]
        let config = ProcessConfig {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stdin: None,
        };

        #[cfg(windows)]
        let config = ProcessConfig {
            command: "cmd".to_string(),
            args: vec!["/C".to_string(), "echo hello".to_string()],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stdin: None,
        };

        let output = runtime.run(config).await.unwrap();
        assert_eq!(output.status, ExitStatus::Success);
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    }

    #[tokio::test]
    async fn test_spawn_and_wait() {
        let runtime = OsProcess::new();

        #[cfg(unix)]
        let config = ProcessConfig {
            command: "echo".to_string(),
            args: vec!["test".to_string()],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stdin: None,
        };

        #[cfg(windows)]
        let config = ProcessConfig {
            command: "cmd".to_string(),
            args: vec!["/C".to_string(), "echo test".to_string()],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stdin: None,
        };

        let pid = runtime.spawn(config).await.unwrap();
        let output = runtime.wait(pid).await.unwrap();
        assert_eq!(output.status, ExitStatus::Success);
        assert!(String::from_utf8_lossy(&output.stdout).contains("test"));
    }

    #[tokio::test]
    async fn test_spawn_and_kill() {
        let runtime = OsProcess::new();

        // Spawn a long-running process
        #[cfg(unix)]
        let config = ProcessConfig {
            command: "sleep".to_string(),
            args: vec!["10".to_string()],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stdin: None,
        };

        #[cfg(windows)]
        let config = ProcessConfig {
            command: "timeout".to_string(),
            args: vec!["/t".to_string(), "10".to_string()],
            env: std::collections::HashMap::new(),
            working_dir: None,
            stdin: None,
        };

        let pid = runtime.spawn(config).await.unwrap();

        // Kill it immediately
        runtime.kill(pid).await.unwrap();
    }
}
