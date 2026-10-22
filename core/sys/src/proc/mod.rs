// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process runtime abstraction
//!
//! This trait abstracts process execution to enable:
//! - Running native OS processes
//! - Running WASM modules
//! - Future bare-metal task scheduling

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;

/// Process exit status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {
    /// Process exited successfully
    Success,
    /// Process exited with a code
    Code(i32),
    /// Process was terminated by a signal
    Signal(i32),
}

/// Output from a process
#[derive(Debug, Clone)]
pub struct ProcessOutput {
    /// Exit status
    pub status: ExitStatus,
    /// Standard output
    pub stdout: Vec<u8>,
    /// Standard error
    pub stderr: Vec<u8>,
}

/// Configuration for spawning a process
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// Command to execute
    pub command: String,
    /// Arguments
    pub args: Vec<String>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Working directory
    pub working_dir: Option<String>,
    /// Standard input
    pub stdin: Option<Vec<u8>>,
}

/// Abstraction for process execution
///
/// Implementations must handle:
/// - Spawning processes with proper isolation
/// - Capturing stdout/stderr
/// - Environment variable management
/// - Working directory handling
///
/// This is the OS-level primitive. In a future Kotton OS, this would be
/// the kernel process scheduler. Services use this under the hood.
#[async_trait]
pub trait Process: Send + Sync {
    /// Spawn a process and wait for it to complete
    async fn run(&self, config: ProcessConfig) -> Result<ProcessOutput>;

    /// Spawn a process in the background
    /// Returns a process ID that can be used to check status or kill
    async fn spawn(&self, config: ProcessConfig) -> Result<u64>;

    /// Check if a background process is still running
    async fn is_running(&self, pid: u64) -> Result<bool>;

    /// Kill a background process
    async fn kill(&self, pid: u64) -> Result<()>;

    /// Wait for a background process to complete
    async fn wait(&self, pid: u64) -> Result<ProcessOutput>;
}
