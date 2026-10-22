// SPDX-License-Identifier: AGPL-3.0-or-later
/// Unit tests for shell command execution and built-in commands
use crate::{
    commands::{CommandOutput, ExitCode},
    utils::{expand_vars, normalize_path, parse_command},
};
use std::collections::HashMap;

// Test variable expansion
#[test]
fn test_simple_variable_expansion() {
    let mut env = HashMap::new();
    env.insert("USER".to_string(), "testuser".to_string());

    let expanded = expand_vars("Hello $USER", &env);
    assert_eq!(expanded, "Hello testuser");
}

#[test]
fn test_brace_variable_expansion() {
    let mut env = HashMap::new();
    env.insert("USER".to_string(), "testuser".to_string());

    let expanded = expand_vars("Hello ${USER}", &env);
    assert_eq!(expanded, "Hello testuser");
}

#[test]
fn test_multiple_variable_expansion() {
    let mut env = HashMap::new();
    env.insert("USER".to_string(), "testuser".to_string());
    env.insert("HOST".to_string(), "localhost".to_string());

    let expanded = expand_vars("$USER@$HOST", &env);
    assert_eq!(expanded, "testuser@localhost");
}

#[test]
fn test_nonexistent_variable() {
    let env = HashMap::new();

    let expanded = expand_vars("${NONEXISTENT}", &env);
    // Should expand to empty string
    assert_eq!(expanded, "");
}

#[test]
fn test_exit_status_variable() {
    let mut env = HashMap::new();
    env.insert("?".to_string(), "42".to_string());

    let expanded = expand_vars("Exit code: $?", &env);
    assert_eq!(expanded, "Exit code: 42");
}

// Test command parsing
#[test]
fn test_parse_simple_command() {
    let parts = parse_command("ls");
    assert_eq!(parts, vec!["ls"]);
}

#[test]
fn test_parse_command_with_args() {
    let parts = parse_command("ls -la /home");
    assert_eq!(parts, vec!["ls", "-la", "/home"]);
}

#[test]
fn test_parse_command_with_quotes() {
    let parts = parse_command("echo \"hello world\"");
    assert_eq!(parts, vec!["echo", "hello world"]);
}

#[test]
fn test_parse_command_with_single_quotes() {
    let parts = parse_command("echo 'hello world'");
    assert_eq!(parts, vec!["echo", "hello world"]);
}

#[test]
fn test_parse_command_with_escapes() {
    let parts = parse_command("echo hello\\ world");
    assert_eq!(parts, vec!["echo", "hello world"]);
}

#[test]
fn test_parse_empty_command() {
    let parts = parse_command("");
    assert_eq!(parts.len(), 0);
}

#[test]
fn test_parse_whitespace_only() {
    let parts = parse_command("   ");
    assert_eq!(parts.len(), 0);
}

// Test path normalization
#[test]
fn test_normalize_absolute_path() {
    assert_eq!(normalize_path("/home/user/file.txt"), "/home/user/file.txt");
}

#[test]
fn test_normalize_path_with_dots() {
    assert_eq!(
        normalize_path("/home/./user/./file.txt"),
        "/home/user/file.txt"
    );
}

#[test]
fn test_normalize_path_with_parent_dirs() {
    assert_eq!(
        normalize_path("/home/user/../admin/file.txt"),
        "/home/admin/file.txt"
    );
}

#[test]
fn test_normalize_root_path() {
    assert_eq!(normalize_path("/"), "/");
}

#[test]
fn test_normalize_path_to_root() {
    assert_eq!(normalize_path("/home/.."), "/");
}

#[test]
fn test_normalize_multiple_slashes() {
    assert_eq!(normalize_path("///home///user///"), "/home/user");
}

// Test command output
#[test]
fn test_command_output_success() {
    let output = CommandOutput::success();
    assert_eq!(output.exit_code, ExitCode::Success);
    assert!(output.stdout.is_none());
    assert!(output.stderr.is_none());
}

#[test]
fn test_command_output_with_stdout() {
    let output = CommandOutput::success_with_output("test output".to_string());
    assert_eq!(output.exit_code, ExitCode::Success);
    assert_eq!(output.stdout, Some("test output".to_string()));
    assert!(output.stderr.is_none());
}

#[test]
fn test_command_output_error() {
    let output = CommandOutput::error(1, "error message".to_string());
    assert_eq!(output.exit_code, ExitCode::Code(1));
    assert!(output.stdout.is_none());
    assert_eq!(output.stderr, Some("error message".to_string()));
}

#[test]
fn test_command_output_exit() {
    let output = CommandOutput::exit();
    assert_eq!(output.exit_code, ExitCode::Exit);
}

// Integration tests with command chaining (using parser)
mod command_tests {
    use crate::parser::parse_command_chain;

    #[test]
    fn test_single_command() {
        let chain = parse_command_chain("ls");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].command, "ls");
    }

    #[test]
    fn test_command_with_args() {
        let chain = parse_command_chain("ls -la /home");
        assert_eq!(chain.len(), 1);
        assert!(chain[0].command.contains("ls"));
    }

    #[test]
    fn test_sequential_commands() {
        let chain = parse_command_chain("ls; pwd; echo test");
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_and_operator() {
        let chain = parse_command_chain("mkdir test && cd test");
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn test_or_operator() {
        let chain = parse_command_chain("rm file.txt || echo failed");
        assert_eq!(chain.len(), 2);
    }
}
