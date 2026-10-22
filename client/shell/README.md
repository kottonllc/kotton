# kotton-shell

Interactive shell for Kotton VFS operations. Not POSIX: it is a confined command engine, and
[Apps](../../docs/design/apps.md) says why.

## Features

### Current

- **Environment Variables**: `$USER`, `$HOME`, `$PWD`, `$OLDPWD`, `$SHELL`, `$PATH`, `$?`
- **Variable Expansion**: Both `$VAR` and `${VAR}` syntax
- **Built-in Commands**: `export`, `unset`, `env`, `echo`, `cd`
- **Exit Code Tracking**: Status displayed in prompt
- **Path Resolution**: Absolute, relative, `~`, `.`, `..`
- **Quote Parsing**: Single quotes, double quotes, escaping
- **Command History**: Via rustyline
- **Signal Handling**: Ctrl+C (cancel), Ctrl+D (exit)

### Planned (Future)

- Tab completion
- Aliases
- Output piping between shell commands
- History expansion

## Architecture

The shell delegates VFS operations to the CLI command layer via IPC to the daemon.

### Design Principles

1. **POSIX Compliance**: Minus networking (no sockets, curl, etc.)
2. **VFS Integration**: All file operations work on encrypted VFS
3. **Session Aware**: Respects user authentication
4. **Code Reuse**: Delegates to existing command functions
5. **Extensibility**: Easy to add new built-ins and features

## Usage

```rust
use kotton_shell::Shell;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let username = "alice";
    Shell::start(username).await
}
```

## Testing

```bash
cargo test --package kotton-shell
```

## Future Work

Inside `kotton repl`, `help` lists every command and `help <command>` shows the help for that one.
