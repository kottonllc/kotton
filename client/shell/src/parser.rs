// SPDX-License-Identifier: AGPL-3.0-or-later
/// Command chaining parser for shell
/// Supports `;`, `&&`, `||`, and `|` operators

#[derive(Debug, Clone, PartialEq)]
pub enum ChainOperator {
    /// `;` - Always execute next command
    Sequential,
    /// `&&` - Execute next only if previous succeeded (exit code 0)
    And,
    /// `||` - Execute next only if previous failed (exit code != 0)
    Or,
    /// `|` - Pipe stdout of left command to stdin of right command
    Pipe,
}

#[derive(Debug, Clone)]
pub struct CommandChain {
    pub command: String,
    pub operator: Option<ChainOperator>,
}

/// Parse a line into chained commands
pub fn parse_command_chain(line: &str) -> Vec<CommandChain> {
    let mut commands = Vec::new();
    let mut current_cmd = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    let mut quote_char = ' ';

    while let Some(ch) = chars.next() {
        match ch {
            // Handle quotes (don't split on operators inside quotes)
            '"' | '\'' if !in_quotes => {
                in_quotes = true;
                quote_char = ch;
                current_cmd.push(ch);
            }
            '"' | '\'' if in_quotes && ch == quote_char => {
                in_quotes = false;
                current_cmd.push(ch);
            }

            // Handle operators (only when not in quotes)
            ';' if !in_quotes => {
                if !current_cmd.trim().is_empty() {
                    commands.push(CommandChain {
                        command: current_cmd.trim().to_string(),
                        operator: Some(ChainOperator::Sequential),
                    });
                    current_cmd.clear();
                }
            }

            '&' if !in_quotes => {
                if chars.peek() == Some(&'&') {
                    chars.next(); // consume second &
                    if !current_cmd.trim().is_empty() {
                        commands.push(CommandChain {
                            command: current_cmd.trim().to_string(),
                            operator: Some(ChainOperator::And),
                        });
                        current_cmd.clear();
                    }
                } else {
                    // Single & - not supported (background execution)
                    current_cmd.push(ch);
                }
            }

            '|' if !in_quotes => {
                if chars.peek() == Some(&'|') {
                    chars.next(); // consume second |
                    if !current_cmd.trim().is_empty() {
                        commands.push(CommandChain {
                            command: current_cmd.trim().to_string(),
                            operator: Some(ChainOperator::Or),
                        });
                        current_cmd.clear();
                    }
                } else {
                    // Single | - pipe stdout to next command's stdin
                    if !current_cmd.trim().is_empty() {
                        commands.push(CommandChain {
                            command: current_cmd.trim().to_string(),
                            operator: Some(ChainOperator::Pipe),
                        });
                        current_cmd.clear();
                    }
                }
            }

            // Regular character
            _ => {
                current_cmd.push(ch);
            }
        }
    }

    // Add the last command (with no operator)
    if !current_cmd.trim().is_empty() {
        commands.push(CommandChain {
            command: current_cmd.trim().to_string(),
            operator: None,
        });
    }

    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential() {
        let result = parse_command_chain("mkdir test; cd test; touch file.txt");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].command, "mkdir test");
        assert_eq!(result[0].operator, Some(ChainOperator::Sequential));
        assert_eq!(result[1].command, "cd test");
        assert_eq!(result[1].operator, Some(ChainOperator::Sequential));
        assert_eq!(result[2].command, "touch file.txt");
        assert_eq!(result[2].operator, None);
    }

    #[test]
    fn test_and_operator() {
        let result = parse_command_chain("mkdir project && cd project && ls");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].operator, Some(ChainOperator::And));
        assert_eq!(result[1].operator, Some(ChainOperator::And));
        assert_eq!(result[2].operator, None);
    }

    #[test]
    fn test_or_operator() {
        let result = parse_command_chain("ls /tmp/file.txt || echo not found");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, "ls /tmp/file.txt");
        assert_eq!(result[0].operator, Some(ChainOperator::Or));
        assert_eq!(result[1].command, "echo not found");
    }

    #[test]
    fn test_mixed_operators() {
        let result = parse_command_chain("mkdir test && cd test || echo failed; ls");
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].operator, Some(ChainOperator::And));
        assert_eq!(result[1].operator, Some(ChainOperator::Or));
        assert_eq!(result[2].operator, Some(ChainOperator::Sequential));
    }

    #[test]
    fn test_pipe_operator() {
        let result = parse_command_chain("ls /notes | grep hello");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, "ls /notes");
        assert_eq!(result[0].operator, Some(ChainOperator::Pipe));
        assert_eq!(result[1].command, "grep hello");
        assert_eq!(result[1].operator, None);
    }

    #[test]
    fn test_pipe_chain() {
        let result = parse_command_chain("cat file.txt | grep foo | wc");
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].operator, Some(ChainOperator::Pipe));
        assert_eq!(result[1].operator, Some(ChainOperator::Pipe));
        assert_eq!(result[2].operator, None);
    }

    #[test]
    fn test_or_not_confused_with_pipe() {
        let result = parse_command_chain("ls || echo nope");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].operator, Some(ChainOperator::Or));
    }

    #[test]
    fn test_quotes() {
        let result = parse_command_chain(r#"echo "hello; world" && echo done"#);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].command, r#"echo "hello; world""#);
        assert_eq!(result[1].command, "echo done");
    }
}
