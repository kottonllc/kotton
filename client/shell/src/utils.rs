// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shell utility functions

use std::collections::HashMap;

/// Expand environment variables in a string ($VAR or ${VAR})
pub fn expand_vars(input: &str, env_vars: &HashMap<String, String>) -> String {
    let mut result = input.to_string();

    // Expand ${VAR} style
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let replacement = env_vars.get(var_name).cloned().unwrap_or_default();
            result.replace_range(start..start + end + 1, &replacement);
        } else {
            break;
        }
    }

    // Expand $VAR style (simple word boundary)
    let mut idx = 0;
    while idx < result.len() {
        if result.as_bytes()[idx] == b'$' && idx + 1 < result.len() {
            let start = idx;
            idx += 1;
            let mut end = idx;

            // Find end of variable name (alphanumeric + underscore, or special char like ?)
            while end < result.len() {
                let ch = result.as_bytes()[end];
                if ch.is_ascii_alphanumeric() || ch == b'_' || (end == idx && ch == b'?') {
                    end += 1;
                } else {
                    break;
                }
            }

            if end > idx {
                let var_name = &result[idx..end];
                let replacement = env_vars.get(var_name).cloned().unwrap_or_default();
                result.replace_range(start..end, &replacement);
                idx = start + replacement.len();
            } else {
                idx = end;
            }
        } else {
            idx += 1;
        }
    }

    result
}

/// Parse command line respecting quotes
pub fn parse_command(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            '\\' if !in_single_quote => {
                // Escape next character
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

/// Normalize a path (resolve .. and .)
pub fn normalize_path(path: &str) -> String {
    let mut parts = Vec::new();

    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

#[cfg(test)]
/// Resolve a relative path against a current directory
pub fn resolve_path_relative(path: &str, current_dir: &str) -> String {
    if path.starts_with('/') {
        // Absolute path - just normalize it
        normalize_path(path)
    } else {
        // Relative path - join with current dir and normalize
        let combined = format!("{}/{}", current_dir.trim_end_matches('/'), path);
        normalize_path(&combined)
    }
}
