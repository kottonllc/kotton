// SPDX-License-Identifier: AGPL-3.0-or-later
/// Security tests for shell path traversal protection
use crate::utils::{normalize_path, resolve_path_relative};

#[test]
fn test_path_traversal_blocked_absolute() {
    // Trying to escape with absolute path should stay in VFS
    let result = normalize_path("/../../../etc/passwd");
    assert_eq!(result, "/etc/passwd", "Should normalize to VFS path");
}

#[test]
fn test_path_traversal_blocked_relative() {
    // From /home/user, trying to go to /etc
    let current = "/home/user";
    let result = resolve_path_relative("../../etc", current);
    assert_eq!(result, "/etc", "Should normalize but stay in VFS");
}

#[test]
fn test_multiple_parent_dirs_from_root() {
    // From root, multiple .. should stay at root
    let current = "/";
    let result = resolve_path_relative("..", current);
    assert_eq!(result, "/", "Should not escape root");

    let result = resolve_path_relative("../..", current);
    assert_eq!(result, "/", "Should not escape root with multiple ..");

    let result = resolve_path_relative("../../../../..", current);
    assert_eq!(result, "/", "Should not escape root with many ..");
}

#[test]
fn test_mixed_traversal() {
    // Complex path with both forward and backward navigation
    let result = normalize_path("/a/b/c/../../d/./e");
    assert_eq!(result, "/a/d/e");
}

#[test]
fn test_normalize_prevents_escaping_root() {
    // No matter how many .., should never go above /
    let result = normalize_path("/../../../../../../../../../etc/passwd");
    assert_eq!(result, "/etc/passwd");

    let result = normalize_path("/../../../../");
    assert_eq!(result, "/");
}

#[test]
fn test_current_dir_navigation() {
    let current = "/docs/project";

    // Same directory
    let result = resolve_path_relative(".", current);
    assert_eq!(result, "/docs/project");

    // One level up
    let result = resolve_path_relative("..", current);
    assert_eq!(result, "/docs");

    // Two levels up
    let result = resolve_path_relative("../..", current);
    assert_eq!(result, "/");

    // Three levels up (should stop at root)
    let result = resolve_path_relative("../../..", current);
    assert_eq!(result, "/");
}

#[test]
fn test_relative_path_from_deep_directory() {
    let current = "/a/b/c/d/e";

    // Go up and then down
    let result = resolve_path_relative("../../x/y", current);
    assert_eq!(result, "/a/b/c/x/y");

    // Try to escape and access system path
    let result = resolve_path_relative("../../../../../system", current);
    assert_eq!(
        result, "/system",
        "Should be at VFS /system, not host system"
    );
}

#[test]
fn test_hidden_path_traversal() {
    // Various sneaky attempts
    let result = normalize_path("/etc/../../../etc/shadow");
    assert_eq!(result, "/etc/shadow");

    let result = normalize_path("/./././etc/passwd");
    assert_eq!(result, "/etc/passwd");

    let result = normalize_path("/../");
    assert_eq!(result, "/");
}

#[test]
fn test_empty_path_segments() {
    let result = normalize_path("///etc///passwd");
    assert_eq!(result, "/etc/passwd");

    let result = normalize_path("/a//b///c");
    assert_eq!(result, "/a/b/c");
}
