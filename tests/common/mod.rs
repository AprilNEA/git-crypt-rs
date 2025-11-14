use assert_cmd::{cargo::cargo_bin_cmd, Command};
use std::process::Command as StdCommand;
use tempfile::TempDir;

/// Create a new temporary git repository with user config set.
pub fn create_git_repo() -> TempDir {
    let temp = TempDir::new().expect("failed to create temp dir");

    StdCommand::new("git")
        .args(["init"])
        .current_dir(temp.path())
        .output()
        .expect("failed to init git repo");

    StdCommand::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(temp.path())
        .output()
        .expect("failed to set git user.email");

    StdCommand::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(temp.path())
        .output()
        .expect("failed to set git user.name");

    temp
}

/// Convenience helper for spawning the git-crypt binary via assert_cmd.
#[allow(dead_code)]
pub fn git_crypt_cmd() -> Command {
    cargo_bin_cmd!("git-crypt")
}

/// Absolute path to the git-crypt test binary.
#[allow(dead_code)]
pub fn git_crypt_bin() -> &'static str {
    env!("CARGO_BIN_EXE_git-crypt")
}
