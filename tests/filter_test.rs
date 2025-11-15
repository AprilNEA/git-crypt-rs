//! # Git Filter Tests
//!
//! Tests for git filter operations (clean/smudge/diff).
//!
//! ## Test Coverage
//!
//! - **Clean filter**: Encrypts files on `git add`/commit
//! - **Smudge filter**: Decrypts files on checkout
//! - **Diff filter**: Shows encryption status instead of binary gibberish
//! - **Round-trip encryption**: Multiple content types (text, binary, Unicode)
//! - **Nonce uniqueness**: Ensures different ciphertext for same plaintext
//! - **Error handling**: Uninitialized repository detection
//!
//! ## How Git Filters Work
//!
//! Git filters are configured in `.git/config`:
//! ```text
//! filter.git-crypt.clean = git-crypt clean
//! filter.git-crypt.smudge = git-crypt smudge
//! filter.git-crypt.diff = git-crypt diff
//! ```
//!
//! Files marked with `filter=git-crypt` in `.gitattributes` are processed
//! through these filters automatically.
//!
//! ## Running Tests
//!
//! ```bash
//! cargo test --test filter_test
//! ```

mod common;

use common::{create_git_repo, git_crypt_bin};
use std::io::Write;
use std::process::{Command, Stdio};

fn init_git_crypt(repo_path: &std::path::Path) {
    let status = Command::new(git_crypt_bin())
        .arg("init")
        .current_dir(repo_path)
        .status()
        .expect("Failed to init git-crypt");

    assert!(status.success());
}

#[test]
fn test_clean_filter_encrypts() {
    let temp = create_git_repo();
    init_git_crypt(temp.path());

    let plaintext = b"This is secret data";

    // Run clean filter
    let mut child = Command::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clean filter");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin
            .write_all(plaintext)
            .expect("Failed to write to stdin");
    }

    let output = child.wait_with_output().expect("Failed to read stdout");

    assert!(output.status.success());

    // Output should be different from input (encrypted)
    assert_ne!(&output.stdout[..], plaintext);

    // Output should be longer (includes nonce)
    assert!(output.stdout.len() > plaintext.len());
}

#[test]
fn test_smudge_filter_decrypts() {
    let temp = create_git_repo();
    init_git_crypt(temp.path());

    let plaintext = b"This is secret data";

    // First encrypt with clean filter
    let mut clean_child = Command::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn clean filter");

    {
        let stdin = clean_child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(plaintext).expect("Failed to write");
    }

    let clean_output = clean_child
        .wait_with_output()
        .expect("Failed to read clean output");

    assert!(clean_output.status.success());

    // Now decrypt with smudge filter
    let mut smudge_child = Command::new(git_crypt_bin())
        .arg("smudge")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn smudge filter");

    {
        let stdin = smudge_child.stdin.as_mut().expect("Failed to open stdin");
        stdin
            .write_all(&clean_output.stdout)
            .expect("Failed to write");
    }

    let smudge_output = smudge_child
        .wait_with_output()
        .expect("Failed to read smudge output");

    assert!(smudge_output.status.success());

    // Output should match original plaintext
    assert_eq!(&smudge_output.stdout[..], plaintext);
}

#[test]
fn test_round_trip_encryption() {
    let temp = create_git_repo();
    init_git_crypt(temp.path());

    let test_cases = vec![
        b"Simple text".to_vec(),
        b"Short".to_vec(),
        b"A bit longer text with some content".to_vec(),
        "Unicode: 🔐 世界".as_bytes().to_vec(),
        (0..128).collect::<Vec<u8>>(), // Various bytes
    ];

    for plaintext in test_cases {
        // Encrypt
        let mut clean = Command::new(git_crypt_bin())
            .arg("clean")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        clean.stdin.as_mut().unwrap().write_all(&plaintext).unwrap();
        let encrypted = clean.wait_with_output().unwrap();
        assert!(encrypted.status.success());

        // Decrypt
        let mut smudge = Command::new(git_crypt_bin())
            .arg("smudge")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        smudge
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&encrypted.stdout)
            .unwrap();
        let decrypted = smudge.wait_with_output().unwrap();
        assert!(decrypted.status.success());

        // Should match original
        assert_eq!(decrypted.stdout, plaintext);
    }
}

#[test]
fn test_diff_filter_shows_encrypted_message() {
    let temp = create_git_repo();
    init_git_crypt(temp.path());

    let plaintext = b"Secret data";

    // First encrypt
    let mut clean = Command::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    clean.stdin.as_mut().unwrap().write_all(plaintext).unwrap();
    let encrypted = clean.wait_with_output().unwrap();

    // Run diff filter on encrypted data
    let mut diff = Command::new(git_crypt_bin())
        .arg("diff")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    diff.stdin
        .as_mut()
        .unwrap()
        .write_all(&encrypted.stdout)
        .unwrap();
    let output = diff.wait_with_output().unwrap();

    assert!(output.status.success());

    let output_str = String::from_utf8_lossy(&output.stdout);
    assert!(output_str.contains("encrypted") || output_str.contains("git-crypt"));
}

#[test]
fn test_clean_filter_without_init_fails() {
    let temp = create_git_repo();

    let mut child = Command::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child.stdin.as_mut().unwrap().write_all(b"data").unwrap();
    let output = child.wait_with_output().unwrap();

    // Should fail because not initialized
    assert!(!output.status.success());
}

#[test]
fn test_multiple_encryptions_different_output() {
    let temp = create_git_repo();
    init_git_crypt(temp.path());

    let plaintext = b"Same data each time";
    let mut outputs = Vec::new();

    // Encrypt same data multiple times
    for _ in 0..3 {
        let mut clean = Command::new(git_crypt_bin())
            .arg("clean")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        clean.stdin.as_mut().unwrap().write_all(plaintext).unwrap();
        let output = clean.wait_with_output().unwrap();
        assert!(output.status.success());

        outputs.push(output.stdout);
    }

    // All outputs should be different (due to random nonces)
    assert_ne!(outputs[0], outputs[1]);
    assert_ne!(outputs[1], outputs[2]);
    assert_ne!(outputs[0], outputs[2]);

    // But all should decrypt to same plaintext
    for encrypted in &outputs {
        let mut smudge = Command::new(git_crypt_bin())
            .arg("smudge")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        smudge.stdin.as_mut().unwrap().write_all(encrypted).unwrap();
        let decrypted = smudge.wait_with_output().unwrap();

        assert_eq!(&decrypted.stdout[..], plaintext);
    }
}
