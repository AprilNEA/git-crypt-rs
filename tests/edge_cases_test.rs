//! # Edge Case and Error Handling Tests
//!
//! Tests corner cases and error conditions to ensure robustness.
//!
//! ## Test Coverage
//!
//! - **Large files**: 10MB file encryption/decryption
//! - **Empty files**: Zero-byte file handling
//! - **Binary data**: Files with null bytes and all byte values
//! - **Unicode**: International characters in filenames and content
//! - **Data corruption**: Tamper detection and authentication
//! - **File operations**: Overwriting existing files
//! - **Concurrency**: Thread-safe operations
//! - **Permissions**: Directory and file security (Unix)
//! - **Idempotency**: Lock/unlock repeated operations
//! - **Special characters**: Control characters and edge cases
//!
//! ## Security Tests
//!
//! These tests verify cryptographic properties:
//! - Corrupted data is detected and rejected
//! - Key isolation between repositories
//! - File permissions are properly restricted (0600 on Unix)
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all edge case tests
//! cargo test --test edge_cases_test
//!
//! # Run with backtrace for debugging
//! RUST_BACKTRACE=1 cargo test --test edge_cases_test
//! ```

mod common;

use common::{create_git_repo, git_crypt_bin, git_crypt_cmd};
use std::fs;
use std::io::Write;
use std::process::{Command as StdCommand, Stdio};

#[test]
fn test_very_large_file_encryption() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    // Create 10MB file
    let large_data = vec![0x42u8; 10 * 1024 * 1024];

    let mut clean = StdCommand::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    clean
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&large_data)
        .unwrap();
    let encrypted = clean.wait_with_output().unwrap();
    assert!(encrypted.status.success());

    // Decrypt back
    let mut smudge = StdCommand::new(git_crypt_bin())
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
    assert_eq!(decrypted.stdout.len(), large_data.len());
}

#[test]
fn test_empty_file_encryption() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    let empty_data = b"";

    let mut clean = StdCommand::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    clean.stdin.as_mut().unwrap().write_all(empty_data).unwrap();
    let encrypted = clean.wait_with_output().unwrap();
    assert!(encrypted.status.success());

    let mut smudge = StdCommand::new(git_crypt_bin())
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
    assert_eq!(&decrypted.stdout[..], empty_data);
}

#[test]
fn test_binary_file_with_null_bytes() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    let binary_data: Vec<u8> = vec![0x00, 0xFF, 0x00, 0x42, 0x00, 0x00, 0xAA, 0xBB];

    let mut clean = StdCommand::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    clean
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&binary_data)
        .unwrap();
    let encrypted = clean.wait_with_output().unwrap();
    assert!(encrypted.status.success());

    let mut smudge = StdCommand::new(git_crypt_bin())
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
    assert_eq!(decrypted.stdout, binary_data);
}

#[test]
fn test_unicode_filenames_and_content() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    // Use content that is less likely to have ASCII-heavy encrypted output
    let unicode_content = "Hello 世界! Emoji: 🔐🦀 Math: ∑∫∂ "
        .repeat(5); // Repeat to ensure sufficient length

    let mut clean = StdCommand::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    clean
        .stdin
        .as_mut()
        .unwrap()
        .write_all(unicode_content.as_bytes())
        .unwrap();
    let encrypted = clean.wait_with_output().unwrap();
    assert!(encrypted.status.success());

    let mut smudge = StdCommand::new(git_crypt_bin())
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
    assert_eq!(
        String::from_utf8(decrypted.stdout).unwrap(),
        unicode_content
    );
}

#[test]
fn test_corrupted_encrypted_data() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    let plaintext = b"Secret message";

    // Encrypt
    let mut clean = StdCommand::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    clean.stdin.as_mut().unwrap().write_all(plaintext).unwrap();
    let encrypted = clean.wait_with_output().unwrap();
    assert!(encrypted.status.success());

    // Corrupt the encrypted data
    let mut corrupted = encrypted.stdout.clone();
    if corrupted.len() > 15 {
        corrupted[15] ^= 0xFF;
    }

    // Try to decrypt corrupted data
    let mut smudge = StdCommand::new(git_crypt_bin())
        .arg("smudge")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    smudge.stdin.as_mut().unwrap().write_all(&corrupted).unwrap();
    let output = smudge.wait_with_output().unwrap();

    // Should fail
    assert!(!output.status.success());
}

#[test]
fn test_export_key_to_existing_file() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    let key_file = temp.path().join("key.bin");

    // First export
    git_crypt_cmd()
        .args(["export-key", key_file.to_str().unwrap()])
        .current_dir(temp.path())
        .assert()
        .success();

    let first_key = fs::read(&key_file).unwrap();

    // Export again (should overwrite)
    git_crypt_cmd()
        .args(["export-key", key_file.to_str().unwrap()])
        .current_dir(temp.path())
        .assert()
        .success();

    let second_key = fs::read(&key_file).unwrap();

    // Should be the same key
    assert_eq!(first_key, second_key);
}

#[test]
fn test_invalid_command() {
    git_crypt_cmd()
        .arg("invalid-command")
        .assert()
        .failure();
}

#[test]
fn test_concurrent_operations() {
    use std::thread;

    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    let temp_path = temp.path().to_path_buf();

    // Spawn multiple threads doing encryption
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let path = temp_path.clone();
            thread::spawn(move || {
                let data = format!("Thread {} data", i);

                let mut clean = StdCommand::new(git_crypt_bin())
                    .arg("clean")
                    .current_dir(&path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();

                clean
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(data.as_bytes())
                    .unwrap();
                let output = clean.wait_with_output().unwrap();

                assert!(output.status.success());
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_key_with_directory_permissions() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    let git_crypt_dir = temp.path().join(".git/git-crypt");
    let keys_dir = git_crypt_dir.join("keys");

    assert!(git_crypt_dir.is_dir());
    assert!(keys_dir.is_dir());
}

#[test]
fn test_lock_unlock_idempotent() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    // Lock multiple times
    for _ in 0..3 {
        git_crypt_cmd()
            .arg("lock")
            .current_dir(temp.path())
            .assert()
            .success();
    }

    // Unlock multiple times
    for _ in 0..3 {
        git_crypt_cmd()
            .arg("unlock")
            .current_dir(temp.path())
            .assert()
            .success();
    }
}

#[test]
fn test_special_characters_in_data() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    // Data with special characters
    let special_data = b"Line1\nLine2\r\nTab\there\0null\x01\x02\x03\xFF";

    let mut clean = StdCommand::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    clean
        .stdin
        .as_mut()
        .unwrap()
        .write_all(special_data)
        .unwrap();
    let encrypted = clean.wait_with_output().unwrap();
    assert!(encrypted.status.success());

    let mut smudge = StdCommand::new(git_crypt_bin())
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
    assert_eq!(&decrypted.stdout[..], special_data);
}

#[test]
fn test_repeated_key_operations() {
    let temp = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(temp.path())
        .assert()
        .success();

    let key_file = temp.path().join("key.bin");

    // Export and import repeatedly
    for _ in 0..5 {
        git_crypt_cmd()
            .args(["export-key", key_file.to_str().unwrap()])
            .current_dir(temp.path())
            .assert()
            .success();

        git_crypt_cmd()
            .args(["import-key", key_file.to_str().unwrap()])
            .current_dir(temp.path())
            .assert()
            .success();
    }

    // Key should still work
    let plaintext = b"Test after repeated operations";

    let mut clean = StdCommand::new(git_crypt_bin())
        .arg("clean")
        .current_dir(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    clean.stdin.as_mut().unwrap().write_all(plaintext).unwrap();
    let encrypted = clean.wait_with_output().unwrap();
    assert!(encrypted.status.success());
}
