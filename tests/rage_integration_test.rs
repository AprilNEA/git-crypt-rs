#![cfg(feature = "ssh")]

mod common;

use common::{create_git_repo, git_crypt_cmd};
use predicates::prelude::*;
use std::fs;

const TEST_SSH_ED25519_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";
const TEST_SSH_ED25519_SK: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----"#;

#[test]
fn add_ssh_user_and_import_age_key_round_trip() {
    // Producer repository creates the shared key
    let producer = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(producer.path())
        .assert()
        .success();

    let pub_path = producer.path().join("alice.pub");
    fs::write(&pub_path, TEST_SSH_ED25519_PUB).unwrap();

    git_crypt_cmd()
        .args([
            "add-ssh-user",
            "--ssh-key",
            pub_path.to_str().unwrap(),
            "--alias",
            "alice",
        ])
        .current_dir(producer.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted key saved"));

    let shared_age_key = producer.path().join(".git/git-crypt/keys/age/alice.age");
    assert!(shared_age_key.exists());

    // Consumer repository imports the key using their SSH identity
    let consumer = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(consumer.path())
        .assert()
        .success();

    let age_copy = consumer.path().join("alice.age");
    fs::copy(&shared_age_key, &age_copy).unwrap();
    let identity_path = consumer.path().join("alice");
    fs::write(&identity_path, TEST_SSH_ED25519_SK).unwrap();

    git_crypt_cmd()
        .args([
            "import-age-key",
            "--input",
            age_copy.to_str().unwrap(),
            "--identity",
            identity_path.to_str().unwrap(),
        ])
        .current_dir(consumer.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("imported successfully"));

    assert!(consumer.path().join(".git/git-crypt/keys/default").exists());
}

#[test]
fn add_ssh_user_requires_ssh_key_argument() {
    let repo = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(repo.path())
        .assert()
        .success();

    git_crypt_cmd()
        .args(["add-ssh-user", "--alias", "test"])
        .current_dir(repo.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("<SSH_KEY>"));
}

#[test]
fn add_ssh_user_rejects_invalid_ssh_key() {
    let repo = create_git_repo();
    git_crypt_cmd()
        .arg("init")
        .current_dir(repo.path())
        .assert()
        .success();

    let bogus_key = repo.path().join("invalid.pub");
    fs::write(&bogus_key, "this is not an ssh key").unwrap();

    git_crypt_cmd()
        .args([
            "add-ssh-user",
            "--ssh-key",
            bogus_key.to_str().unwrap(),
            "--alias",
            "invalid",
        ])
        .current_dir(repo.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid SSH recipient"));
}
