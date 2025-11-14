use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{GitCryptError, Result};
use crate::git::GitRepo;
use crate::key::KeyManager;
use crate::rage_support::RageManager;

/// Add an SSH recipient using age/rage encryption.
pub fn add_ssh_user(ssh_key_path: &Path, alias: Option<&str>) -> Result<()> {
    println!(
        "Adding SSH (age) user from: {}",
        ssh_key_path.display()
    );

    let repo = GitRepo::open(".")?;
    let key_manager = KeyManager::new(repo.git_dir());

    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    let key = key_manager.load_key()?;
    let ssh_key = fs::read_to_string(ssh_key_path)?;
    let encrypted_key = RageManager::encrypt_key_for_ssh_recipient(&key, &ssh_key)?;

    let name = alias
        .map(sanitize_label)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| derive_recipient_name(&ssh_key, ssh_key_path));

    let age_dir = key_manager.git_crypt_dir().join("keys").join("age");
    fs::create_dir_all(&age_dir)?;
    let key_file = age_dir.join(format!("{name}.age"));
    fs::write(&key_file, encrypted_key)?;

    println!("Encrypted key saved to {}", key_file.display());
    println!("Share this file with the SSH user; they can decrypt it with rage/age.");

    Ok(())
}

fn derive_recipient_name(ssh_key: &str, ssh_key_path: &Path) -> String {
    ssh_key
        .split_whitespace()
        .nth(2)
        .map(sanitize_label)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            ssh_key_path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(sanitize_label)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| fallback_fingerprint(ssh_key))
}

fn sanitize_label(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect::<String>()
}

fn fallback_fingerprint(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let digest = hasher.finalize();
    format!("ssh-{}", hex::encode(&digest[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn sanitize_label_strips_invalid_chars() {
        assert_eq!(sanitize_label("alice@example.com"), "aliceexample.com");
        assert_eq!(sanitize_label("Team-Name_01"), "Team-Name_01");
        assert_eq!(sanitize_label("weird label!*"), "weirdlabel");
    }

    #[test]
    fn derive_recipient_prefers_comment_field() {
        let pubkey = "ssh-ed25519 AAAAC3 comment@example.com";
        let name = derive_recipient_name(pubkey, Path::new("id_ed25519.pub"));
        assert_eq!(name, "commentexample.com");
    }

    #[test]
    fn derive_recipient_falls_back_to_filename() {
        let pubkey = "ssh-ed25519 AAAAC3";
        let name = derive_recipient_name(pubkey, Path::new("keys/test-id.pub"));
        assert_eq!(name, "test-id");
    }

    #[test]
    fn fallback_fingerprint_is_deterministic() {
        let fp1 = fallback_fingerprint("ssh-ed25519 AAAAC3");
        let fp2 = fallback_fingerprint("ssh-ed25519 AAAAC3");
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("ssh-"));
    }
}
