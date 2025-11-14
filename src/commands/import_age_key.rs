use std::fs;
use std::path::Path;

use crate::error::{GitCryptError, Result};
use crate::git::GitRepo;
use crate::key::KeyManager;
use crate::rage_support::RageManager;

/// Import an age/rage-encrypted key using an SSH identity.
pub fn import_age_key(encrypted_path: &Path, identity_path: &Path) -> Result<()> {
    println!(
        "Importing age key from {} using identity {}",
        encrypted_path.display(),
        identity_path.display()
    );

    let repo = GitRepo::open(".")?;
    let key_manager = KeyManager::new(repo.git_dir());

    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    let encrypted = fs::read(encrypted_path)?;
    let identity = fs::read_to_string(identity_path)?;
    let identity_label = identity_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ssh identity");

    let key =
        RageManager::decrypt_key_with_ssh_identity(&encrypted, &identity, identity_label)?;

    key_manager.save_key(&key)?;

    println!("Repository key imported successfully using SSH identity.");
    Ok(())
}
