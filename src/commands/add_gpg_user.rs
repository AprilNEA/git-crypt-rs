use crate::error::{GitCryptError, Result};
use crate::git::GitRepo;
use crate::gpg::GpgManager;
use crate::key::KeyManager;
use std::fs;

/// Add a GPG user who can unlock the repository
pub fn add_gpg_user(gpg_id: &str) -> Result<()> {
    println!("Adding GPG user: {}", gpg_id);

    // Open repository
    let repo = GitRepo::open(".")?;
    let git_dir = repo.git_dir();

    let key_manager = KeyManager::new(git_dir);

    // Check if initialized
    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    // Load the symmetric key
    let key = key_manager.load_key()?;

    // Encrypt the key for this GPG user
    let encrypted_key = GpgManager::encrypt_key_for_recipient(&key, gpg_id)?;

    // Save the encrypted key
    let gpg_keys_dir = key_manager.git_crypt_dir().join("keys").join("gpg");
    fs::create_dir_all(&gpg_keys_dir)?;

    let key_file = gpg_keys_dir.join(format!("{}.key", gpg_id));
    fs::write(&key_file, encrypted_key)?;

    println!("Successfully added GPG user: {}", gpg_id);
    println!("Encrypted key saved to: {}", key_file.display());

    Ok(())
}
