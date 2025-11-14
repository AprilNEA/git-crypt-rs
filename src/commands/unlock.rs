use crate::error::{GitCryptError, Result};
use crate::git::GitRepo;
use crate::key::KeyManager;
use std::path::Path;

/// Unlock the repository (make encrypted files readable)
pub fn unlock(key_file: Option<&Path>) -> Result<()> {
    println!("Unlocking repository...");

    // Open repository
    let repo = GitRepo::open(".")?;
    let git_dir = repo.git_dir();

    let key_manager = KeyManager::new(git_dir);

    // Check if initialized
    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    // If key file provided, import it
    if let Some(key_path) = key_file {
        println!("Importing key from: {}", key_path.display());
        key_manager.import_key(key_path)?;
    }

    // Try to load the key to verify it exists
    let _key = key_manager.load_key()?;

    // Configure filters
    repo.configure_filters()?;

    println!("Repository unlocked successfully!");
    println!("\nRun 'git checkout HEAD -- .' to decrypt all tracked files");

    Ok(())
}
