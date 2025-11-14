use crate::error::{GitCryptError, Result};
use crate::git::GitRepo;
use crate::key::KeyManager;
use std::path::Path;

/// Export the symmetric key to a file
pub fn export_key(output_path: &Path) -> Result<()> {
    println!("Exporting key to: {}", output_path.display());

    // Open repository
    let repo = GitRepo::open(".")?;
    let git_dir = repo.git_dir();

    let key_manager = KeyManager::new(git_dir);

    // Check if initialized
    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    // Export the key
    key_manager.export_key(output_path)?;

    println!("Key exported successfully!");
    println!("\nWARNING: Keep this key file secure!");
    println!("Anyone with this key can decrypt your encrypted files.");

    Ok(())
}

/// Import a symmetric key from a file
pub fn import_key(input_path: &Path) -> Result<()> {
    println!("Importing key from: {}", input_path.display());

    // Open repository
    let repo = GitRepo::open(".")?;
    let git_dir = repo.git_dir();

    let key_manager = KeyManager::new(git_dir);

    // Check if initialized
    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    // Import the key
    key_manager.import_key(input_path)?;

    println!("Key imported successfully!");

    Ok(())
}
