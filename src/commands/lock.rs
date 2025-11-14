use crate::error::{GitCryptError, Result};
use crate::git::GitRepo;
use crate::key::KeyManager;

/// Lock the repository (remove filters and show encrypted content)
pub fn lock() -> Result<()> {
    println!("Locking repository...");

    // Open repository
    let repo = GitRepo::open(".")?;
    let git_dir = repo.git_dir();

    let key_manager = KeyManager::new(git_dir);

    // Check if initialized
    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    // Remove git filters
    repo.remove_filters()?;

    println!("Repository locked!");
    println!("\nEncrypted files will now show their encrypted content.");
    println!("Run 'git-crypt unlock' to restore access.");

    Ok(())
}
