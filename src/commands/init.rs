use crate::error::Result;
use crate::git::GitRepo;
use crate::key::KeyManager;

/// Initialize git-crypt in the repository
pub fn init() -> Result<()> {
    println!("Initializing git-crypt...");

    // Open repository
    let repo = GitRepo::open(".")?;
    let git_dir = repo.git_dir();

    // Initialize key manager
    let key_manager = KeyManager::new(git_dir);

    // Check if already initialized
    if key_manager.is_initialized() {
        println!("Repository already initialized for git-crypt");
        return Ok(());
    }

    // Create directory structure
    key_manager.init_dirs()?;

    // Generate and save key
    let _key = key_manager.generate_key()?;
    println!("Generated new encryption key");

    // Configure git filters
    repo.configure_filters()?;
    println!("Configured git filters");

    println!("\nInitialization complete!");
    println!("\nNext steps:");
    println!("1. Create a .gitattributes file to specify which files to encrypt");
    println!("   Example: echo 'secretfile filter=git-crypt diff=git-crypt' >> .gitattributes");
    println!("2. Commit the .gitattributes file");
    println!("3. Use 'git-crypt add-gpg-user' to grant access to other users");

    Ok(())
}
