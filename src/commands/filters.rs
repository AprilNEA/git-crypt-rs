use crate::error::{GitCryptError, Result};
use crate::git::{clean_filter, diff_filter, smudge_filter, GitRepo};
use crate::key::KeyManager;

/// Clean filter implementation (called by git during add/commit)
pub fn clean() -> Result<()> {
    let repo = GitRepo::open(".").map_err(|_| {
        GitCryptError::Other("Not in a git repository".into())
    })?;

    let key_manager = KeyManager::new(repo.git_dir());

    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    let key = key_manager.load_key()?;
    clean_filter(&key)
}

/// Smudge filter implementation (called by git during checkout)
pub fn smudge() -> Result<()> {
    let repo = GitRepo::open(".").map_err(|_| {
        GitCryptError::Other("Not in a git repository".into())
    })?;

    let key_manager = KeyManager::new(repo.git_dir());

    if !key_manager.is_initialized() {
        return Err(GitCryptError::NotInitialized);
    }

    let key = key_manager.load_key()?;
    smudge_filter(&key)
}

/// Diff filter implementation (called by git during diff)
pub fn diff() -> Result<()> {
    diff_filter()
}
