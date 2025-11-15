use crate::crypto::CryptoKey;
use crate::error::{GitCryptError, Result};
use git2::Repository;
use std::io::{self, Read, Write};
use std::path::Path;

pub struct GitRepo {
    repo: Repository,
}

impl GitRepo {
    /// Open repository at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let repo = Repository::discover(path).map_err(|_| GitCryptError::NotInGitRepo)?;
        Ok(Self { repo })
    }

    /// Get the git directory path
    pub fn git_dir(&self) -> &Path {
        self.repo.path()
    }

    /// Configure git filters for git-crypt
    pub fn configure_filters(&self) -> Result<()> {
        let mut config = self.repo.config()?;

        // Set up clean filter (encrypts on add/commit)
        config.set_str("filter.git-crypt.clean", "git-crypt clean")?;

        // Set up smudge filter (decrypts on checkout)
        config.set_str("filter.git-crypt.smudge", "git-crypt smudge")?;

        // Don't diff encrypted files
        config.set_str("filter.git-crypt.diff", "git-crypt diff")?;

        // Required attribute
        config.set_bool("filter.git-crypt.required", true)?;

        Ok(())
    }

    /// Remove git-crypt filters
    pub fn remove_filters(&self) -> Result<()> {
        let mut config = self.repo.config()?;

        let _ = config.remove("filter.git-crypt.clean");
        let _ = config.remove("filter.git-crypt.smudge");
        let _ = config.remove("filter.git-crypt.diff");
        let _ = config.remove("filter.git-crypt.required");

        Ok(())
    }

    /// Get repository root path
    #[allow(dead_code)]
    pub fn workdir(&self) -> Result<&Path> {
        self.repo.workdir().ok_or(GitCryptError::Other(
            "Repository has no working directory".into(),
        ))
    }
}

/// Clean filter: encrypt file content
pub fn clean_filter(key: &CryptoKey) -> Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    // Check if already encrypted (has magic header)
    if CryptoKey::is_encrypted(&input) {
        io::stdout().write_all(&input)?;
        return Ok(());
    }

    let encrypted = key.encrypt(&input)?;

    // Write encrypted data to stdout
    io::stdout().write_all(&encrypted)?;

    Ok(())
}

/// Smudge filter: decrypt file content
pub fn smudge_filter(key: &CryptoKey) -> Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    // Check if encrypted
    if !CryptoKey::is_encrypted(&input) {
        io::stdout().write_all(&input)?;
        return Ok(());
    }

    let decrypted = key.decrypt(&input)?;

    // Write decrypted data to stdout
    io::stdout().write_all(&decrypted)?;

    Ok(())
}

/// Diff filter: show that file is encrypted
pub fn diff_filter() -> Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    if CryptoKey::is_encrypted(&input) {
        writeln!(
            io::stdout(),
            "*** This file is encrypted with git-crypt ***"
        )?;
    } else {
        io::stdout().write_all(&input)?;
    }

    Ok(())
}
