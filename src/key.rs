//! # Key Management
//!
//! This module handles encryption key storage, import, export, and lifecycle management.
//!
//! ## Key Storage
//!
//! Keys are stored in the git repository's internal directory:
//! - **Default key path**: `.git/git-crypt/keys/default`
//! - **Format**: Raw 32-byte binary data
//! - **Permissions**: 0600 on Unix (owner read/write only)
//! - **Never committed**: Keys stay in `.git/` directory
//!
//! ## Key Operations
//!
//! - **Generate**: Create new random 256-bit key
//! - **Save/Load**: Persist keys to/from filesystem
//! - **Export**: Save key to file for sharing
//! - **Import**: Load key from shared file
//!
//! ## Security Considerations
//!
//! - Keys are stored unencrypted in `.git/git-crypt/`
//! - File permissions are restricted to owner only (Unix)
//! - Exported key files must be shared securely
//! - Consider using GPG for team key distribution
//!
//! ## Unit Tests
//!
//! Run key management tests:
//! ```bash
//! cargo test key::
//! ```
//!
//! Tests cover:
//! - Directory path resolution
//! - Initialization and duplicate detection
//! - Key generation and persistence
//! - Export and import workflows
//! - File permissions (Unix)
//! - Error handling for missing files

use crate::crypto::CryptoKey;
use crate::error::{GitCryptError, Result};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Key storage and management
pub struct KeyManager {
    git_dir: PathBuf,
}

impl KeyManager {
    pub fn new(git_dir: impl AsRef<Path>) -> Self {
        Self {
            git_dir: git_dir.as_ref().to_path_buf(),
        }
    }

    /// Get the path to the git-crypt directory
    pub fn git_crypt_dir(&self) -> PathBuf {
        self.git_dir.join("git-crypt")
    }

    /// Get the path to the default key file
    pub fn default_key_path(&self) -> PathBuf {
        self.git_crypt_dir().join("keys").join("default")
    }

    /// Initialize the git-crypt directory structure
    pub fn init_dirs(&self) -> Result<()> {
        let git_crypt_dir = self.git_crypt_dir();
        if git_crypt_dir.exists() {
            return Err(GitCryptError::AlreadyInitialized);
        }

        fs::create_dir_all(&git_crypt_dir)?;
        fs::create_dir(git_crypt_dir.join("keys"))?;

        Ok(())
    }

    /// Check if repository is initialized
    pub fn is_initialized(&self) -> bool {
        self.git_crypt_dir().exists()
    }

    /// Generate and save a new key
    pub fn generate_key(&self) -> Result<CryptoKey> {
        let key = CryptoKey::generate();
        self.save_key(&key)?;
        Ok(key)
    }

    /// Save a key to disk
    pub fn save_key(&self, key: &CryptoKey) -> Result<()> {
        let key_path = self.default_key_path();
        fs::create_dir_all(key_path.parent().unwrap())?;

        let mut file = File::create(&key_path)?;
        file.write_all(key.as_bytes())?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_path, perms)?;
        }

        Ok(())
    }

    /// Load the key from disk
    pub fn load_key(&self) -> Result<CryptoKey> {
        let key_path = self.default_key_path();

        if !key_path.exists() {
            return Err(GitCryptError::KeyNotFound("default".into()));
        }

        let mut file = File::open(&key_path)?;
        let mut key_bytes = Vec::new();
        file.read_to_end(&mut key_bytes)?;

        CryptoKey::from_bytes(&key_bytes)
    }

    /// Export key to a file
    pub fn export_key(&self, output_path: impl AsRef<Path>) -> Result<()> {
        let key = self.load_key()?;
        let mut file = File::create(output_path.as_ref())?;
        file.write_all(key.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(output_path.as_ref())?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(output_path.as_ref(), perms)?;
        }

        Ok(())
    }

    /// Import key from a file
    pub fn import_key(&self, input_path: impl AsRef<Path>) -> Result<()> {
        let mut file = File::open(input_path)?;
        let mut key_bytes = Vec::new();
        file.read_to_end(&mut key_bytes)?;

        let key = CryptoKey::from_bytes(&key_bytes)?;
        self.save_key(&key)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_git_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn test_git_crypt_dir_path() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        let expected = temp.path().join("git-crypt");
        assert_eq!(key_manager.git_crypt_dir(), expected);
    }

    #[test]
    fn test_default_key_path() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        let expected = temp.path().join("git-crypt").join("keys").join("default");
        assert_eq!(key_manager.default_key_path(), expected);
    }

    #[test]
    fn test_is_initialized_false() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        assert!(!key_manager.is_initialized());
    }

    #[test]
    fn test_init_dirs() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        key_manager.init_dirs().unwrap();

        assert!(key_manager.git_crypt_dir().exists());
        assert!(key_manager.git_crypt_dir().join("keys").exists());
        assert!(key_manager.is_initialized());
    }

    #[test]
    fn test_init_dirs_twice_fails() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        key_manager.init_dirs().unwrap();
        let result = key_manager.init_dirs();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GitCryptError::AlreadyInitialized
        ));
    }

    #[test]
    fn test_generate_and_load_key() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        key_manager.init_dirs().unwrap();
        let key1 = key_manager.generate_key().unwrap();
        let key2 = key_manager.load_key().unwrap();

        // Keys should be the same
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_load_key_before_init_fails() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        let result = key_manager.load_key();
        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_key() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        key_manager.init_dirs().unwrap();

        let original_key = CryptoKey::generate();
        key_manager.save_key(&original_key).unwrap();

        let loaded_key = key_manager.load_key().unwrap();
        assert_eq!(original_key.as_bytes(), loaded_key.as_bytes());
    }

    #[test]
    fn test_export_and_import_key() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        key_manager.init_dirs().unwrap();
        let original_key = key_manager.generate_key().unwrap();

        let export_path = temp.path().join("exported.key");
        key_manager.export_key(&export_path).unwrap();

        // Verify export file exists
        assert!(export_path.exists());

        // Create new key manager for import test
        let temp2 = create_test_git_dir();
        let key_manager2 = KeyManager::new(temp2.path());
        key_manager2.init_dirs().unwrap();

        // Import the key
        key_manager2.import_key(&export_path).unwrap();
        let imported_key = key_manager2.load_key().unwrap();

        // Keys should match
        assert_eq!(original_key.as_bytes(), imported_key.as_bytes());
    }

    #[test]
    fn test_export_key_without_init_fails() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());

        let export_path = temp.path().join("exported.key");
        let result = key_manager.export_key(&export_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_import_invalid_key_file() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());
        key_manager.init_dirs().unwrap();

        // Create invalid key file (wrong size)
        let invalid_key_path = temp.path().join("invalid.key");
        fs::write(&invalid_key_path, b"too short").unwrap();

        let result = key_manager.import_key(&invalid_key_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_import_nonexistent_file() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());
        key_manager.init_dirs().unwrap();

        let result = key_manager.import_key("/nonexistent/path.key");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_file_permissions_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let temp = create_test_git_dir();
            let key_manager = KeyManager::new(temp.path());
            key_manager.init_dirs().unwrap();

            key_manager.generate_key().unwrap();

            let key_path = key_manager.default_key_path();
            let metadata = fs::metadata(&key_path).unwrap();
            let permissions = metadata.permissions();

            // Should be 0600 (owner read/write only)
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_multiple_save_overwrites() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());
        key_manager.init_dirs().unwrap();

        let key1 = CryptoKey::generate();
        key_manager.save_key(&key1).unwrap();

        let key2 = CryptoKey::generate();
        key_manager.save_key(&key2).unwrap();

        let loaded = key_manager.load_key().unwrap();

        // Should have the second key
        assert_eq!(key2.as_bytes(), loaded.as_bytes());
        assert_ne!(key1.as_bytes(), loaded.as_bytes());
    }

    #[test]
    fn test_key_survives_encrypt_decrypt() {
        let temp = create_test_git_dir();
        let key_manager = KeyManager::new(temp.path());
        key_manager.init_dirs().unwrap();

        let key = key_manager.generate_key().unwrap();
        let plaintext = b"Secret data";

        let ciphertext = key.encrypt(plaintext).unwrap();

        // Load key again and decrypt
        let loaded_key = key_manager.load_key().unwrap();
        let decrypted = loaded_key.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }
}
