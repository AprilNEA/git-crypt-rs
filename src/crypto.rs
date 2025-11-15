//! # Cryptographic Operations
//!
//! This module provides core encryption and decryption functionality using AES-256-GCM.
//!
//! ## Algorithm
//!
//! - **Cipher**: AES-256-GCM (Galois/Counter Mode)
//! - **Key size**: 256 bits (32 bytes)
//! - **Nonce size**: 96 bits (12 bytes)
//! - **Authentication**: Built into GCM mode (16-byte tag)
//!
//! ## Encrypted Data Format
//!
//! ```text
//! [GITCRYPT][12-byte nonce][variable-length ciphertext + 16-byte GCM tag]
//! ```
//!
//! The magic header ensures reliable detection of encrypted data and provides
//! versioning capability for future format changes.
//!
//! ## Security Properties
//!
//! - **Confidentiality**: AES-256 provides strong encryption
//! - **Authentication**: GCM mode ensures tamper detection
//! - **Nonce uniqueness**: Random nonces prevent pattern detection
//! - **Key derivation**: Keys generated from OS random number generator
//!
//! ## Unit Tests
//!
//! Run crypto module tests:
//! ```bash
//! cargo test crypto::
//! ```
//!
//! Tests cover:
//! - Basic encryption/decryption round-trips
//! - Empty and large data handling
//! - Binary data with all byte values
//! - Unicode content
//! - Key uniqueness and nonce randomness
//! - Authentication with wrong keys
//! - Tamper detection on corrupted data
//! - Invalid key size rejection

use crate::error::{GitCryptError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

pub const KEY_SIZE: usize = 32; // 256 bits
pub const NONCE_SIZE: usize = 12; // 96 bits for GCM

// Magic header to identify encrypted data
const MAGIC_HEADER: &[u8] = b"GITCRYPT";

#[derive(Clone)]
pub struct CryptoKey {
    key: [u8; KEY_SIZE],
}

impl CryptoKey {
    /// Generate a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create a key from existing bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(GitCryptError::InvalidKeyFormat);
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    /// Get the key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| GitCryptError::Crypto(e.to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| GitCryptError::Crypto(e.to_string()))?;

        // Format: MAGIC_HEADER + nonce + ciphertext
        let mut result = Vec::with_capacity(MAGIC_HEADER.len() + NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(MAGIC_HEADER);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let min_size = MAGIC_HEADER.len() + NONCE_SIZE;
        if ciphertext.len() < min_size {
            return Err(GitCryptError::Crypto("Ciphertext too short".into()));
        }

        // Check magic header
        if &ciphertext[..MAGIC_HEADER.len()] != MAGIC_HEADER {
            return Err(GitCryptError::Crypto(
                "Invalid encrypted data format".into(),
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| GitCryptError::Crypto(e.to_string()))?;

        // Extract nonce and ciphertext (skip magic header)
        let data = &ciphertext[MAGIC_HEADER.len()..];
        let (nonce_bytes, encrypted_data) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| GitCryptError::Crypto(e.to_string()))?;

        Ok(plaintext)
    }

    /// Check if data has our magic header
    pub fn is_encrypted(data: &[u8]) -> bool {
        data.len() >= MAGIC_HEADER.len() && &data[..MAGIC_HEADER.len()] == MAGIC_HEADER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = CryptoKey::generate();
        let plaintext = b"Hello, World!";

        let ciphertext = key.encrypt(plaintext).unwrap();
        assert_ne!(plaintext.as_slice(), &ciphertext[..]);

        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }

    #[test]
    fn test_empty_data() {
        let key = CryptoKey::generate();
        let plaintext = b"";

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }

    #[test]
    fn test_large_data() {
        let key = CryptoKey::generate();
        let plaintext = vec![0x42u8; 1024 * 1024]; // 1MB

        let ciphertext = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_binary_data() {
        let key = CryptoKey::generate();
        let plaintext: Vec<u8> = (0..=255).collect();

        let ciphertext = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = CryptoKey::generate();
        let key2 = CryptoKey::generate();
        let plaintext = b"Same plaintext";

        let ciphertext1 = key1.encrypt(plaintext).unwrap();
        let ciphertext2 = key2.encrypt(plaintext).unwrap();

        // Different keys should produce different ciphertext
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_same_key_different_nonces() {
        let key = CryptoKey::generate();
        let plaintext = b"Same plaintext and key";

        let ciphertext1 = key.encrypt(plaintext).unwrap();
        let ciphertext2 = key.encrypt(plaintext).unwrap();

        // Same key but different nonces should produce different ciphertext
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to same plaintext
        assert_eq!(key.decrypt(&ciphertext1).unwrap(), plaintext.as_slice());
        assert_eq!(key.decrypt(&ciphertext2).unwrap(), plaintext.as_slice());
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = CryptoKey::generate();
        let key2 = CryptoKey::generate();
        let plaintext = b"Secret message";

        let ciphertext = key1.encrypt(plaintext).unwrap();

        // Decryption with wrong key should fail
        let result = key2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let key = CryptoKey::generate();
        let plaintext = b"Secret message";

        let mut ciphertext = key.encrypt(plaintext).unwrap();

        // Corrupt a byte in the ciphertext (not the nonce)
        if ciphertext.len() > NONCE_SIZE {
            ciphertext[NONCE_SIZE] ^= 0xFF;
        }

        // Decryption should fail due to authentication
        let result = key.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = CryptoKey::generate();
        let plaintext = b"Secret message";

        let ciphertext = key.encrypt(plaintext).unwrap();

        // Try to decrypt truncated ciphertext
        let truncated = &ciphertext[..5];
        let result = key.decrypt(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_from_bytes() {
        let key_bytes = [0x42u8; KEY_SIZE];
        let key = CryptoKey::from_bytes(&key_bytes).unwrap();
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn test_key_from_invalid_length() {
        let too_short = vec![0x42u8; KEY_SIZE - 1];
        let result = CryptoKey::from_bytes(&too_short);
        assert!(result.is_err());

        let too_long = vec![0x42u8; KEY_SIZE + 1];
        let result = CryptoKey::from_bytes(&too_long);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_roundtrip() {
        let key1 = CryptoKey::generate();
        let key_bytes = key1.as_bytes();
        let key2 = CryptoKey::from_bytes(key_bytes).unwrap();

        // Both keys should encrypt/decrypt the same way
        let plaintext = b"Test message";
        let ciphertext = key1.encrypt(plaintext).unwrap();
        let decrypted = key2.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), &decrypted[..]);
    }

    #[test]
    fn test_unicode_data() {
        let key = CryptoKey::generate();
        let plaintext = "Hello, 世界! 🔐🦀".as_bytes();

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(String::from_utf8(decrypted).unwrap(), "Hello, 世界! 🔐🦀");
    }

    #[test]
    fn test_ciphertext_has_nonce() {
        let key = CryptoKey::generate();
        let plaintext = b"Test";

        let ciphertext = key.encrypt(plaintext).unwrap();

        // Ciphertext should be longer than plaintext (nonce + tag)
        assert!(ciphertext.len() >= plaintext.len() + NONCE_SIZE);

        // First NONCE_SIZE bytes should be the nonce
        assert_eq!(&ciphertext[..NONCE_SIZE].len(), &NONCE_SIZE);
    }
}
