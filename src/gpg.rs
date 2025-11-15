#[cfg(feature = "gpg")]
use pgp::{
    composed::{MessageBuilder, SignedPublicKey, SignedPublicSubKey},
    crypto::sym::SymmetricKeyAlgorithm,
    errors::Error as PgpError,
    packet::{KeyFlags, PublicKey, PublicSubkey},
};
#[cfg(feature = "gpg")]
use rand::rngs::OsRng;

use crate::crypto::CryptoKey;
use crate::error::{GitCryptError, Result};

pub struct GpgManager;

impl GpgManager {
    /// Encrypt a key for a GPG recipient using rPGP.
    #[cfg(feature = "gpg")]
    pub fn encrypt_key_for_recipient(
        key: &CryptoKey,
        recipient_fingerprint: &str,
    ) -> Result<Vec<u8>> {
        let signed_key = Self::get_public_key_from_keyring(recipient_fingerprint)?;
        let recipient = select_recipient_key(&signed_key).ok_or_else(|| {
            GitCryptError::Gpg(format!(
                "No encryption-capable keys found for recipient: {recipient_fingerprint}"
            ))
        })?;

        let mut rng = OsRng;
        let mut builder = MessageBuilder::from_bytes("", key.as_bytes().to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

        match recipient {
            RecipientKey::Primary(pk) => builder.encrypt_to_key(&mut rng, pk),
            RecipientKey::Subkey(subkey) => builder.encrypt_to_key(&mut rng, subkey),
        }
        .map_err(map_pgp_err)?;

        let mut encrypted = Vec::new();
        builder
            .to_writer(&mut rng, &mut encrypted)
            .map_err(map_pgp_err)?;

        Ok(encrypted)
    }

    /// Encrypt a key for a GPG recipient (no GPG support compiled in)
    #[cfg(not(feature = "gpg"))]
    pub fn encrypt_key_for_recipient(
        _key: &CryptoKey,
        _recipient_fingerprint: &str,
    ) -> Result<Vec<u8>> {
        Err(GitCryptError::Gpg(
            "GPG support not enabled. Rebuild with --features gpg".into(),
        ))
    }

    /// Decrypt a GPG-encrypted key
    #[cfg(feature = "gpg")]
    #[allow(dead_code)]
    pub fn decrypt_key(_encrypted_data: &[u8]) -> Result<CryptoKey> {
        // This is a placeholder - actual implementation would need:
        // 1. Access to private key material
        // 2. Proper decryption with rPGP
        // 3. Password handling for encrypted private keys

        Err(GitCryptError::Gpg(
            "GPG decryption via rPGP requires private key access - to be implemented".into(),
        ))
    }

    /// Decrypt a GPG-encrypted key (no GPG support compiled in)
    #[cfg(not(feature = "gpg"))]
    pub fn decrypt_key(_encrypted_data: &[u8]) -> Result<CryptoKey> {
        Err(GitCryptError::Gpg(
            "GPG support not enabled. Rebuild with --features gpg".into(),
        ))
    }

    /// Get a public key from the keyring
    #[cfg(feature = "gpg")]
    fn get_public_key_from_keyring(fingerprint: &str) -> Result<SignedPublicKey> {
        // This is a placeholder - actual implementation would:
        // 1. Query the GPG keyring (via gpg, gpgme, or another interface)
        // 2. Look up by fingerprint or key ID
        // 3. Return the signed public key for encryption

        Err(GitCryptError::Gpg(format!(
            "Certificate lookup not yet implemented for: {fingerprint}"
        )))
    }

    /// List available GPG keys
    #[cfg(feature = "gpg")]
    #[allow(dead_code)]
    pub fn list_keys() -> Result<Vec<String>> {
        // Placeholder for listing available GPG keys
        Err(GitCryptError::Gpg("Key listing not yet implemented".into()))
    }

    /// List available GPG keys (no GPG support compiled in)
    #[cfg(not(feature = "gpg"))]
    pub fn list_keys() -> Result<Vec<String>> {
        Err(GitCryptError::Gpg(
            "GPG support not enabled. Rebuild with --features gpg".into(),
        ))
    }
}

#[cfg(feature = "gpg")]
enum RecipientKey<'a> {
    Primary(&'a PublicKey),
    Subkey(&'a PublicSubkey),
}

#[cfg(feature = "gpg")]
fn select_recipient_key(signed_key: &SignedPublicKey) -> Option<RecipientKey<'_>> {
    signed_key
        .public_subkeys
        .iter()
        .find(|subkey| subkey_supports_encryption(subkey))
        .map(|subkey| RecipientKey::Subkey(&subkey.key))
        .or_else(|| Some(RecipientKey::Primary(&signed_key.primary_key)))
}

#[cfg(feature = "gpg")]
fn subkey_supports_encryption(subkey: &SignedPublicSubKey) -> bool {
    subkey
        .signatures
        .iter()
        .any(|sig| key_flags_allow_encryption(&sig.key_flags()))
}

#[cfg(feature = "gpg")]
fn key_flags_allow_encryption(flags: &KeyFlags) -> bool {
    flags.encrypt_comms() || flags.encrypt_storage()
}

#[cfg(feature = "gpg")]
fn map_pgp_err(err: PgpError) -> GitCryptError {
    GitCryptError::Gpg(err.to_string())
}
