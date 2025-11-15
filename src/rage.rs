use std::io::{Cursor, Read, Write};

use crate::crypto::CryptoKey;
use crate::error::{GitCryptError, Result};

use age::secrecy::SecretString;
use age::{
    ssh::{Identity as SshIdentity, Recipient as SshRecipient},
    Callbacks, DecryptError, Decryptor, EncryptError, Encryptor,
};
use rpassword::prompt_password;

pub struct RageManager;

impl RageManager {
    /// Encrypt the repo's symmetric key for an SSH recipient using age/rage tooling.
    pub fn encrypt_key_for_ssh_recipient(key: &CryptoKey, recipient: &str) -> Result<Vec<u8>> {
        let recipient: SshRecipient = recipient
            .trim()
            .parse()
            .map_err(|e| GitCryptError::Age(format!("Invalid SSH recipient: {e:?}")))?;

        let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as _))
            .map_err(map_encrypt_err)?;

        let mut ciphertext = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(GitCryptError::from)?;
        writer
            .write_all(key.as_bytes())
            .map_err(|e| GitCryptError::Io(e))?;
        writer.finish().map_err(GitCryptError::from)?;

        Ok(ciphertext)
    }

    /// Decrypt an age-encrypted key blob using an SSH identity.
    pub fn decrypt_key_with_ssh_identity(
        encrypted: &[u8],
        identity_content: &str,
        identity_label: &str,
    ) -> Result<CryptoKey> {
        let cursor = Cursor::new(identity_content.as_bytes());
        let identity = SshIdentity::from_buffer(cursor, Some(identity_label.to_string()))
            .map_err(|e| GitCryptError::Age(format!("Invalid SSH identity: {e}")))?;

        let decryptor = Decryptor::new_buffered(Cursor::new(encrypted)).map_err(map_decrypt_err)?;
        let identity = identity.with_callbacks(PromptCallbacks::new(identity_label));

        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(map_decrypt_err)?;
        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| GitCryptError::Io(e))?;

        CryptoKey::from_bytes(&plaintext)
    }
}

fn map_encrypt_err(err: EncryptError) -> GitCryptError {
    GitCryptError::Age(format!("age encryption failed: {err}"))
}

fn map_decrypt_err(err: DecryptError) -> GitCryptError {
    GitCryptError::Age(format!("age decryption failed: {err}"))
}

#[derive(Clone)]
struct PromptCallbacks {
    identity_label: String,
}

impl PromptCallbacks {
    fn new(identity_label: &str) -> Self {
        Self {
            identity_label: identity_label.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoKey, KEY_SIZE};

    const TEST_SSH_ED25519_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";
    const TEST_SSH_ED25519_SK: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=
-----END OPENSSH PRIVATE KEY-----"#;

    fn deterministic_key(byte: u8) -> CryptoKey {
        let bytes = vec![byte; KEY_SIZE];
        CryptoKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = deterministic_key(0xAA);
        let ciphertext =
            RageManager::encrypt_key_for_ssh_recipient(&key, TEST_SSH_ED25519_PUB).unwrap();
        let decrypted =
            RageManager::decrypt_key_with_ssh_identity(&ciphertext, TEST_SSH_ED25519_SK, "test")
                .unwrap();
        assert_eq!(decrypted.as_bytes(), key.as_bytes());
    }

    #[test]
    fn invalid_recipient_is_rejected() {
        let key = deterministic_key(0x11);
        let err = RageManager::encrypt_key_for_ssh_recipient(&key, "not-a-key").unwrap_err();
        match err {
            GitCryptError::Age(message) => {
                assert!(message.contains("Invalid SSH recipient"));
            }
            other => panic!("expected age error, got {other:?}"),
        }
    }
}

impl Callbacks for PromptCallbacks {
    fn display_message(&self, message: &str) {
        eprintln!("{message}");
    }

    fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        let prompt = if description.is_empty() {
            format!("Passphrase for {}", self.identity_label)
        } else {
            description.to_string()
        };

        match prompt_password(format!("{prompt}: ")) {
            Ok(passphrase) => Some(SecretString::new(passphrase.into())),
            Err(err) => {
                eprintln!("Failed to read passphrase: {err}");
                None
            }
        }
    }
}
