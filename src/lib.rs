//! # git-crypt
//!
//! A Rust implementation of git-crypt for transparent encryption of files in a git repository.
//!
//! ## Features
//!
//! - **Transparent Encryption**: Files are automatically encrypted when committed and decrypted when checked out
//! - **AES-256-GCM Encryption**: Strong, authenticated encryption with built-in tamper detection
//! - **Git Filter Integration**: Uses git's clean/smudge filters for seamless operation
//! - **Key Management**: Export and import symmetric keys for secure sharing
//! - **GPG Support**: Optional GPG integration for team key distribution
//! - **Simple CLI**: Easy-to-use command-line interface
//!
//! ## Quick Start
//!
//! ### Installation
//!
//! Install from GitHub:
//! ```bash
//! cargo install --git https://github.com/AprilNEA/git-crypt-rs
//! ```
//!
//! Or build from source:
//! ```bash
//! cargo build --release
//! # Binary will be at target/release/git-crypt
//! ```
//!
//! ### Basic Usage
//!
//! ```bash
//! # Initialize in your git repository
//! git-crypt init
//!
//! # Configure which files to encrypt in .gitattributes
//! echo "*.secret filter=git-crypt diff=git-crypt" >> .gitattributes
//! git add .gitattributes
//! git commit -m "Configure git-crypt"
//!
//! # Add encrypted files (automatically encrypted)
//! echo "my secret data" > test.secret
//! git add test.secret
//! git commit -m "Add encrypted file"
//!
//! # Export key for sharing
//! git-crypt export-key git-crypt-key.bin
//! ```
//!
//! ## How It Works
//!
//! git-crypt uses git's filter system to transparently encrypt and decrypt files:
//!
//! 1. **Clean filter** (encryption): When you `git add` a file, the clean filter encrypts it before storing in the repository
//! 2. **Smudge filter** (decryption): When you `git checkout`, the smudge filter decrypts it in your working directory
//! 3. **Diff filter**: When you `git diff`, it shows that the file is encrypted rather than binary gibberish
//!
//! The encryption key is stored in `.git/git-crypt/keys/default` and is never committed to the repository.
//!
//! ### Data Flow
//!
//! **Encryption (git add):**
//! ```text
//! File content → git add → clean filter → encrypt → store in .git
//! ```
//!
//! **Decryption (git checkout):**
//! ```text
//! Encrypted data in .git → smudge filter → decrypt → working directory
//! ```
//!
//! ## Module Overview
//!
//! - [`crypto`] - Core AES-256-GCM encryption/decryption operations
//! - [`key`] - Key management, storage, export/import
//! - [`git`] - Git filter integration and repository operations
//! - [`gpg`] - Optional GPG support for key sharing (requires `gpg` feature)
//! - [`error`] - Error types and unified error handling
//!
//! ## Commands
//!
//! - `init` - Initialize git-crypt in the current repository
//! - `lock` - Lock the repository (remove filters, show encrypted content)
//! - `unlock [--key-file PATH]` - Unlock the repository
//! - `export-key OUTPUT` - Export the symmetric key to a file
//! - `import-key INPUT` - Import a symmetric key from a file
//! - `add-gpg-user GPG_ID` - Grant access to a GPG user (requires `gpg` feature)
//! - `status` - Show status of encrypted files (not yet implemented)
//!
//! ## Examples
//!
//! ### Complete Workflow
//!
//! ```bash
//! # 1. Initialize a git repository
//! git init my-secure-repo
//! cd my-secure-repo
//!
//! # 2. Initialize git-crypt
//! git-crypt init
//!
//! # 3. Configure encryption patterns in .gitattributes
//! cat > .gitattributes << 'EOF'
//! # Encrypt all files in the secrets/ directory
//! secrets/** filter=git-crypt diff=git-crypt
//!
//! # Encrypt specific file types
//! *.key filter=git-crypt diff=git-crypt
//! *.secret filter=git-crypt diff=git-crypt
//!
//! # Encrypt specific config files
//! config/database.yml filter=git-crypt diff=git-crypt
//! .env.production filter=git-crypt diff=git-crypt
//! EOF
//!
//! git add .gitattributes
//! git commit -m "Configure git-crypt"
//!
//! # 4. Add encrypted files
//! mkdir -p secrets
//! echo "AWS_SECRET_KEY=secret123" > secrets/api_keys.txt
//! git add secrets/
//! git commit -m "Add encrypted secrets"
//!
//! # 5. Share access with team members
//! git-crypt export-key team-key.bin
//! # Share team-key.bin securely (password manager, secure channel, etc.)
//! ```
//!
//! ### Unlocking on Another Machine
//!
//! ```bash
//! # Clone the repository
//! git clone <repository-url>
//! cd <repository>
//!
//! # At this point, encrypted files show as encrypted data
//!
//! # Unlock with the shared key
//! git-crypt unlock --key-file team-key.bin
//!
//! # Refresh working directory
//! git checkout HEAD -- .
//!
//! # Now files are decrypted
//! cat secrets/api_keys.txt
//! ```
//!
//! ### Lock/Unlock
//!
//! ```bash
//! # Lock repository (useful before sharing working directory)
//! git-crypt lock
//! # Now all encrypted files show their encrypted content
//!
//! # Unlock again
//! git-crypt unlock
//! git checkout HEAD -- .
//! ```
//!
//! ## Security Considerations
//!
//! ### Threat Model
//!
//! **Protected against:**
//! - Unauthorized access to repository content
//! - Accidental exposure of secrets in public repositories
//! - Historical secret leakage in git history
//!
//! **Not protected against:**
//! - Attacks on the working directory (files are plaintext there)
//! - Compromised git client or filters
//! - Key extraction from `.git` directory
//! - Side-channel attacks
//!
//! ### Best Practices
//!
//! 1. Keep `.git/git-crypt/` directory secure
//! 2. Use restrictive file permissions (automatic on Unix)
//! 3. Never commit key files to the repository
//! 4. Use GPG for team key distribution when possible
//! 5. Rotate keys if compromised
//! 6. Consider full-disk encryption for additional security
//! 7. Share exported keys through secure channels only
//!
//! ## Cryptography Details
//!
//! - **Algorithm**: AES-256-GCM (Galois/Counter Mode)
//! - **Key size**: 256 bits (32 bytes)
//! - **Nonce size**: 96 bits (12 bytes), randomly generated per encryption
//! - **Authentication**: Built into GCM mode (16-byte tag)
//!
//! ### Encrypted File Format
//!
//! ```text
//! [GITCRYPT][12-byte nonce][variable-length ciphertext + 16-byte GCM tag]
//! ```
//!
//! The magic header ensures reliable detection of encrypted data and provides
//! versioning capability for future format changes.
//!
//! ## GPG Support (Optional)
//!
//! To enable GPG support, install system dependencies and build with the `gpg` feature:
//!
//! **macOS:**
//! ```bash
//! brew install nettle gmp
//! cargo install --git https://github.com/AprilNEA/git-crypt-rs --features gpg
//! ```
//!
//! **Ubuntu/Debian:**
//! ```bash
//! sudo apt-get install libnettle-dev libgmp-dev
//! cargo install --git https://github.com/AprilNEA/git-crypt-rs --features gpg
//! ```
//!
//! Then use GPG for key sharing:
//! ```bash
//! git-crypt add-gpg-user user@example.com
//! ```
//!
//! ## Compatibility
//!
//! **Not compatible with original git-crypt:**
//! - Different file format (magic header + nonce prepended)
//! - Different key storage location
//! - Different filter commands
//!
//! This is a complete reimplementation focusing on:
//! - Memory safety (Rust)
//! - Modern cryptography practices
//! - Simplicity and maintainability
//! - Optional features (GPG)
//!
//! ## Testing
//!
//! The project has a comprehensive test suite with **63 tests** covering:
//!
//! ### Unit Tests (29 tests)
//!
//! Run all unit tests:
//! ```bash
//! cargo test --lib
//! ```
//!
//! - **Crypto module** ([`crypto`]): Encryption correctness, authentication, edge cases
//! - **Key management** ([`key`]): File operations, permissions, key lifecycle
//!
//! ### Integration Tests (16 tests)
//!
//! Run all integration tests:
//! ```bash
//! cargo test --test integration_test
//! ```
//!
//! Tests complete workflows: initialization, lock/unlock, key export/import, multi-repo isolation.
//!
//! ### Filter Tests (6 tests)
//!
//! Run filter tests:
//! ```bash
//! cargo test --test filter_test
//! ```
//!
//! Tests git filter operations: clean (encrypt), smudge (decrypt), diff.
//!
//! ### Edge Case Tests (12 tests)
//!
//! Run edge case tests:
//! ```bash
//! cargo test --test edge_cases_test
//! ```
//!
//! Tests corner cases: large files (10MB), empty files, binary data, Unicode,
//! corruption detection, concurrency, permissions.
//!
//! ## Running All Tests
//!
//! ```bash
//! # Run all tests
//! cargo test
//!
//! # Run with output
//! cargo test -- --nocapture
//!
//! # Run with backtrace
//! RUST_BACKTRACE=1 cargo test
//!
//! # Run specific test
//! cargo test test_encrypt_decrypt
//! ```
//!
//! ## Test Coverage
//!
//! Generate coverage report (requires cargo-tarpaulin):
//! ```bash
//! cargo install cargo-tarpaulin
//! cargo tarpaulin --out Html
//! ```
//!
//! ## Security Testing
//!
//! Tests verify security properties:
//! - ✅ Authentication (wrong key fails decryption)
//! - ✅ Tamper detection (corrupted data rejected)
//! - ✅ File permissions (0600 on Unix)
//! - ✅ Key isolation (different repos use different keys)
//! - ✅ Nonce uniqueness (no nonce reuse)

// Library exports for testing
pub mod crypto;
pub mod error;
pub mod git;
pub mod gpg;
pub mod key;

// Re-export commonly used types
pub use crypto::CryptoKey;
pub use error::{GitCryptError, Result};
pub use git::GitRepo;
pub use key::KeyManager;
