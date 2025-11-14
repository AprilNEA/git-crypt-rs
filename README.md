# git-crypt

[![Crates.io](https://img.shields.io/crates/v/git-crypt.svg)](https://crates.io/crates/git-crypt)
[![Documentation](https://docs.rs/git-crypt/badge.svg)](https://docs.rs/git-crypt)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

A Rust implementation of git-crypt for transparent encryption of files in a git repository.

## Features

- 🔒 **Transparent Encryption**: Files are automatically encrypted when committed and decrypted when checked out
- 🛡️ **AES-256-GCM**: Strong authenticated encryption with tamper detection
- 🔧 **Git Filter Integration**: Seamless integration using git's clean/smudge filters
- 🔑 **Key Management**: Export and import symmetric keys for secure sharing
- 👥 **GPG Support**: Optional GPG integration for team key distribution
- 🪪 **SSH/age Sharing**: Optional age/rage integration to share keys using SSH recipients
- 📦 **Simple CLI**: Easy-to-use command-line interface

## Installation

### Using cargo

```bash
cargo install git-crypt

# If you want GPG support, install with the gpg feature
cargo install git-crypt --features gpg

# If you want SSH/age support for sharing keys via SSH
cargo install git-crypt --features ssh
```


## Quick Start

```bash
# Initialize in your git repository
git-crypt init

# Configure which files to encrypt in .gitattributes
echo "*.secret filter=git-crypt diff=git-crypt" >> .gitattributes
git add .gitattributes
git commit -m "Configure git-crypt"

# Add encrypted files (automatically encrypted)
echo "my secret data" > test.secret
git add test.secret
git commit -m "Add encrypted file"

# Export key for sharing
git-crypt export-key git-crypt-key.bin
```

## Documentation

**📚 [View Full Documentation](https://docs.rs/git-crypt)** (generated with `cargo doc`)

The complete documentation includes:
- Detailed usage examples
- Security considerations
- Architecture overview
- Complete API reference
- Testing guide

Generate documentation locally:
```bash
cargo doc --no-deps --open
```

## How It Works

git-crypt uses git's filter system to transparently encrypt and decrypt files:

1. **Clean filter**: Encrypts files when you `git add`
2. **Smudge filter**: Decrypts files when you `git checkout`
3. **Diff filter**: Shows encryption status in `git diff`

The encryption key is stored in `.git/git-crypt/keys/default` and is never committed.

## SSH/age Key Sharing (Optional)

Build with `--features ssh` to share keys using SSH recipients powered by the Rust `age` implementation:

```bash
# Encrypt the repo key for an SSH public key
git-crypt add-ssh-user --ssh-key ~/.ssh/id_ed25519.pub --alias teammate

# Recipient decrypts using their private key
git-crypt import-age-key --input .git/git-crypt/keys/age/teammate.age --identity ~/.ssh/id_ed25519
```

Key command flags:
- `--ssh-key <PATH>`: path to the recipient's SSH *public* key (OpenSSH format).
- `--alias <NAME>`: optional label used for the generated `.age` file; falls back to the key's comment or a fingerprint when omitted.
- `--input <FILE>`: the `.age` bundle produced by `add-ssh-user`.
- `--identity <PATH>`: the SSH *private* key used to decrypt the age file (works with encrypted keys; the CLI will prompt for a passphrase when needed).

This uses rage/age under the hood, so the resulting `.age` files are also compatible with the standalone `rage` CLI.

## Commands

- `init` - Initialize git-crypt in the current repository
- `lock` - Lock the repository (remove filters)
- `unlock [--key-file PATH]` - Unlock the repository
- `export-key OUTPUT` - Export the symmetric key to a file
- `import-key INPUT` - Import a symmetric key from a file
- `add-gpg-user GPG_ID` - Grant access to a GPG user (requires GPG feature)
- `add-ssh-user --ssh-key PATH [--alias NAME]` - Encrypt the key for an SSH user via age/rage (requires ssh feature)
- `import-age-key --input FILE --identity SSH_KEY` - Import an age-encrypted key with your SSH identity (requires ssh feature)

## Differences from Original git-crypt

This is a complete reimplementation with some differences:

- ✅ Written in Rust for memory safety and performance
- ✅ GPG support is optional (compile-time feature)
- ⚠️ Not compatible with original git-crypt (different file format)
- ✅ Focus on simplicity and modern Rust idioms

## Development

```bash
# Run tests
cargo test

# Build with GPG support
cargo build --release --features gpg

# Generate documentation
cargo doc --no-deps --open
```

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please open an issue or pull request.

---

**Note**: For complete documentation, examples, and API reference, please run `cargo doc --no-deps --open` or visit [docs.rs/git-crypt](https://docs.rs/git-crypt).
