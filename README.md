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
- ☁️ **S3 Sync (Optional)**: Upload encrypted key blobs to S3/MinIO when `sync-s3` is enabled
- 📦 **Simple CLI**: Easy-to-use command-line interface

## Installation

### Using cargo

```bash
cargo install git-crypt

# If you want GPG support, install with the gpg feature
cargo install git-crypt --features gpg

# If you want SSH/age support for sharing keys via SSH
cargo install git-crypt --features ssh

# SSH sharing with automatic S3 sync (requires ssh + sync-s3)
cargo install git-crypt --features "ssh,sync-s3"
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

Build with `--features ssh` (and optionally `sync-s3`) to share keys using SSH recipients powered by the Rust `age` implementation:

```bash
# Encrypt the repo key for an SSH public key (optionally sync to S3 when sync-s3 is enabled)
git-crypt add-ssh-user --ssh-key ~/.ssh/id_ed25519.pub --alias teammate

# Recipient decrypts using their private key
git-crypt import-age-key --input s3://team/repo/keys/age/teammate.age --identity ~/.ssh/id_ed25519
```

Key command flags:
- `--ssh-key <PATH>`: path to the recipient's SSH *public* key (OpenSSH format).
- `--alias <NAME>`: optional label used for the generated `.age` file; falls back to the key's comment or a fingerprint when omitted.
- `--input <FILE>`: the `.age` bundle produced by `add-ssh-user` (local path or S3 URL if synced).
- `--identity <PATH>`: the SSH *private* key used to decrypt the age file (works with encrypted keys; the CLI will prompt for a passphrase when needed).

This uses rage/age under the hood, so the resulting `.age` files are also compatible with the standalone `rage` CLI or any S3-compatible object storage if `sync-s3` uploads are enabled.

### S3 Sync (Optional `sync-s3` feature)

When the `sync-s3` feature is compiled together with `ssh`, git-crypt can automatically upload the encrypted `.age` blob to S3 or a compatible service (MinIO). Configure the behaviour by adding a `.git-crypt.toml` file in the repository root:

```toml
[sync_s3]
enabled = true
bucket = "git-crypt"
scope = "team-alpha"
repo = "demo-repo"   # optional, defaults to the folder name
region = "us-east-1"
endpoint = "http://localhost:9000"   # optional (useful for MinIO)
access_key = "minioadmin"
secret_key = "minioadmin"
path_style = true
```

Environment variables can override any of these settings or replace the file entirely. Supported keys:

- `GIT_CRYPT_SYNC_S3_BUCKET`
- `GIT_CRYPT_SYNC_S3_SCOPE`
- `GIT_CRYPT_SYNC_S3_REPO`
- `GIT_CRYPT_SYNC_S3_REGION`
- `GIT_CRYPT_SYNC_S3_ENDPOINT`
- `GIT_CRYPT_SYNC_S3_ACCESS_KEY`
- `GIT_CRYPT_SYNC_S3_SECRET_KEY`
- `GIT_CRYPT_SYNC_S3_ENABLED` (`1/0`, `true/false`)
- `GIT_CRYPT_SYNC_S3_PATH_STYLE` (`1/0`, `true/false`)

Example:

```bash
GIT_CRYPT_SYNC_S3_BUCKET=git-crypt \
GIT_CRYPT_SYNC_S3_SCOPE=team-alpha \
GIT_CRYPT_SYNC_S3_ENDPOINT=http://localhost:9000 \
GIT_CRYPT_SYNC_S3_ACCESS_KEY=minioadmin \
GIT_CRYPT_SYNC_S3_SECRET_KEY=minioadmin \
git-crypt add-ssh-user --ssh-key ~/.ssh/id_ed25519.pub --alias teammate
```

Each uploaded object follows the pattern `<scope>/<repo>/keys/age/<alias>.age`. To experiment locally you can use the provided `docker-compose.yaml`:

```bash
docker compose up -d
aws --endpoint-url http://localhost:9000 s3 mb s3://git-crypt

# then build git-crypt with ssh + sync-s3 features and run add-ssh-user
git-crypt add-ssh-user --ssh-key ~/.ssh/id_ed25519.pub --alias teammate

# run the sync integration test (requires Docker/MinIO running locally)
SYNC_S3_TEST=1 cargo test --features "ssh,sync-s3" sync_s3_test
```

By default the upload is best-effort: failures are reported as warnings but do not prevent the local `.age` file from being written.

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
