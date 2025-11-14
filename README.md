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
- 📦 **Simple CLI**: Easy-to-use command-line interface

## Installation

### Using cargo

```bash
cargo install git-crypt

# If you want GPG support, install with the gpg feature
cargo install git-crypt --features gpg
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

## Commands

- `init` - Initialize git-crypt in the current repository
- `lock` - Lock the repository (remove filters)
- `unlock [--key-file PATH]` - Unlock the repository
- `export-key OUTPUT` - Export the symmetric key to a file
- `import-key INPUT` - Import a symmetric key from a file
- `add-gpg-user GPG_ID` - Grant access to a GPG user (requires GPG feature)

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

### Building on macOS

The project auto-configures macOS SDK requirements on first build:

```bash
cargo build --features gpg
# If first build fails, simply run again:
cargo build --features gpg
```

The `build.rs` script automatically:
1. Detects your SDK path via `xcrun --show-sdk-path`
2. Creates `.cargo/config.toml` with `SDKROOT` configuration
3. Applies settings on the next build

Manual configuration (if needed):
```bash
export SDKROOT=$(xcrun --show-sdk-path)
cargo build --features gpg
```

### Cross-Platform Compatibility

The build system automatically handles platform-specific requirements:
- **macOS**: Auto-configures SDKROOT for C dependencies
- **Linux**: Checks for nettle/gmp installation and provides install instructions
- **Windows**: Provides guidance for dependency setup via vcpkg/MSYS2

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please open an issue or pull request.

---

**Note**: For complete documentation, examples, and API reference, please run `cargo doc --no-deps --open` or visit [docs.rs/git-crypt](https://docs.rs/git-crypt).
