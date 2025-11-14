use thiserror::Error;

#[derive(Error, Debug)]
pub enum GitCryptError {
    #[error("Git error: {0}")]
    Git(#[from] git2::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("GPG error: {0}")]
    Gpg(String),

    #[error("Repository not initialized. Run 'git-crypt init' first")]
    NotInitialized,

    #[error("Repository already initialized")]
    AlreadyInitialized,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Not in a git repository")]
    NotInGitRepo,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, GitCryptError>;
