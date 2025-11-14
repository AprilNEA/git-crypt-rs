mod commands;
mod crypto;
mod error;
mod git;
mod gpg;
mod key;
#[cfg(feature = "ssh")]
mod rage_support;

use clap::{Parser, Subcommand};
use error::Result;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "git-crypt")]
#[command(version = "0.1.0")]
#[command(about = "Transparent file encryption in git", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize git-crypt in the current repository
    Init,

    /// Unlock the repository (decrypt files)
    Unlock {
        /// Path to key file (optional)
        #[arg(short, long)]
        key_file: Option<PathBuf>,
    },

    /// Lock the repository (show encrypted content)
    Lock,

    /// Grant access to a GPG user
    AddGpgUser {
        /// GPG key ID or fingerprint
        gpg_id: String,
    },

    /// Grant access to an SSH user using age/rage
    #[cfg(feature = "ssh")]
    AddSshUser {
        /// Path to the SSH public key
        #[arg(long = "ssh-key", value_name = "SSH_KEY")]
        ssh_key: PathBuf,
        /// Optional alias used when storing the encrypted key
        #[arg(short, long)]
        alias: Option<String>,
    },

    /// Export the repository's symmetric key
    ExportKey {
        /// Output file path
        output: PathBuf,
    },

    /// Import a symmetric key
    ImportKey {
        /// Input file path
        input: PathBuf,
    },

    /// Import an age/rage-encrypted key using your SSH identity
    #[cfg(feature = "ssh")]
    ImportAgeKey {
        /// Path to the age-encrypted key blob
        #[arg(long = "input", value_name = "AGE_FILE")]
        input: PathBuf,
        /// Path to your SSH private key (identity)
        #[arg(long = "identity", value_name = "SSH_KEY")]
        identity: PathBuf,
    },

    /// Clean filter (used internally by git)
    Clean,

    /// Smudge filter (used internally by git)
    Smudge,

    /// Diff filter (used internally by git)
    Diff,

    /// Show status of encrypted files
    Status,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => commands::init(),
        Commands::Unlock { key_file } => commands::unlock(key_file.as_deref()),
        Commands::Lock => commands::lock(),
        Commands::AddGpgUser { gpg_id } => commands::add_gpg_user(&gpg_id),
        #[cfg(feature = "ssh")]
        Commands::AddSshUser { ssh_key, alias } => {
            commands::add_ssh_user(&ssh_key, alias.as_deref())
        }
        Commands::ExportKey { output } => commands::export_key(&output),
        Commands::ImportKey { input } => commands::import_key(&input),
        #[cfg(feature = "ssh")]
        Commands::ImportAgeKey { input, identity } => {
            commands::import_age_key(&input, &identity)
        }
        Commands::Clean => commands::clean(),
        Commands::Smudge => commands::smudge(),
        Commands::Diff => commands::diff(),
        Commands::Status => {
            println!("Status command not yet implemented");
            Ok(())
        }
    }
}
