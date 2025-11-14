mod commands;
mod crypto;
mod error;
mod git;
mod gpg;
mod key;

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
        Commands::ExportKey { output } => commands::export_key(&output),
        Commands::ImportKey { input } => commands::import_key(&input),
        Commands::Clean => commands::clean(),
        Commands::Smudge => commands::smudge(),
        Commands::Diff => commands::diff(),
        Commands::Status => {
            println!("Status command not yet implemented");
            Ok(())
        }
    }
}
