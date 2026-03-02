mod audit;
mod commands;
mod vault;

use clap::{Parser, Subcommand};
use lws_core::{ChainType, LwsError};
use lws_signer::hd::HdError;
use lws_signer::mnemonic::MnemonicError;
use lws_signer::{CryptoError, SignerError};

/// Lightweight Wallet Signer CLI
#[derive(Parser)]
#[command(name = "lws", version, about, long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("LWS_GIT_COMMIT"), ")"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new BIP-39 mnemonic phrase
    Generate {
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
    },
    /// Derive an address from a mnemonic (reads mnemonic from stdin)
    Derive {
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// Sign a message with a mnemonic-derived key (reads mnemonic from stdin)
    Sign {
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Message to sign
        #[arg(long)]
        message: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// Show vault path and supported chains
    Info,
    /// Create a new wallet (generates mnemonic, encrypts and saves to vault)
    CreateWallet {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
        /// Display the generated mnemonic (DANGEROUS — only for backup)
        #[arg(long)]
        show_mnemonic: bool,
    },
    /// List all saved wallets
    ListWallets,
    /// Update lws to the latest version
    Update {
        /// Force rebuild even if already on the latest commit
        #[arg(long)]
        force: bool,
    },
    /// Uninstall lws from the system
    Uninstall {
        /// Also remove all wallet data and config (~/.lws)
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Lws(#[from] LwsError),
    #[error("{0}")]
    Mnemonic(#[from] MnemonicError),
    #[error("{0}")]
    Hd(#[from] HdError),
    #[error("{0}")]
    Signer(#[from] SignerError),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    InvalidArgs(String),
}

fn parse_chain(s: &str) -> Result<ChainType, CliError> {
    s.parse::<ChainType>()
        .map_err(|e| CliError::InvalidArgs(e))
}

/// Read a mnemonic phrase from stdin (one line).
fn read_mnemonic_stdin() -> Result<String, CliError> {
    let mut line = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut line)?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no mnemonic provided on stdin — pipe it in: echo \"word1 word2 ...\" | lws derive ...".into(),
        ));
    }
    Ok(trimmed)
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Generate { words } => commands::generate::run(words),
        Commands::Derive { chain, index } => {
            let mnemonic = read_mnemonic_stdin()?;
            commands::derive::run(&mnemonic, &chain, index)
        }
        Commands::Sign {
            chain,
            message,
            index,
        } => {
            let mnemonic = read_mnemonic_stdin()?;
            commands::sign::run(&mnemonic, &chain, &message, index)
        }
        Commands::Info => commands::info::run(),
        Commands::CreateWallet {
            name,
            chain,
            words,
            show_mnemonic,
        } => commands::wallet::create(&name, &chain, words, show_mnemonic),
        Commands::ListWallets => commands::wallet::list(),
        Commands::Update { force } => commands::update::run(force),
        Commands::Uninstall { purge } => commands::uninstall::run(purge),
    }
}
