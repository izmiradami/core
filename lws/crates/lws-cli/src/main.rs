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
#[command(name = "lws", version = env!("LWS_VERSION"), about, long_version = concat!(env!("LWS_VERSION"), " (", env!("LWS_GIT_COMMIT"), ")"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage wallets
    Wallet {
        #[command(subcommand)]
        subcommand: WalletCommands,
    },
    /// Sign messages and transactions
    Sign {
        #[command(subcommand)]
        subcommand: SignCommands,
    },
    /// Generate and derive from mnemonics
    Mnemonic {
        #[command(subcommand)]
        subcommand: MnemonicCommands,
    },
    /// View configuration and RPC endpoints
    Config {
        #[command(subcommand)]
        subcommand: ConfigCommands,
    },
    /// Update lws to the latest release
    Update {
        /// Re-download even if already on the latest version
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

#[derive(Subcommand)]
enum WalletCommands {
    /// Create a new wallet (generates mnemonic, encrypts and saves to vault)
    Create {
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
    /// Import an existing wallet from a mnemonic or private key
    Import {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Import a mnemonic phrase (from LWS_MNEMONIC env or stdin)
        #[arg(long)]
        mnemonic: bool,
        /// Import a raw private key (from LWS_PRIVATE_KEY env or stdin)
        #[arg(long)]
        private_key: bool,
        /// Account index for HD derivation (mnemonic only)
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// Export wallet secret (mnemonic or private key) to stdout
    Export {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
    },
    /// Delete a wallet from the vault
    Delete {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
        /// Confirm deletion (required)
        #[arg(long)]
        confirm: bool,
    },
    /// Rename a wallet
    Rename {
        /// Current wallet name or ID
        #[arg(long)]
        wallet: String,
        /// New wallet name
        #[arg(long)]
        new_name: String,
    },
    /// List all saved wallets
    List,
    /// Show vault path and supported chains
    Info,
}

#[derive(Subcommand)]
enum SignCommands {
    /// Sign a message with chain-specific formatting (EIP-191, Bitcoin message signing, etc.)
    Message {
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "LWS_WALLET")]
        wallet: String,
        /// Message to sign
        #[arg(long)]
        message: String,
        /// Message encoding: "utf8" or "hex"
        #[arg(long, default_value = "utf8")]
        encoding: String,
        /// EIP-712 typed data JSON (EVM only)
        #[arg(long)]
        typed_data: Option<String>,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
    },
    /// Sign a transaction (accepts hex-encoded unsigned transaction bytes)
    Tx {
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "LWS_WALLET")]
        wallet: String,
        /// Hex-encoded unsigned transaction bytes
        #[arg(long)]
        tx: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
    },
    /// Sign and broadcast a transaction
    SendTx {
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "LWS_WALLET")]
        wallet: String,
        /// Hex-encoded unsigned transaction bytes
        #[arg(long)]
        tx: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
        /// Override configured RPC URL
        #[arg(long)]
        rpc_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum MnemonicCommands {
    /// Generate a new BIP-39 mnemonic phrase
    Generate {
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
    },
    /// Derive an address from a mnemonic (reads from LWS_MNEMONIC env or stdin)
    Derive {
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration and RPC endpoints
    Show,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Lws(#[from] LwsError),
    #[error("{0}")]
    Lib(#[from] lws_lib::LwsLibError),
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

pub(crate) fn parse_chain(s: &str) -> Result<ChainType, CliError> {
    s.parse::<ChainType>()
        .map_err(|e| CliError::InvalidArgs(e))
}

fn main() {
    lws_signer::process_hardening::harden_process();

    // Eagerly initialize the global key cache and register it for zeroization
    // on termination signals (SIGTERM, SIGINT, SIGHUP).
    let cache = lws_signer::global_key_cache();
    lws_signer::process_hardening::register_cleanup(move || cache.clear());
    lws_signer::process_hardening::install_signal_handlers();

    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    };

    // Explicitly zeroize all cached key material before exiting.
    lws_signer::global_key_cache().clear();
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Wallet { subcommand } => match subcommand {
            WalletCommands::Create {
                name,
                chain,
                words,
                show_mnemonic,
            } => commands::wallet::create(&name, &chain, words, show_mnemonic),
            WalletCommands::Import {
                name,
                chain,
                mnemonic,
                private_key,
                index,
            } => commands::wallet::import(&name, &chain, mnemonic, private_key, index),
            WalletCommands::Export { wallet } => commands::wallet::export(&wallet),
            WalletCommands::Delete { wallet, confirm } => {
                commands::wallet::delete(&wallet, confirm)
            }
            WalletCommands::Rename { wallet, new_name } => {
                commands::wallet::rename(&wallet, &new_name)
            }
            WalletCommands::List => commands::wallet::list(),
            WalletCommands::Info => commands::info::run(),
        },
        Commands::Sign { subcommand } => match subcommand {
            SignCommands::Message {
                chain,
                wallet,
                message,
                encoding,
                typed_data,
                index,
                json,
            } => commands::sign_message::run(
                &chain,
                &wallet,
                &message,
                &encoding,
                typed_data.as_deref(),
                index,
                json,
            ),
            SignCommands::Tx {
                chain,
                wallet,
                tx,
                index,
                json,
            } => commands::sign_transaction::run(&chain, &wallet, &tx, index, json),
            SignCommands::SendTx {
                chain,
                wallet,
                tx,
                index,
                json,
                rpc_url,
            } => commands::send_transaction::run(
                &chain,
                &wallet,
                &tx,
                index,
                json,
                rpc_url.as_deref(),
            ),
        },
        Commands::Mnemonic { subcommand } => match subcommand {
            MnemonicCommands::Generate { words } => commands::generate::run(words),
            MnemonicCommands::Derive { chain, index } => commands::derive::run(&chain, index),
        },
        Commands::Config { subcommand } => match subcommand {
            ConfigCommands::Show => commands::config::show(),
        },
        Commands::Update { force } => commands::update::run(force),
        Commands::Uninstall { purge } => commands::uninstall::run(purge),
    }
}
