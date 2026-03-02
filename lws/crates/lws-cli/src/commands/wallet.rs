use lws_core::{ChainType, EncryptedWallet, KeyType, WalletAccount};
use lws_signer::{encrypt, signer_for_chain, HdDeriver, Mnemonic, MnemonicStrength};

use crate::audit;
use crate::vault;
use crate::{parse_chain, CliError};

/// Returns a default CAIP-2 chain reference for a given chain type.
fn default_chain_reference(chain: ChainType) -> &'static str {
    match chain {
        ChainType::Evm => "1",
        ChainType::Solana => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        ChainType::Bitcoin => "000000000019d6689c085ae165831e93",
        ChainType::Cosmos => "cosmoshub-4",
        ChainType::Tron => "mainnet",
    }
}

pub fn create(name: &str, chain_str: &str, words: u32, show_mnemonic: bool) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    let strength = match words {
        12 => MnemonicStrength::Words12,
        24 => MnemonicStrength::Words24,
        _ => return Err(CliError::InvalidArgs("--words must be 12 or 24".into())),
    };

    // Prompt for passphrase (with confirmation)
    let passphrase = vault::get_passphrase(true)?;

    // Generate mnemonic
    let mnemonic = Mnemonic::generate(strength)?;
    let signer = signer_for_chain(chain);
    let path = signer.default_derivation_path(0);
    let curve = signer.curve();

    let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, curve)?;
    let address = signer.derive_address(key.expose())?;

    let chain_id_str = format!("{}:{}", chain.namespace(), default_chain_reference(chain));
    let account_id_str = format!("{chain_id_str}:{address}");

    // Encrypt the mnemonic entropy
    let phrase = mnemonic.phrase();
    let crypto_envelope = encrypt(phrase.expose(), &passphrase)?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet = EncryptedWallet::new(
        wallet_id.clone(),
        name.to_string(),
        chain,
        vec![WalletAccount {
            account_id: account_id_str,
            address: address.clone(),
            chain_id: chain_id_str.clone(),
            derivation_path: path.clone(),
        }],
        crypto_json,
        KeyType::Mnemonic,
    );

    vault::save_encrypted_wallet(&wallet)?;

    // Audit log
    audit::log_wallet_created(&wallet_id, &chain_id_str, &address);

    println!("Wallet created: {wallet_id}");
    println!("Name:           {name}");
    println!("Chain:          {chain}");
    println!("Address:        {address}");
    println!("Path:           {path}");

    if show_mnemonic {
        let phrase_str = String::from_utf8(phrase.expose().to_vec())
            .map_err(|e| CliError::InvalidArgs(format!("invalid UTF-8 in mnemonic: {e}")))?;
        eprintln!();
        eprintln!("⚠️  WARNING: The mnemonic below provides FULL ACCESS to this wallet.");
        eprintln!("⚠️  Store it securely offline. It will NOT be shown again.");
        eprintln!();
        println!("{phrase_str}");
    } else {
        eprintln!();
        eprintln!("Mnemonic encrypted and saved to vault.");
        eprintln!("Use --show-mnemonic at creation time if you need a backup copy.");
    }

    Ok(())
}

pub fn list() -> Result<(), CliError> {
    let wallets = vault::list_encrypted_wallets()?;

    if wallets.is_empty() {
        println!("No wallets found.");
        return Ok(());
    }

    for w in &wallets {
        println!("ID:      {}", w.id);
        println!("Name:    {}", w.name);
        println!("Chain:   {}", w.chain_type);
        println!("Secured: ✓ (encrypted)");
        for acct in &w.accounts {
            println!("  {} → {}", acct.chain_id, acct.address);
        }
        println!("Created: {}", w.created_at);
        println!();
    }

    Ok(())
}
