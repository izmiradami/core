use std::io::IsTerminal;

use lws_core::{default_chain_for_type, EncryptedWallet, KeyType, WalletAccount, ALL_CHAIN_TYPES};
use lws_signer::{
    decrypt, encrypt, signer_for_chain, CryptoEnvelope, HdDeriver, Mnemonic, MnemonicStrength,
};

use crate::audit;
use crate::vault;
use crate::CliError;

pub fn create(name: &str, words: u32, show_mnemonic: bool) -> Result<(), CliError> {
    let strength = match words {
        12 => MnemonicStrength::Words12,
        24 => MnemonicStrength::Words24,
        _ => return Err(CliError::InvalidArgs("--words must be 12 or 24".into())),
    };

    // Generate mnemonic
    let mnemonic = Mnemonic::generate(strength)?;

    // Derive addresses for all chains
    let accounts = derive_all_accounts_from_mnemonic(&mnemonic, 0)?;

    // Encrypt the mnemonic entropy
    let phrase = mnemonic.phrase();
    let crypto_envelope = encrypt(phrase.expose(), "")?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet = EncryptedWallet::new(
        wallet_id.clone(),
        name.to_string(),
        accounts.clone(),
        crypto_json,
        KeyType::Mnemonic,
    );

    vault::save_encrypted_wallet(&wallet)?;

    // Audit log — log all accounts
    audit::log_wallet_created(&wallet_id, &accounts);

    println!("Wallet created: {wallet_id}");
    println!("Name:           {name}");
    println!();
    for acct in &accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

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

pub fn import(
    name: &str,
    use_mnemonic: bool,
    use_private_key: bool,
    chain: Option<&str>,
    index: u32,
) -> Result<(), CliError> {
    if use_mnemonic == use_private_key {
        return Err(CliError::InvalidArgs(
            "specify exactly one of --mnemonic or --private-key".into(),
        ));
    }

    let (accounts, secret_bytes, key_type) = if use_mnemonic {
        let phrase = super::read_mnemonic()?;
        let mnemonic = Mnemonic::from_phrase(&phrase)?;
        let accts = derive_all_accounts_from_mnemonic(&mnemonic, index)?;
        let phrase_bytes = mnemonic.phrase();
        (accts, phrase_bytes.expose().to_vec(), KeyType::Mnemonic)
    } else {
        let hex_key = super::read_private_key()?;
        let hex_trimmed = hex_key.strip_prefix("0x").unwrap_or(&hex_key);
        let key_bytes = hex::decode(hex_trimmed)
            .map_err(|e| CliError::InvalidArgs(format!("invalid hex private key: {e}")))?;
        // Determine curve from source chain (default: secp256k1)
        let source_curve = match chain {
            Some(c) => {
                let parsed = lws_core::parse_chain(c).map_err(|e| CliError::InvalidArgs(e))?;
                signer_for_chain(parsed.chain_type).curve()
            }
            None => lws_signer::Curve::Secp256k1,
        };
        // Generate random key for the other curve
        let mut other_key = vec![0u8; 32];
        getrandom::getrandom(&mut other_key)
            .map_err(|e| CliError::InvalidArgs(format!("failed to generate random key: {e}")))?;
        let keys = match source_curve {
            lws_signer::Curve::Secp256k1 => (key_bytes, other_key),
            lws_signer::Curve::Ed25519 => (other_key, key_bytes),
        };
        let payload = serde_json::json!({
            "secp256k1": hex::encode(&keys.0),
            "ed25519": hex::encode(&keys.1),
        })
        .to_string()
        .into_bytes();
        let accts = derive_all_accounts_from_keys(&keys.0, &keys.1)?;
        (accts, payload, KeyType::PrivateKey)
    };

    let crypto_envelope = encrypt(&secret_bytes, "")?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet = EncryptedWallet::new(
        wallet_id.clone(),
        name.to_string(),
        accounts.clone(),
        crypto_json,
        key_type,
    );

    vault::save_encrypted_wallet(&wallet)?;
    audit::log_wallet_imported(&wallet_id, &accounts);

    println!("Wallet imported: {wallet_id}");
    println!("Name:            {name}");
    println!();
    for acct in &accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

    Ok(())
}

pub fn export(wallet_name: &str) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::InvalidArgs(
            "wallet export requires an interactive terminal (do not pipe stdin)".into(),
        ));
    }

    let wallet = vault::load_wallet_by_name_or_id(wallet_name)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;

    // Try empty passphrase first, then prompt if it fails
    let secret = match decrypt(&envelope, "") {
        Ok(s) => s,
        Err(_) => {
            let passphrase = super::read_passphrase();
            decrypt(&envelope, &passphrase)?
        }
    };

    match wallet.key_type {
        KeyType::Mnemonic => {
            let phrase = String::from_utf8(secret.expose().to_vec())
                .map_err(|_| CliError::InvalidArgs("wallet contains invalid mnemonic".into()))?;
            eprintln!();
            eprintln!("WARNING: The mnemonic below provides FULL ACCESS to this wallet.");
            eprintln!("Do not share it. Store it securely offline.");
            eprintln!();
            println!("{phrase}");
        }
        KeyType::PrivateKey => {
            let hex_key = hex::encode(secret.expose());
            eprintln!();
            eprintln!("WARNING: The private key below provides FULL ACCESS to this wallet.");
            eprintln!("Do not share it. Store it securely offline.");
            eprintln!();
            println!("{hex_key}");
        }
    }

    audit::log_wallet_exported(&wallet.id);
    Ok(())
}

pub fn delete(wallet_name: &str, confirm: bool) -> Result<(), CliError> {
    if !confirm {
        eprintln!("To delete a wallet, pass --confirm.");
        eprintln!("Consider exporting it first: lws wallet export --wallet {wallet_name}");
        return Err(CliError::InvalidArgs(
            "--confirm is required to delete a wallet".into(),
        ));
    }

    let wallet = vault::load_wallet_by_name_or_id(wallet_name)?;
    let id = wallet.id.clone();
    let name = wallet.name.clone();

    vault::delete_wallet(&id)?;
    audit::log_wallet_deleted(&id, &name);

    println!("Wallet deleted: {id} ({name})");
    Ok(())
}

pub fn rename(wallet_name: &str, new_name: &str) -> Result<(), CliError> {
    let mut wallet = vault::load_wallet_by_name_or_id(wallet_name)?;

    if wallet.name == new_name {
        return Ok(());
    }

    if vault::wallet_name_exists(new_name)? {
        return Err(CliError::InvalidArgs(format!(
            "a wallet named '{new_name}' already exists"
        )));
    }

    let old_name = wallet.name.clone();
    wallet.name = new_name.to_string();
    vault::save_encrypted_wallet(&wallet)?;
    audit::log_wallet_renamed(&wallet.id, &old_name, new_name);

    println!("Wallet renamed: '{}' -> '{}'", old_name, new_name);
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
        println!("Secured: ✓ (encrypted)");
        for acct in &w.accounts {
            println!("  {} → {}", acct.chain_id, acct.address);
        }
        println!("Created: {}", w.created_at);
        println!();
    }

    Ok(())
}

// --- helpers ---

fn derive_all_accounts_from_mnemonic(
    mnemonic: &Mnemonic,
    index: u32,
) -> Result<Vec<WalletAccount>, CliError> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let chain = default_chain_for_type(*ct);
        let signer = signer_for_chain(*ct);
        let path = signer.default_derivation_path(index);
        let curve = signer.curve();
        let key = HdDeriver::derive_from_mnemonic(mnemonic, "", &path, curve)?;
        let address = signer.derive_address(key.expose())?;
        let account_id = format!("{}:{}", chain.chain_id, address);
        accounts.push(WalletAccount {
            account_id,
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: path,
        });
    }
    Ok(accounts)
}

fn derive_all_accounts_from_keys(
    secp256k1_key: &[u8],
    ed25519_key: &[u8],
) -> Result<Vec<WalletAccount>, CliError> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let signer = signer_for_chain(*ct);
        let key = match signer.curve() {
            lws_signer::Curve::Secp256k1 => secp256k1_key,
            lws_signer::Curve::Ed25519 => ed25519_key,
        };
        let chain = default_chain_for_type(*ct);
        let address = signer.derive_address(key)?;
        accounts.push(WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, address),
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: String::new(),
        });
    }
    Ok(accounts)
}
