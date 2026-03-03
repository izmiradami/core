pub mod derive;
pub mod generate;
pub mod info;
pub mod sign;
pub mod sign_message;
pub mod sign_transaction;
pub mod uninstall;
pub mod update;
pub mod wallet;

use crate::{vault, CliError};
use lws_signer::process_hardening::clear_env_var;
use lws_signer::CryptoEnvelope;
use std::io::{self, BufRead, IsTerminal, Write};

/// Read mnemonic from LWS_MNEMONIC env var or stdin. Used by the `derive` command.
pub fn read_mnemonic() -> Result<String, CliError> {
    if let Some(value) = clear_env_var("LWS_MNEMONIC") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter mnemonic: ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no mnemonic provided (set LWS_MNEMONIC or pipe via stdin)".into(),
        ));
    }

    Ok(trimmed)
}

/// Look up a wallet by name or ID, decrypt its mnemonic, and return it.
pub fn resolve_mnemonic(wallet_name: &str) -> Result<String, CliError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let passphrase = vault::get_passphrase(false)?;
    let secret = lws_signer::decrypt(&envelope, &passphrase)?;
    String::from_utf8(secret.expose().to_vec())
        .map_err(|_| CliError::InvalidArgs("wallet contains invalid UTF-8 mnemonic".into()))
}
