use lws_core::EncryptedWallet;

use crate::CliError;

// Delegate vault operations to lws-lib, using the default vault path.

pub fn save_encrypted_wallet(wallet: &EncryptedWallet) -> Result<(), CliError> {
    Ok(lws_lib::vault::save_encrypted_wallet(wallet, None)?)
}

pub fn list_encrypted_wallets() -> Result<Vec<EncryptedWallet>, CliError> {
    Ok(lws_lib::vault::list_encrypted_wallets(None)?)
}

pub fn load_wallet_by_name_or_id(name_or_id: &str) -> Result<EncryptedWallet, CliError> {
    Ok(lws_lib::vault::load_wallet_by_name_or_id(name_or_id, None)?)
}

pub fn delete_wallet(id: &str) -> Result<(), CliError> {
    Ok(lws_lib::vault::delete_wallet_file(id, None)?)
}

pub fn wallet_name_exists(name: &str) -> Result<bool, CliError> {
    Ok(lws_lib::vault::wallet_name_exists(name, None)?)
}
