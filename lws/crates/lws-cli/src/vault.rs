use lws_core::{Config, EncryptedWallet};
use std::fs;
use std::path::PathBuf;

use crate::CliError;

/// Returns the wallets directory, creating it with strict permissions if necessary.
pub fn wallets_dir() -> Result<PathBuf, CliError> {
    let config = Config::default();
    let vault = &config.vault_path;

    // Create vault root and wallets dir
    let dir = vault.join("wallets");
    fs::create_dir_all(&dir)?;

    // Set strict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(vault, fs::Permissions::from_mode(0o700));
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }

    Ok(dir)
}

/// Verify vault directory permissions are strict (owner-only).
/// Returns an error if the vault is world-readable or group-readable.
#[cfg(unix)]
pub fn verify_permissions(path: &std::path::Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();

    // Check that group and other have no access (last 6 bits should be 0)
    if mode & 0o077 != 0 {
        return Err(CliError::InvalidArgs(format!(
            "vault directory {} has insecure permissions {:o} — expected 700. \
             Fix with: chmod 700 {}",
            path.display(),
            mode & 0o777,
            path.display(),
        )));
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn verify_permissions(_path: &std::path::Path) -> Result<(), CliError> {
    Ok(())
}

/// Save an encrypted wallet file with strict permissions.
pub fn save_encrypted_wallet(wallet: &EncryptedWallet) -> Result<(), CliError> {
    let dir = wallets_dir()?;
    let path = dir.join(format!("{}.json", wallet.id));
    let json = serde_json::to_string_pretty(wallet)?;
    fs::write(&path, json)?;

    // Set file permissions to 600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Load all encrypted wallets from the vault.
/// Verifies directory permissions first.
/// Returns wallets sorted by created_at descending (newest first).
pub fn list_encrypted_wallets() -> Result<Vec<EncryptedWallet>, CliError> {
    let dir = wallets_dir()?;

    // Verify permissions before reading
    let config = Config::default();
    verify_permissions(&config.vault_path)?;

    let mut wallets = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(wallets),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<EncryptedWallet>(&contents) {
                Ok(w) => wallets.push(w),
                Err(e) => {
                    eprintln!("warning: skipping {}: {e}", path.display());
                }
            },
            Err(e) => {
                eprintln!("warning: skipping {}: {e}", path.display());
            }
        }
    }

    wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(wallets)
}

/// Prompt the user for a passphrase (with confirmation for new wallets).
pub fn prompt_passphrase(confirm: bool) -> Result<String, CliError> {
    let pass = rpassword::prompt_password("Enter vault passphrase: ")
        .map_err(|e| CliError::InvalidArgs(format!("failed to read passphrase: {e}")))?;

    if pass.len() < 12 {
        return Err(CliError::InvalidArgs(
            "passphrase must be at least 12 characters".into(),
        ));
    }

    if confirm {
        let pass2 = rpassword::prompt_password("Confirm vault passphrase: ")
            .map_err(|e| CliError::InvalidArgs(format!("failed to read passphrase: {e}")))?;
        if pass != pass2 {
            return Err(CliError::InvalidArgs("passphrases do not match".into()));
        }
    }

    Ok(pass)
}

/// Read passphrase from LWS_PASSPHRASE env var, falling back to interactive prompt.
pub fn get_passphrase(confirm: bool) -> Result<String, CliError> {
    if let Ok(pass) = std::env::var("LWS_PASSPHRASE") {
        if pass.len() < 12 {
            return Err(CliError::InvalidArgs(
                "LWS_PASSPHRASE must be at least 12 characters".into(),
            ));
        }
        return Ok(pass);
    }
    prompt_passphrase(confirm)
}
