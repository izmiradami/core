use lws_signer::{signer_for_chain, HdDeriver, Mnemonic};
use zeroize::Zeroize;

use crate::{parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    let mut mnemonic_str = super::resolve_mnemonic(wallet_name)?;
    let mnemonic = Mnemonic::from_phrase(&mnemonic_str)?;
    mnemonic_str.zeroize();

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| CliError::InvalidArgs(format!("invalid hex transaction: {e}")))?;

    let signer = signer_for_chain(chain);
    let path = signer.default_derivation_path(index);
    let curve = signer.curve();

    let key = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?;
    let output = signer.sign_transaction(key.expose(), &tx_bytes)?;

    if json_output {
        let obj = serde_json::json!({
            "signature": hex::encode(&output.signature),
            "recovery_id": output.recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", hex::encode(&output.signature));
    }

    Ok(())
}
