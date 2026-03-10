use lws_signer::chains::EvmSigner;
use lws_signer::{signer_for_chain, HdDeriver, Mnemonic, SecretBytes};

use super::WalletSecret;
use crate::{parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    message: &str,
    encoding: &str,
    typed_data: Option<&str>,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    let wallet_secret = super::resolve_wallet_secret(wallet_name)?;

    let signer = signer_for_chain(chain.chain_type);

    let key = match wallet_secret {
        WalletSecret::Mnemonic(phrase) => {
            let mnemonic = Mnemonic::from_phrase(&phrase)?;
            let path = signer.default_derivation_path(index);
            let curve = signer.curve();
            HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?
        }
        WalletSecret::PrivateKeys(secret) => {
            extract_key_for_curve(secret.expose(), signer.curve())?
        }
    };

    let output = if let Some(td_json) = typed_data {
        if chain.chain_type != lws_core::ChainType::Evm {
            return Err(CliError::InvalidArgs(
                "--typed-data is only supported for EVM chains".into(),
            ));
        }
        EvmSigner.sign_typed_data(key.expose(), td_json)?
    } else {
        let msg_bytes = match encoding {
            "utf8" => message.as_bytes().to_vec(),
            "hex" => hex::decode(message)
                .map_err(|e| CliError::InvalidArgs(format!("invalid hex message: {e}")))?,
            _ => {
                return Err(CliError::InvalidArgs(format!(
                    "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
                )))
            }
        };
        signer.sign_message(key.expose(), &msg_bytes)?
    };

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

fn extract_key_for_curve(
    json_bytes: &[u8],
    curve: lws_signer::Curve,
) -> Result<SecretBytes, CliError> {
    let s = String::from_utf8(json_bytes.to_vec())
        .map_err(|_| CliError::InvalidArgs("invalid key data".into()))?;
    let obj: serde_json::Value = serde_json::from_str(&s)?;
    let field = match curve {
        lws_signer::Curve::Secp256k1 => "secp256k1",
        lws_signer::Curve::Ed25519 => "ed25519",
    };
    let hex_key = obj[field]
        .as_str()
        .ok_or_else(|| CliError::InvalidArgs(format!("missing {field} key in wallet")))?;
    let bytes = hex::decode(hex_key)
        .map_err(|e| CliError::InvalidArgs(format!("invalid {field} hex: {e}")))?;
    Ok(SecretBytes::from_slice(&bytes))
}
