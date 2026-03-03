use lws_signer::{signer_for_chain, HdDeriver, Mnemonic};
use zeroize::Zeroize;

use crate::{parse_chain, CliError};

pub fn run(chain_str: &str, wallet_name: &str, message: &str, index: u32) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    let mut mnemonic_str = super::resolve_mnemonic(wallet_name)?;
    let mnemonic = Mnemonic::from_phrase(&mnemonic_str)?;
    mnemonic_str.zeroize();

    let signer = signer_for_chain(chain);
    let path = signer.default_derivation_path(index);
    let curve = signer.curve();

    let key = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?;
    let output = signer.sign_message(key.expose(), message.as_bytes())?;

    println!("{}", hex::encode(&output.signature));
    Ok(())
}
