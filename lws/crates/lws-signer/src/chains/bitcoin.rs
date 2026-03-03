use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use lws_core::ChainType;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Bitcoin chain signer (BIP-84 native segwit / bech32).
pub struct BitcoinSigner {
    /// Human-readable part for bech32 encoding ("bc" mainnet, "tb" testnet).
    hrp: String,
}

impl BitcoinSigner {
    pub fn new(hrp: &str) -> Self {
        BitcoinSigner {
            hrp: hrp.to_string(),
        }
    }

    pub fn mainnet() -> Self {
        Self::new("bc")
    }

    pub fn testnet() -> Self {
        Self::new("tb")
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }

    /// Hash160: SHA256 then RIPEMD160 of the compressed public key.
    fn hash160(data: &[u8]) -> Vec<u8> {
        let sha256 = Sha256::digest(data);
        let ripemd = Ripemd160::digest(sha256);
        ripemd.to_vec()
    }
}

impl ChainSigner for BitcoinSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Bitcoin
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        0
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        // Compressed public key (33 bytes)
        let pubkey_compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();

        // Hash160
        let hash = Self::hash160(pubkey_bytes);

        // Bech32 segwit v0 encoding
        let hrp = bech32::Hrp::parse(&self.hrp)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;

        let address = bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, &hash)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;

        Ok(address)
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            )));
        }

        let signing_key = Self::signing_key(private_key)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(recovery_id.to_byte()),
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Bitcoin transaction signing: double SHA256 of the sighash preimage
        let hash = Sha256::digest(Sha256::digest(tx_bytes));
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Bitcoin message signing: double-SHA256 of prefixed message
        let prefix = b"\x18Bitcoin Signed Message:\n";
        let msg_len = message.len() as u8;
        let mut data = Vec::new();
        data.extend_from_slice(prefix);
        data.push(msg_len);
        data.extend_from_slice(message);

        let hash = Sha256::digest(Sha256::digest(&data));
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/84'/0'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_address_generator_point() {
        // Generator point G private key = 1 (0x0000...0001)
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);

        let signer = BitcoinSigner::mainnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert_eq!(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_testnet_prefix() {
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);

        let signer = BitcoinSigner::testnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(address.starts_with("tb1"));
    }

    #[test]
    fn test_derivation_path() {
        let signer = BitcoinSigner::mainnet();
        assert_eq!(signer.default_derivation_path(0), "m/84'/0'/0'/0/0");
        assert_eq!(signer.default_derivation_path(3), "m/84'/0'/0'/0/3");
    }

    #[test]
    fn test_deterministic() {
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);

        let signer = BitcoinSigner::mainnet();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_chain_properties() {
        let signer = BitcoinSigner::mainnet();
        assert_eq!(signer.chain_type(), ChainType::Bitcoin);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 0);
    }
}
