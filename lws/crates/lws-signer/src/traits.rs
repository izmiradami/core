use crate::curve::Curve;
use lws_core::ChainType;

/// Output of a signing operation.
#[derive(Debug, Clone)]
pub struct SignOutput {
    /// The raw signature bytes.
    pub signature: Vec<u8>,
    /// Recovery ID (for secp256k1 signatures). None for Ed25519.
    pub recovery_id: Option<u8>,
}

/// Trait for chain-specific signing operations.
///
/// All methods take raw `&[u8]` private keys — callers are responsible for
/// HD derivation and zeroization of key material.
pub trait ChainSigner: Send + Sync {
    /// The chain type this signer handles.
    fn chain_type(&self) -> ChainType;

    /// The elliptic curve used by this chain.
    fn curve(&self) -> Curve;

    /// The BIP-44 coin type for this chain.
    fn coin_type(&self) -> u32;

    /// Derive an on-chain address from a private key.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError>;

    /// Sign a pre-hashed message (32 bytes for secp256k1, raw message for ed25519).
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError>;

    /// Sign an arbitrary message with chain-specific prefixing/hashing.
    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError>;

    /// Sign an unsigned transaction. Each chain hashes the raw transaction
    /// bytes according to its own rules before signing.
    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError>;

    /// Returns the default BIP-44 derivation path template for this chain.
    fn default_derivation_path(&self, index: u32) -> String;
}

/// Errors that can occur during signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("address derivation failed: {0}")]
    AddressDerivationFailed(String),

    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
}
