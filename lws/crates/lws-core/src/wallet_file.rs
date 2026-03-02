use crate::chain::ChainType;
use serde::{Deserialize, Serialize};

/// The full on-disk wallet file format (extended Ethereum Keystore v3).
/// Written to `~/.lws/wallets/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub lws_version: u32,
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub chain_type: ChainType,
    pub accounts: Vec<WalletAccount>,
    pub crypto: serde_json::Value,
    pub key_type: KeyType,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub metadata: serde_json::Value,
}

/// An account entry within an encrypted wallet file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub account_id: String,
    pub address: String,
    pub chain_id: String,
    pub derivation_path: String,
}

/// Type of key material stored in the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    Mnemonic,
    PrivateKey,
}

impl EncryptedWallet {
    pub fn new(
        id: String,
        name: String,
        chain_type: ChainType,
        accounts: Vec<WalletAccount>,
        crypto: serde_json::Value,
        key_type: KeyType,
    ) -> Self {
        EncryptedWallet {
            lws_version: 1,
            id,
            name,
            created_at: chrono::Utc::now().to_rfc3339(),
            chain_type,
            accounts,
            crypto,
            key_type,
            metadata: serde_json::Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_wallet() -> EncryptedWallet {
        EncryptedWallet::new(
            "test-id".to_string(),
            "test-wallet".to_string(),
            ChainType::Evm,
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        )
    }

    #[test]
    fn test_serde_roundtrip() {
        let wallet = dummy_wallet();
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        let deserialized: EncryptedWallet = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "test-id");
        assert_eq!(deserialized.name, "test-wallet");
        assert_eq!(deserialized.lws_version, 1);
    }

    #[test]
    fn test_key_type_serde() {
        let json = serde_json::to_string(&KeyType::Mnemonic).unwrap();
        assert_eq!(json, "\"mnemonic\"");
        let json = serde_json::to_string(&KeyType::PrivateKey).unwrap();
        assert_eq!(json, "\"private_key\"");
    }

    #[test]
    fn test_matches_spec_format() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        for key in ["lws_version", "id", "name", "created_at", "chain_type", "accounts", "crypto", "key_type"] {
            assert!(json.get(key).is_some(), "missing key: {key}");
        }
    }

    #[test]
    fn test_metadata_omitted_when_null() {
        let wallet = dummy_wallet();
        let json = serde_json::to_value(&wallet).unwrap();
        assert!(json.get("metadata").is_none());
    }
}
