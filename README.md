# OWS — Open Wallet Standard.

Secure signing and wallet management for every chain. One vault, one interface — keys never leave your machine.

[![CI](https://github.com/open-wallet-standard/core/actions/workflows/ci.yml/badge.svg)](https://github.com/open-wallet-standard/core/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@open-wallet-standard/core)](https://www.npmjs.com/package/@open-wallet-standard/core)
[![PyPI](https://img.shields.io/pypi/v/open-wallet-standard)](https://pypi.org/project/open-wallet-standard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Why OWS

- **Zero key exposure.** Private keys are encrypted at rest, decrypted only after policy checks pass, then immediately wiped from memory. Agents authenticate with scoped API tokens and never see raw key material.
- **Every chain, one interface.** EVM, Solana, Sui, Bitcoin, Cosmos, Tron, TON — all first-class. CAIP-2/CAIP-10 addressing abstracts away chain-specific details.
- **Policy before signing.** A pre-signing policy engine gates agent (API key) operations — chain allowlists, expiry, and optional custom executables — before any key is touched.
- **Built for agents.** MCP server, native SDK, and CLI. A wallet created by one tool works in every other.

## Install

```bash
# Everything (CLI + Node + Python bindings)
curl -fsSL https://openwallet.sh/install.sh | bash
```

Or install only what you need:

```bash
npm install @open-wallet-standard/core    # Node.js SDK
npm install -g @open-wallet-standard/core # Node.js SDK + CLI (provides `ows` command)
pip install open-wallet-standard           # Python
cd ows && cargo build --workspace --release # From source
```

The language bindings are **fully self-contained** — they embed the Rust core via native FFI. Installing globally with `-g` also provides the `ows` CLI.

## Quick Start

```bash
# Create a wallet (derives addresses for all supported chains)
ows wallet create --name "agent-treasury"

# Sign a message
ows sign message --wallet agent-treasury --chain evm --message "hello"

# Sign a transaction
ows sign tx --wallet agent-treasury --chain evm --tx-hex "deadbeef..."
```

```javascript
import { createWallet, signMessage } from "@open-wallet-standard/core";

const wallet = createWallet("agent-treasury");
// => accounts for EVM, Solana, Sui, BTC, Cosmos, Tron, TON

const sig = signMessage("agent-treasury", "evm", "hello");
console.log(sig.signature);
```

```python
from open_wallet_standard import create_wallet, sign_message

wallet = create_wallet("agent-treasury")
# => accounts for EVM, Solana, Sui, BTC, Cosmos, Tron, TON

sig = sign_message("agent-treasury", "evm", "hello")
print(sig["signature"])
```

## Architecture

```
Agent / CLI / App
       │
       │  OWS Interface (MCP / SDK / CLI)
       ▼
┌─────────────────────┐
│    Access Layer      │     1. Agent calls ows.sign()
│  ┌────────────────┐  │     2. Policy engine evaluates
│  │ Policy Engine   │  │     3. Enclave decrypts key
│  │ (pre-signing)   │  │     4. Transaction signed
│  └───────┬────────┘  │     5. Key wiped from memory
│  ┌───────▼────────┐  │     6. Signature returned
│  │ Signing Enclave │  │
│  │ (isolated proc) │  │     The agent NEVER sees
│  └───────┬────────┘  │     the private key.
│  ┌───────▼────────┐  │
│  │  Wallet Vault   │  │
│  │ ~/.ows/wallets/ │  │
│  └────────────────┘  │
└─────────────────────┘
```

## Supported Chains

| Chain | Curve | Address Format | Derivation Path |
|-------|-------|----------------|-----------------|
| EVM (Ethereum, Polygon, etc.) | secp256k1 | EIP-55 checksummed | `m/44'/60'/0'/0/0` |
| Solana | Ed25519 | base58 | `m/44'/501'/0'/0'` |
| Bitcoin | secp256k1 | BIP-84 bech32 | `m/84'/0'/0'/0/0` |
| Cosmos | secp256k1 | bech32 | `m/44'/118'/0'/0/0` |
| Tron | secp256k1 | base58check | `m/44'/195'/0'/0/0` |
| TON | Ed25519 | raw/bounceable | `m/44'/607'/0'` |
| Sui | Ed25519 | 0x + BLAKE2b-256 hex | `m/44'/784'/0'/0'/0'` |

## CLI Reference

| Command | Description |
|---------|-------------|
| `ows wallet create` | Create a new wallet with addresses for all chains |
| `ows wallet list` | List all wallets in the vault |
| `ows wallet info` | Show vault path and supported chains |
| `ows sign message` | Sign a message with chain-specific formatting |
| `ows sign tx` | Sign a raw transaction |
| `ows pay request` | Make a paid request to an x402-enabled API endpoint |
| `ows pay discover` | Discover x402-enabled services |
| `ows fund deposit` | Create a MoonPay deposit to fund a wallet with USDC |
| `ows fund balance` | Check token balances for a wallet |
| `ows mnemonic generate` | Generate a BIP-39 mnemonic phrase |
| `ows mnemonic derive` | Derive an address from a mnemonic |
| `ows update` | Update ows and bindings |
| `ows uninstall` | Remove ows from the system |

## Specification

The full spec lives in [`docs/`](docs/) and at [openwallet.sh](https://openwallet.sh):

1. [Storage Format](docs/01-storage-format.md) — Vault layout, Keystore v3, filesystem permissions
2. [Signing Interface](docs/02-signing-interface.md) — sign, signAndSend, signMessage operations
3. [Policy Engine](docs/03-policy-engine.md) — Pre-signing transaction policies
4. [Agent Access Layer](docs/04-agent-access-layer.md) — MCP server, native language bindings
5. [Key Isolation](docs/05-key-isolation.md) — HD derivation paths and key separation
6. [Wallet Lifecycle](docs/06-wallet-lifecycle.md) — Creation, recovery, deletion
7. [Supported Chains](docs/07-supported-chains.md) — Chain families, CAIP identifiers, RPC endpoints

## License

MIT
