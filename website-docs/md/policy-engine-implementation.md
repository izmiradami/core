# Policy Engine & API Keys — Implementation Guide

> Design document for implementing OWS policy enforcement and API key-based agent access.
> Supersedes `03-policy-engine.md` and parts of `05-key-isolation.md`.

## Table of Contents

1. [Context](#context)
2. [Core Design](#core-design)
3. [How It Works](#how-it-works)
4. [Cryptographic Design](#cryptographic-design)
5. [Policy Evaluation](#policy-evaluation)
6. [Declarative Rules](#declarative-rules)
7. [Custom Executable Policies](#custom-executable-policies)
8. [Spending State](#spending-state)
9. [Storage Formats](#storage-formats)
10. [Signing Flow](#signing-flow)
11. [CLI Commands](#cli-commands)
12. [Bindings](#bindings)
13. [Audit Logging](#audit-logging)
14. [Bug Fixes Required](#bug-fixes-required)
15. [PR Plan](#pr-plan)
16. [Open Questions](#open-questions)

---

## Context

OWS has wallet creation, encryption, signing, and broadcasting across 9 chains — but zero access control. Any process with the wallet name and passphrase can sign anything. For AI agents, this is the primary risk: prompt injection, misconfiguration, or runaway behavior can drain a wallet.

The original spec (`03-policy-engine.md`) designed policy enforcement around executable programs piped JSON over stdin/stdout, attached to API keys. Two problems:

1. **Only executable policies** — operationally heavy for "limit spending to 1 ETH/day on Base."
2. **The signing enclave is specced as a prerequisite** — a daemon or subprocess model that isn't viable (daemon crash = agents can't sign; subprocess adds complexity for limited gain against the primary threat model).

This document describes what we're actually building.

---

## Core Design

**The credential determines the access tier.** No flags, no bypass modes — just two kinds of credentials:

```
sign_transaction(wallet, chain, tx, credential)
                                       │
                          ┌────────────┴────────────┐
                          │                          │
                     passphrase                 ows_key_abc...
                          │                          │
                     owner mode                 agent mode
                     no policy                  policies enforced
                     scrypt decrypt             HKDF decrypt
```

- **Owner** provides the wallet passphrase. Full access. No policy evaluation. This is the existing behavior.
- **Agent** provides an API token (`ows_key_...`). Policies attached to that token are evaluated before any key material is touched. Non-bypassable.

Different agents get different tokens with different policies. The identity is the credential.

### Departures from the original spec

**1. No wallet-level policies.** Policies attach to API keys only. A wallet with no API keys behaves exactly as it does today — passphrase in, signature out. Policy enforcement only exists in the agent path.

**Why:** Wallet-level policies with a shared passphrase have no real security boundary. Every caller authenticates with the same credential, so there's no way to distinguish agents from owners, and no way to give different agents different permissions. The API key IS the identity boundary.

**2. Declarative rules are first-class.** The original spec treats all policies as executables. We add built-in rule types (`allowed_chains`, `expires_at`) evaluated in-process. Per-tx value caps, recipient allowlists, and cumulative spend are not declarative — use a custom **`executable`** policy if you need those. Custom executables remain as an escape hatch.

**Why:** The 90% case shouldn't require writing a shell script.

**3. The enclave is an optional future add-on.** Policy enforcement happens in-process, trusted by the code path. The per-request subprocess enclave from `05-key-isolation.md` can be layered on later for key exfiltration prevention — it uses the same Approach B crypto, just in a child process. Not a prerequisite.

**Why:** The enclave adds defense against a compromised agent binary reading keys from shared memory. The primary threats (prompt injection, runaway agents, misconfigured agents) are handled by code-path enforcement.

**4. HKDF instead of scrypt for API tokens.** Tokens are 256-bit random — scrypt's brute-force resistance is unnecessary. HKDF is instant.

---

## How It Works

### Owner creates an API key

```bash
ows key create --name "claude-agent" \
  --wallet agent-treasury \
  --policy spending-limit \
  --policy base-only
```

1. Owner enters wallet passphrase
2. OWS decrypts the wallet mnemonic
3. Generates a random token `ows_key_<base62>`
4. Re-encrypts the mnemonic under HKDF(token)
5. Stores key file with token hash, policy IDs, and encrypted mnemonic copy
6. Displays token once — owner provisions it to the agent

### Agent signs a transaction

```typescript
import { signTransaction } from "@open-wallet-standard/core";

const result = signTransaction(
  "agent-treasury", "base", "0x02f8...", "ows_key_a1b2c3d4..."
);
```

1. OWS detects `ows_key_` prefix → agent mode
2. SHA256(token) → looks up key file
3. Verifies wallet is in scope, checks expiry
4. Loads policies attached to this key
5. Evaluates all policies against the transaction
6. If denied → returns `PolicyDenied` error (key material never touched)
7. If allowed → HKDF(token) → decrypts mnemonic → signs → wipes → returns signature

### Owner signs (unchanged)

```bash
ows sign tx --wallet agent-treasury --chain base --tx 0x02f8...
```

Passphrase authentication. No policy evaluation. Existing behavior preserved exactly.

### Revoking access

```bash
ows key revoke --id 7a2f1b3c --confirm
```

Deletes the key file. The encrypted mnemonic copy is gone. The token becomes useless. Other API keys and the owner's passphrase are unaffected.

---

## Cryptographic Design

### The problem

Agents need to sign autonomously — no human in the loop. The mnemonic is encrypted under the owner's passphrase. How does an agent decrypt it?

### Token-as-capability (Approach B)

When the owner creates an API key, OWS re-encrypts the mnemonic under a key derived from the API token. The token is both the authentication credential and the decryption capability.

### Key derivation

```
token = ows_key_<random 256 bits, base62-encoded>
salt  = random 32 bytes
prk   = HKDF-Extract(salt, token)
key   = HKDF-Expand(prk, "ows-api-key-v1", 32)  →  AES-256-GCM key
```

Reuses the existing `CryptoEnvelope` struct with a new KDF identifier:

```json
{
  "cipher": "aes-256-gcm",
  "cipherparams": { "iv": "..." },
  "ciphertext": "...",
  "auth_tag": "...",
  "kdf": "hkdf-sha256",
  "kdfparams": { "dklen": 32, "salt": "...", "info": "ows-api-key-v1" }
}
```

### Why HKDF instead of scrypt

Scrypt makes brute-force expensive for low-entropy passphrases. API tokens have 256 bits of entropy — brute force is infeasible regardless of KDF speed. HKDF derives the key in microseconds vs scrypt's 500ms-1s.

### Security properties

| Threat | Mitigation |
|---|---|
| Token stolen, no disk access | Useless — encrypted key file not accessible |
| Disk access, no token | Can't decrypt — HKDF + AES-256-GCM |
| Token + disk access | Can decrypt, but requires bypassing OWS entirely |
| Owner passphrase changed | API keys unaffected (independently encrypted) |
| API key revoked | Encrypted copy deleted — token decrypts nothing |
| Multiple API keys | Independent encrypted copies; revoking one doesn't affect others |

---

## Policy Evaluation

### Flow

```
1. Detect credential type (passphrase vs ows_key_ token)
2. If passphrase → skip policy, decrypt with scrypt, sign (owner mode)
3. If token:
   a. SHA256(token) → look up key file
   b. Check expires_at
   c. Check wallet is in key's wallet_ids
   d. Load policies from key's policy_ids
   e. For each policy:
      - Evaluate declarative rules (in-process, fast)
      - If rules pass and executable is set, run executable (subprocess)
      - If policy has both, both must pass
   f. AND semantics — all policies must allow, short-circuit on first deny
   g. deny action → block request. warn action → log, allow.
4. If denied → return PolicyDenied error (never decrypt)
5. If allowed → HKDF decrypt → sign → record spend → audit log
```

### PolicyContext

JSON object available to both declarative evaluation and custom executables:

```json
{
  "operation": "sign_transaction",
  "transaction": {
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C",
    "value": "100000000000000000",
    "data": "0x",
    "raw_hex": "02f8..."
  },
  "chain_id": "eip155:8453",
  "wallet": {
    "id": "3198bc9c-...",
    "name": "agent-treasury",
    "accounts": [
      {
        "account_id": "eip155:8453:0xab16a96D...",
        "address": "0xab16a96D...",
        "chain_id": "eip155:8453"
      }
    ]
  },
  "timestamp": "2026-03-22T10:35:22Z",
  "key_id": "7a2f1b3c-...",
  "key_name": "claude-agent",
  "spending": {
    "daily_total_wei": "50000000000000000",
    "daily_remaining_wei": "950000000000000000"
  },
  "policy_config": {}
}
```

- `transaction` is chain-specific. EVM gets parsed `to`, `value`, `data`. Other chains get `raw_hex` only.
- `spending` is populated from state store. Custom executables can use it without managing state.
- `policy_config` contains the static `config` object from the policy file.

### PolicyResult

```json
{ "allow": true }
```

```json
{ "allow": false, "reason": "Daily spending limit exceeded: 0.95 / 1.0 ETH" }
```

---

## Declarative Rules

Two built-in rule types, evaluated in-process (microseconds). Value limits, recipient allowlists, and cumulative spend are not declarative — use **`executable`** policies for those.

### `allowed_chains`

```json
{ "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] }
```

Denies if `chain_id` is not in the list.

### `expires_at`

```json
{ "type": "expires_at", "timestamp": "2026-04-01T00:00:00Z" }
```

Denies if current time is past the timestamp.

---

## Custom Executable Policies

For anything declarative rules can't express.

```bash
echo '<PolicyContext JSON>' | /path/to/policy-executable
```

- Receives PolicyContext on stdin, writes PolicyResult to stdout
- Non-zero exit → deny
- Invalid JSON on stdout → deny
- No exit within 5 seconds → kill + deny
- Stderr captured and logged

If a policy has both `rules` and `executable`, declarative rules evaluate first as a fast pre-filter. The executable only runs if rules pass.

### Example: transaction simulation

```python
#!/usr/bin/env python3
import json, sys, urllib.request

ctx = json.load(sys.stdin)
tx = ctx["transaction"]
rpc = {"eip155:8453": "https://mainnet.base.org"}.get(ctx["chain_id"])
if not rpc:
    json.dump({"allow": False, "reason": f"No RPC for {ctx['chain_id']}"}, sys.stdout)
    sys.exit(0)

payload = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "eth_call",
    "params": [{"to": tx["to"], "value": hex(int(tx["value"])), "data": tx["data"]}, "latest"]
}).encode()
try:
    resp = json.load(urllib.request.urlopen(
        urllib.request.Request(rpc, data=payload, headers={"Content-Type": "application/json"}), timeout=4))
    if "error" in resp:
        json.dump({"allow": False, "reason": f"Reverted: {resp['error']['message']}"}, sys.stdout)
    else:
        json.dump({"allow": True}, sys.stdout)
except Exception as e:
    json.dump({"allow": False, "reason": str(e)}, sys.stdout)
```

---

## Storage Formats

### Policy file (`~/.ows/policies/<id>.json`)

```json
{
  "id": "base-agent-limits",
  "name": "Base Agent Safety Limits",
  "version": 1,
  "created_at": "2026-03-22T10:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] },
    { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
  ],
  "executable": null,
  "config": null,
  "action": "deny"
}
```

Permissions: `755` (policies are not secret).

### API key file (`~/.ows/keys/<id>.json`)

```json
{
  "id": "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "name": "claude-agent",
  "token_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
  "created_at": "2026-03-22T10:30:00Z",
  "wallet_ids": ["3198bc9c-6672-5ab3-d995-4942343ae5b6"],
  "policy_ids": ["base-agent-limits"],
  "expires_at": null,
  "wallet_secrets": {
    "3198bc9c-...": {
      "cipher": "aes-256-gcm",
      "cipherparams": { "iv": "..." },
      "ciphertext": "...",
      "auth_tag": "...",
      "kdf": "hkdf-sha256",
      "kdfparams": { "dklen": 32, "salt": "...", "info": "ows-api-key-v1" }
    }
  }
}
```

Permissions: `700` (directory), `600` (files).

### No wallet file changes

Wallets don't gain a `policy_ids` field. Policies attach to API keys only.

---

## Signing Flow

### Current flow

```
sign_transaction(wallet, chain, tx, passphrase, ...)
  → load wallet
  → scrypt(passphrase) → decrypt mnemonic
  → HD derive → sign → return
```

### New flow

The credential parameter determines the path:

```
sign_transaction(wallet, chain, tx, credential, ...)
  → if credential starts with "ows_key_":
      │  agent mode
      │  SHA256(credential) → look up key file
      │  check expires_at, check wallet in scope
      │  load key.policy_ids → load policy files
      │  build PolicyContext(tx, chain, wallet, spending state)
      │  evaluate_policies() → if denied: return error
      │  HKDF(credential) → decrypt mnemonic from key.wallet_secrets
      │  HD derive → sign → record spend → audit → return
      │
  → else:
      │  owner mode (existing behavior, unchanged)
      │  scrypt(credential) → decrypt mnemonic from wallet file
      │  HD derive → sign → return
```

### Implementation: single credential parameter

Today the bindings expose `passphrase` as an optional string parameter. The change is minimal — accept either a passphrase or an API token in the same parameter, branch on the `ows_key_` prefix:

```rust
// ows-lib/src/ops.rs
pub fn sign_transaction(
    wallet: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,       // passphrase OR ows_key_... token
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, OwsLibError> {
    if credential.starts_with("ows_key_") {
        sign_with_api_key(credential, wallet, chain, tx_hex, index, vault_path)
    } else {
        sign_with_passphrase(wallet, chain, tx_hex, credential, index, vault_path)
    }
}
```

The `sign_with_passphrase` path is the existing code, extracted. The `sign_with_api_key` path is new. No new function signatures needed in the bindings — the existing `passphrase` parameter just accepts tokens too.

### Unifying CLI and library paths

The CLI's `resolve_signing_key()` in `commands/mod.rs` duplicates `decrypt_signing_key()` from ows-lib. This must be unified into a single code path through ows-lib so the token detection and policy enforcement exist in one place.

---

## Module Boundaries

The new code is organized into self-contained modules that don't modify existing logic. The only integration point is the credential branch in the signing path.

### Crate-level layout

```
ows-core/src/
  policy.rs          NEW — Policy, PolicyRule, PolicyAction, PolicyContext, PolicyResult types
  api_key.rs         NEW — ApiKeyFile type
  error.rs           MODIFIED — add PolicyDenied, ApiKeyNotFound, ApiKeyExpired variants
  lib.rs             MODIFIED — add pub mod policy, pub mod api_key, re-exports

ows-signer/src/
  crypto.rs          MODIFIED — add encrypt_with_hkdf(), decrypt_with_hkdf(), dispatch on kdf field in decrypt()
  lib.rs             MODIFIED — re-export new functions

ows-lib/src/
  policy_store.rs    NEW — CRUD for ~/.ows/policies/
  policy_engine.rs   NEW — evaluate_policies(), declarative rule evaluation, executable subprocess
  key_store.rs       NEW — CRUD for ~/.ows/keys/, token generation, SHA-256 hashing
  key_ops.rs         NEW — create_api_key(), sign_with_api_key()
  ops.rs             MODIFIED — credential branch (ows_key_ prefix check) at top of signing functions
  lib.rs             MODIFIED — add pub mod declarations and re-exports

ows-cli/src/
  commands/policy.rs NEW — ows policy create/list/show/delete
  commands/key.rs    NEW — ows key create/list/revoke
  main.rs            MODIFIED — add Policy and Key subcommands
  audit.rs           MODIFIED — add policy_id, api_key_id fields to AuditEntry
```

### Separation principle

All new logic lives in new files. Existing files get minimal, surgical changes:

**`ows-core/error.rs`** — three new enum variants appended. No existing variants change.

**`ows-signer/crypto.rs`** — two new public functions added. The existing `decrypt()` gains a match on the `kdf` field to dispatch to HKDF when it sees `"hkdf-sha256"`. The existing scrypt path is untouched. If the `kdf` field is `"scrypt"` (all existing wallet files), the code path is identical to today.

**`ows-lib/ops.rs`** — this is the critical integration point. The change is a branch at the top of each signing function:

```rust
pub fn sign_transaction(wallet, chain, tx_hex, credential, ...) {
    if credential.starts_with("ows_key_") {
        // NEW path — entirely in key_ops.rs
        return key_ops::sign_with_api_key(credential, wallet, chain, tx_hex, ...);
    }
    // EXISTING path — untouched code below this point
    let wallet = vault::load_wallet_by_name_or_id(wallet, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    // ... existing scrypt decrypt → HD derive → sign
}
```

The existing passphrase path is never entered when a token is provided. The new token path is entirely contained in `key_ops.rs`, which calls into `key_store.rs` (lookup), `policy_engine.rs` (evaluation), and `crypto::decrypt_with_hkdf` (decryption). None of these touch the existing wallet/vault/signing code.

**`ows-cli/main.rs`** — two new subcommand variants (`Policy`, `Key`) added to the `Commands` enum. Existing command dispatch is unchanged.

**`ows-cli/audit.rs`** — two optional fields added to `AuditEntry` (`policy_id`, `api_key_id`), both `#[serde(skip_serializing_if = "Option::is_none")]`. Existing audit entries serialize identically.

### What does NOT change

- `ows-signer/src/chains/*.rs` — no chain signer changes
- `ows-signer/src/hd.rs` — no HD derivation changes
- `ows-signer/src/zeroizing.rs` — no SecretBytes changes
- `ows-signer/src/process_hardening.rs` — no signal/mlock changes
- `ows-signer/src/key_cache.rs` — no cache changes
- `ows-lib/src/vault.rs` — no wallet storage changes
- `ows-lib/src/migrate.rs` — no migration changes
- `ows-core/src/wallet_file.rs` — no wallet file format changes
- `ows-core/src/chain.rs` — no chain registry changes
- `ows-core/src/config.rs` — no config changes
- `bindings/node/src/lib.rs` — signing functions unchanged (new management functions added, existing ones untouched)
- `bindings/python/src/lib.rs` — same

### Dependency flow between new modules

```
key_ops.rs
  ├── key_store.rs       (token lookup, key file I/O)
  ├── policy_engine.rs   (evaluate policies)
  │     └── policy_store.rs   (load policy files)
  └── crypto.rs          (decrypt_with_hkdf — existing module, new function)
```

Each new module has a narrow interface:

- **`policy_store`**: `save_policy()`, `load_policy()`, `list_policies()`, `delete_policy()`
- **`policy_engine`**: `evaluate_policies(policies, context) → PolicyResult`
- **`key_store`**: `generate_token()`, `hash_token()`, `save_api_key()`, `load_api_key_by_token_hash()`, `list_api_keys()`, `delete_api_key()`
- **`key_ops`**: `create_api_key()`, `sign_with_api_key()`

No module reaches into another's internals. Testing each module in isolation is straightforward — mock the filesystem for store modules, pass constructed PolicyContext to the engine, etc.

---

## CLI Commands

### Policy management

```bash
ows policy create --file <path>           # register a policy
ows policy list                            # list all policies
ows policy show --id <id>                  # show policy details
ows policy delete --id <id> --confirm      # delete a policy
```

### Key management

```bash
ows key create --name "claude-agent" \
  --wallet agent-treasury \
  --policy spending-limit \
  --policy base-only
# Prompts for wallet passphrase
# Outputs: ows_key_a1b2c3d4... (shown once)

ows key list                               # list keys (no tokens shown)
ows key revoke --id <id> --confirm         # delete key file
```

### Signing (unchanged surface, new behavior)

```bash
# Owner (existing)
ows sign tx --wallet treasury --chain base --tx 0x...

# Agent (pass token via env)
OWS_PASSPHRASE=ows_key_abc... ows sign tx --wallet treasury --chain base --tx 0x...
```

The CLI's existing passphrase input path (env var, stdin, prompt) works for tokens too — no new flags needed.

---

## Bindings

### No new function signatures needed for signing

The existing functions accept the token in the passphrase parameter:

```typescript
// Node.js — existing API, works with tokens
signTransaction("treasury", "base", "0x...", "ows_key_abc...");
signMessage("treasury", "base", "hello", "ows_key_abc...");
signAndSend("treasury", "base", "0x...", "ows_key_abc...");
```

### New management functions

```typescript
// Policy management
createPolicy(jsonStr: string, vaultPath?: string): PolicyInfo
listPolicies(vaultPath?: string): PolicyInfo[]
deletePolicy(id: string, vaultPath?: string): void

// Key management
createApiKey(name: string, wallet: string, passphrase: string,
             policies: string[], vaultPath?: string): { id: string, token: string }
listApiKeys(vaultPath?: string): ApiKeyInfo[]
revokeApiKey(id: string, vaultPath?: string): void
```

Python bindings mirror the same functions.

---

## Audit Logging

Extend `AuditEntry` with policy fields:

```json
{
  "timestamp": "2026-03-22T10:35:22Z",
  "wallet_id": "3198bc9c-...",
  "operation": "policy_denied",
  "chain_id": "eip155:8453",
  "details": "Daily spending limit exceeded: 0.95 / 1.0 ETH",
  "api_key_id": "7a2f1b3c-...",
  "policy_id": "spending-limit"
}
```

Operations: `policy_evaluated`, `policy_denied`, `policy_timeout`.

---

## Bug Fixes Required

From `bugs/aggregated-bugs.md` — these are on the critical path:

| Bug | Tier | Why It Matters | Fix |
|---|---|---|---|
| **#3 Wallet ID path traversal** | 0 | Key files in `~/.ows/keys/` reachable via crafted wallet IDs | Sanitize IDs in vault.rs |
| **#27 Passphrase read errors swallowed** | 1 | Silent empty passphrase could cause unexpected signing behavior | Return error on read failure |
| **#2 Vault path falls back to `/tmp`** | 1 | Key files and spending state in world-readable `/tmp` | Refuse to operate when HOME unset |
| **#6 Permissions only warned** | 1 | Can't trust that `~/.ows/keys/` is actually 700 | Enforce on `wallets/` and `keys/` |
| **#9 Malformed envelope handling** | 1 | HKDF envelopes need same validation as scrypt | Validate all fields before crypto ops |
| **#26 Audit log silent failure** | 2 | Policy denials invisible if audit can't write | Warn to stderr on write failure |

### Characterization tests (also PR 0)

Before refactoring the signing paths in PR 1, add tests that lock down the current behavior as a regression safety net. These run against the existing code — they should all pass before any changes land.

**ows-lib (ops.rs) — end-to-end signing flow:**
- Create wallet with passphrase → `sign_transaction` → verify valid signature
- Create wallet with empty passphrase → `sign_transaction("")` → verify valid signature
- `sign_transaction` with wrong passphrase → verify `CryptoError` / `InvalidPassphrase`
- `sign_transaction` with nonexistent wallet → verify `WalletNotFound`
- `sign_message` round-trip for each chain family (EVM, Solana, Bitcoin, Cosmos, Tron, TON, Sui)
- `sign_and_send` with invalid RPC → verify `BroadcastFailed` (not a panic)
- `sign_typed_data` for EVM → verify valid signature

**ows-lib (ops.rs) — wallet lifecycle through signing:**
- Create wallet → sign → rename wallet → sign with new name → verify both signatures valid
- Create wallet → sign → delete wallet → sign → verify `WalletNotFound`
- Import wallet from mnemonic → sign → export → reimport → sign → verify same signature (determinism)
- Import wallet from private key → sign → verify valid signature

**ows-signer (crypto.rs) — encryption round-trip:**
- `encrypt(plaintext, passphrase)` → `decrypt(envelope, passphrase)` → verify plaintext matches
- `decrypt` with wrong passphrase → verify error (not panic)
- `decrypt` with empty passphrase on empty-passphrase envelope → verify success
- `decrypt` with malformed envelope (bad IV length, bad salt, bad ciphertext, truncated auth_tag) → verify error for each
- `decrypt` with `dklen > 32` → verify error (not panic, regression for known bug)
- `decrypt` with `n` not a power of 2 → verify error

**ows-signer (HD derivation) — determinism:**
- Same mnemonic + same path + same chain → same key (multiple calls)
- Different index → different key
- Known test vector: "abandon" mnemonic → known EVM address

**ows-lib (vault.rs) — file handling:**
- Save wallet → load by name → verify fields match
- Save wallet → load by ID → verify fields match
- Save wallet with ID containing `../` → verify rejection (validates path traversal fix)
- List wallets returns newest first
- Duplicate wallet name → verify `WalletNameExists`

**ows-cli (audit.rs) — audit trail:**
- Create wallet → verify audit entry written
- Broadcast transaction → verify audit entry with tx_hash
- Audit write to read-only directory → verify operation still succeeds (or warns, depending on fix for #26)

These tests serve dual purpose: they catch regressions during the refactor PRs, and they document the current contract for the signing flow that the policy engine will be inserted into.

Fix these alongside characterization tests in **PR 0**.

### PR 1: Unify signing paths

Before PR 0, the codebase had two independent code paths that turned a credential into signing key material:

1. **CLI path** (`ows-cli/src/commands/mod.rs`): `resolve_signing_key()` → `resolve_wallet_secret()` → `extract_key_for_curve()` / `HdDeriver::derive_from_mnemonic_cached()`. Loaded the wallet, decrypted (trying empty passphrase first, prompting on failure), then derived the key. ~60 lines of code including the `WalletSecret` enum.

2. **Library path** (`ows-lib/src/ops.rs`): `decrypt_signing_key()` (private). Loaded the wallet, decrypted with a caller-provided passphrase, then derived the key. Used uncached HD derivation.

PR 8 (token-based signing) needs to insert credential detection and policy evaluation into the signing flow. That only works if there's a single code path to hook into.

**Changes:**

- **`ows-lib/src/ops.rs`**: `decrypt_signing_key()` made `pub`. Switched from `derive_from_mnemonic()` to `derive_from_mnemonic_cached()` so the library gets the same HD derivation caching the CLI already had.
- **`ows-cli/src/commands/mod.rs`**: Deleted `WalletSecret` enum, `resolve_wallet_secret()`, and `extract_key_for_curve()`. `resolve_signing_key()` is now a thin wrapper: tries `ows_lib::decrypt_signing_key(wallet, chain, "", index, None)`, and on `OwsLibError::Crypto` prompts the user and retries. Removed unused imports (`vault`, `KeyType`, `CryptoEnvelope`, `Zeroize`).
- **`ows-cli/src/vault.rs`**: Removed `load_wallet_by_name_or_id()` wrapper (only caller was the deleted `resolve_wallet_secret`).
- **CLI signing commands** (`sign_transaction.rs`, `sign_message.rs`, `send_transaction.rs`): Zero changes — they call `super::resolve_signing_key()` which has the same signature.

**Known tradeoffs:**

1. **HD key cache now active in the library API.** The library previously used uncached `derive_from_mnemonic()`; it now uses the cached variant (global cache, 5s TTL, 32 entries, zeroized on eviction). For CLI usage this is irrelevant (process exits immediately). For the library used in a long-running agent process, derived keys linger in memory up to 5 seconds. Acceptable because: (a) the agent path will go through policy enforcement (PR 8) which adds its own controls, (b) the cache zeroizes on eviction, and (c) a 5-second window is negligible compared to the mnemonic being in-memory for the process lifetime.

2. **Double wallet file read for passphrase-protected wallets.** The CLI tries empty passphrase via `decrypt_signing_key()` (loads wallet + scrypt), and on failure calls it again with the real passphrase (loads wallet again). One extra file read vs. the old code which loaded once. Negligible compared to scrypt cost (~500ms).

3. **Error type nesting changed.** A wrong-passphrase error now surfaces as `CliError::Lib(OwsLibError::Crypto(CryptoError))` instead of `CliError::Crypto(CryptoError)`. Same `Display` output; nothing pattern-matches on the variant.

---

## PR Plan

| PR | Title | What Changes | Depends On |
|---|---|---|---|
| ~~**0**~~ | ~~**Bug fixes + characterization tests**~~ | ~~Security fixes + characterization tests~~ | **Done** |
| ~~**1**~~ | ~~**Unify signing paths**~~ | ~~Export `decrypt_signing_key()` from ows-lib, delete CLI's duplicate, single code path~~ | **Done** |
| **2** | **Core types** | `Policy`, `PolicyRule`, `PolicyAction`, `PolicyContext`, `PolicyResult`, `ApiKeyFile` in ows-core. `PolicyDenied`/`ApiKeyNotFound` error variants. | — |
| **3** | **HKDF encryption** | Add `encrypt_with_hkdf`/`decrypt_with_hkdf` to ows-signer. `kdf: "hkdf-sha256"` in CryptoEnvelope. | 0 ✓ |
| **4** | **Policy storage** | `policy_store.rs` (CRUD for `~/.ows/policies/`) in ows-lib | 2 |
| **5** | **API key storage** | `key_store.rs` in ows-lib. Token generation, SHA-256 hashing, CRUD for `~/.ows/keys/`. | 2 |
| **6** | **Policy evaluation engine** | `policy_engine.rs` in ows-lib. Declarative rules + executable subprocess support. | 2, 4 |
| **7** | **API key creation** | `create_api_key()`: decrypt wallet → re-encrypt with HKDF(token) → store key file | 3, 5 |
| **8** | **Token-based signing** | Credential detection (`ows_key_` prefix), token lookup, policy eval, HKDF decrypt, sign. Hook into unified signing path. | 1 ✓, 6, 7 |
| **9** | **CLI commands** | `ows policy create/list/show/delete`, `ows key create/list/revoke` | 4, 8 |
| **10** | **Audit logging** | Extend AuditEntry, emit policy events | 8 |
| **11** | **Bindings** | `createPolicy`, `listPolicies`, `deletePolicy`, `createApiKey`, `listApiKeys`, `revokeApiKey` in Node.js and Python. Signing functions work automatically. | 8 |
| ~~**12**~~ | ~~**Spec updates**~~ | ~~Rewrite 03-policy-engine.md, update 05-key-isolation.md, 01-storage-format.md, 04-agent-access-layer.md~~ | **Done** |
| **13** | **Website sync** | Sync `website/docs/md/` with updated spec docs. Update `index.html` architecture copy and `terminal-demo.js` to replace enclave references with policy-gated signing model. | 12 ✓ |

### Dependency graph

```
PR 0 (bugs) ──► PR 1 (unify paths) ──────────────────────────┐
      │                                                        │
      ▼                                                        │
PR 3 (HKDF) ──────────────────────────┐                       │
                                       │                       │
PR 2 (types) ──┬── PR 4 (policy store) ── PR 6 (engine) ──┐  │
               │                                            │  │
               └── PR 5 (key store) ───┐                    │  │
                                       │                    │  │
                          PR 7 (key creation) ◄── PR 3      │  │
                                       │                    │  │
                                       PR 8 (signing) ◄────┘──┘
                                          │
                                   ┌──────┼──────┐
                                   │      │      │
                                PR 9   PR 10  PR 11
                                (CLI)  (audit) (bindings)
                                   │      │      │
                                   └──────┼──────┘
                                          │
                                       PR 12
                                       (spec)
```

### Parallelism

**What can actually run in parallel** (verified against file-level conflicts):

**Wave 1** (start immediately):
- **PR 0** and **PR 2** in parallel — PR 0 touches ows-lib/vault.rs, ows-signer/crypto.rs, ows-cli/commands/mod.rs, ows-cli/audit.rs. PR 2 touches only ows-core (new files + error.rs + lib.rs). Zero file overlap.
- **PR 3 cannot parallel with PR 0** — both modify `ows-signer/src/crypto.rs`. PR 0 adds envelope validation; PR 3 adds HKDF functions. PR 3 must follow PR 0.

**Wave 2** (after PR 0 and PR 2 merge):
- **PR 1** and **PR 3** in parallel — PR 1 touches ows-lib/ops.rs and ows-cli/commands/mod.rs. PR 3 touches ows-signer/crypto.rs and Cargo.toml. No overlap.
- **PR 4** and **PR 5** in parallel — PR 4 creates policy_store.rs. PR 5 creates key_store.rs. Both add module declarations to ows-lib/src/lib.rs (trivial merge). Different files otherwise.
- **PR 6** and **PR 7** can overlap — PR 6 creates policy_engine.rs (needs PR 4). PR 7 adds create_api_key logic (needs PR 3 + PR 5). Independent chains, different files.

**Wave 3** (after PR 8 — the convergence point):
- **PR 9, 10, 11** all in parallel — PR 9 adds commands/policy.rs + commands/key.rs + main.rs changes. PR 10 modifies audit.rs. PR 11 modifies bindings/node/src/lib.rs + bindings/python/src/lib.rs. Zero overlap.
- **PR 12** after PR 11.

### Two-person split

| Person A (policy path) | Person B (key path) |
|---|---|
| PR 2 (core types) | PR 0 (bug fixes + tests) |
| PR 4 (policy storage) | PR 3 (HKDF — after PR 0) |
| PR 6 (policy engine) | PR 1 (unify paths — after PR 0) |
| | PR 5 (key storage — after PR 2) |
| | PR 7 (key creation — after PR 3, 5) |
| **converge** → PR 8 (token-based signing) | |
| PR 9 (CLI) | PR 11 (bindings) |
| PR 10 (audit) | PR 12 (spec) |

---

## Open Questions

### 1. Transaction parsing depth

Start minimal: parse EVM `to` and `value` only. Other chains get `raw_hex` — custom executables handle parsing. Expand per-chain as demand arises.

### 2. Policy composition

AND semantics only. No OR groups. A single policy with custom executable logic can implement OR internally if needed.

### 3. Unknown rule types

Deny (fail closed). The `version` field enables future migration.

### 4. Multi-wallet API keys

Support in the storage format (`wallet_ids` is an array), but the CLI only allows `--wallet <single>` initially.

### 5. Non-EVM spending limits

Rename `max_wei` to `max_native_units`. The unit depends on the chain (wei, lamports, satoshis). The engine does decimal string comparison regardless.

### 6. EVM transaction value parsing

For the initial implementation, require callers to pass structured fields (to, value) alongside raw hex. This avoids building a full EVM tx decoder. The existing RLP module can be extended later.
