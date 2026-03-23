# 03 - Policy Engine

> How transaction policies are defined, evaluated, and enforced before any key material is touched.

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Two-tier access model (owner vs agent) | Done | Passphrase vs `ows_key_...` token (`ows-lib` key path) |
| API key CLI (`ows key create` / `list` / `revoke`) | Done | |
| API key file format + storage (`~/.ows/keys/`) | Done | Mnemonic re-encrypted under HKDF(token) |
| HKDF-SHA256 key derivation for API tokens | Done | |
| Policy file format + storage (`~/.ows/policies/`) | Done | |
| Declarative policy rules (`allowed_chains`, `expires_at`) | Done | |
| Custom executable policy protocol (stdin/stdout) | Done | 5s timeout + kill on timeout |
| PolicyContext / PolicyResult | Done | `ows-core/src/policy.rs` |
| Policy attachment to API keys | Done | |
| Default-deny on executable failures | Done | |
| AND semantics (all policies must allow) | Done | |
| `ows policy` CLI (`create`, `list`, `show`, `delete`) | Done | |
| `PolicyAction::warn` | Not started | JSON policies only support `deny` today |
| Rich audit entries (policy_id / API key on deny) | Partial | See `audit.jsonl` format in `docs/01-storage-format.md` |
| Spending state in `PolicyContext` | Partial | Fields exist; declarative daily caps were removed — use an `executable` for spend tracking |

**Implemented in** `ows-cli`, `ows-lib` (`policy_engine`, `policy_store`, `key_store`, `key_ops`). See [policy-engine-implementation.md](policy-engine-implementation.md) for design history. Some **spec** items (warn action, richer audit) are still open.

## Design Decision

**The credential determines the access tier.** The wallet owner authenticates with a passphrase and has full, unrestricted access — no policies are evaluated. Agents authenticate with API tokens (`ows_key_...`) whose attached policies are evaluated before any key material is touched. Policies are attached to API keys, not wallets. Only transactions that pass all of a key's policies are signed.

### Why Pre-Signing Policy Enforcement

We studied three enforcement models:

| Model | Where Enforced | Used By | Trade-offs |
|---|---|---|---|
| Application-layer | In the calling app | Most agent frameworks | Bypassable; the app can ignore its own rules |
| Smart contract | On-chain | Crossmint (ERC-4337), Lit Protocol | Strong but chain-specific; gas cost for policy checks |
| **Pre-signing gate** | In the wallet process | Privy, Turnkey | Universal across chains; not bypassable without vault access |

OWS uses pre-signing enforcement because:
1. It works identically for all chains (no smart contract deployment needed)
2. It prevents key material from being accessed for unauthorized transactions
3. It complements on-chain enforcement (use both for defense in depth)

## Access Model

```
sign_transaction(wallet, chain, tx, credential)
                                       │
                          ┌────────────┴────────────┐
                          │                          │
                     passphrase                 ows_key_...
                          │                          │
                     owner mode                 agent mode
                     no policy                  policies enforced
                     scrypt decrypt             HKDF decrypt
```

| Caller | Authentication | Policy Evaluation |
|---|---|---|
| **Owner** | Passphrase | **None.** Full access to all wallets. |
| **Agent** | `ows_key_...` token | **All policies attached to the API key** are evaluated. Every policy must allow (AND semantics). |

The credential itself determines the access tier. No bypass flags. The owner uses the passphrase; agents use tokens. Different agents get different tokens with different policies.

If the owner wants policy-constrained access for themselves, they create an API key and use the token instead of the passphrase.

## API Key Cryptography

### The problem

Agents need to sign autonomously — no human in the loop. The wallet's mnemonic is encrypted under the owner's passphrase. How does an agent decrypt it without the passphrase?

### Token-as-capability

When the owner creates an API key, OWS decrypts the wallet mnemonic using the owner's passphrase and **re-encrypts it under a key derived from the API token**. The encrypted copy is stored in the API key file. The agent presents the token with each signing request; the token serves as both authentication and decryption capability.

### Key derivation (HKDF-SHA256)

API tokens are 256-bit random values (`ows_key_<base62>`). Since they are already high-entropy, we use HKDF-SHA256 instead of scrypt:

```
token = ows_key_<random 256 bits, base62-encoded>
salt  = random 32 bytes (stored in CryptoEnvelope)
prk   = HKDF-Extract(salt, token)
key   = HKDF-Expand(prk, "ows-api-key-v1", 32)  →  AES-256-GCM key
```

Scrypt exists to make brute-force expensive for low-entropy passphrases. API tokens have 256 bits of entropy — brute force is already infeasible. HKDF derives the key in microseconds vs scrypt's ~500ms, eliminating latency in the agent signing path.

The `CryptoEnvelope` struct is reused with a new KDF identifier:

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

### Key creation flow

```bash
ows key create --name "claude-agent" --wallet agent-treasury --policy spending-limit
```

1. Owner enters wallet passphrase
2. OWS decrypts the wallet mnemonic using scrypt(passphrase)
3. Generates random token: `T = "ows_key_" + base62(random 256 bits)`
4. Generates random salt S
5. Derives key: `K = HKDF-SHA256(S, T, "ows-api-key-v1", 32)`
6. Encrypts mnemonic with K via AES-256-GCM
7. Stores key file with `token_hash: SHA256(T)`, policy IDs, and encrypted mnemonic copy
8. Displays T once — owner provisions it to the agent
9. Zeroizes mnemonic from memory

### Agent signing flow

```
Agent calls: sign_transaction(wallet, chain, tx, "ows_key_a1b2c3...")

1. Detect ows_key_ prefix → agent mode
2. SHA256(token) → look up API key file
3. Check expires_at (if set)
4. Verify wallet is in key's wallet_ids scope
5. Load policies from key's policy_ids
6. Build PolicyContext(tx, chain, wallet, spending state, key_id)
7. Evaluate all policies (AND semantics, short-circuit on first deny)
8. If denied → return POLICY_DENIED error (key material never touched)
9. HKDF-SHA256(salt, token) → AES key → decrypt mnemonic from key.wallet_secrets
10. HD-derive chain-specific key
11. Sign transaction
12. Zeroize mnemonic and derived key
13. Log to audit
14. Return signature
```

### Revocation

Delete the API key file. The encrypted mnemonic copy is gone. `SHA256(T)` matches nothing. The token is useless. The original wallet and other API keys are unaffected.

### Security properties

| Threat | Mitigation |
|---|---|
| Token stolen, no disk access | Useless — encrypted key file not accessible |
| Disk access, no token | Can't decrypt — HKDF + AES-256-GCM |
| Token + disk access | Can decrypt, but requires bypassing OWS process entirely |
| Owner passphrase changed | API keys unaffected (independently encrypted) |
| API key revoked | Encrypted copy deleted — token decrypts nothing |
| Multiple API keys | Independent encrypted copies; revoking one doesn't affect others |

## Declarative Policy Rules

These rule types are evaluated in-process (microseconds, no subprocess). Per-transaction value caps, recipient allowlists, and cumulative daily spend are **not** implemented as declarative rules; use an **`executable`** policy (see below) if you need that level of control.

### `allowed_chains`

Restricts which CAIP-2 chain IDs can be signed for.

```json
{ "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] }
```

### `expires_at`

Time-bound access (compares `PolicyContext.timestamp` to this ISO-8601 string).

```json
{ "type": "expires_at", "timestamp": "2026-04-01T00:00:00Z" }
```

## Custom Executable Policies

For anything declarative rules can't express — on-chain simulation, external API calls, complex business logic. Custom executables are the escape hatch.

### Protocol

```
echo '<PolicyContext JSON>' | /path/to/policy-executable
```

- The executable receives the full `PolicyContext` as a single JSON object on stdin
- The executable MUST write a single `PolicyResult` JSON object to stdout
- A non-zero exit code is treated as a denial
- Stderr is captured and logged to the audit log but does not affect the verdict

### Evaluation order within a policy

A policy can have both `rules` (declarative) and `executable` (custom). When both are present:

1. Declarative rules evaluate first (in-process, fast)
2. If declarative rules deny → skip executable (no subprocess spawned)
3. If declarative rules allow → spawn executable for final verdict
4. Both must allow

Declarative rules act as a fast pre-filter. The executable only runs for requests that pass basic checks.

## Policy File Format

Policies are JSON files stored in `~/.ows/policies/`:

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

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Unique policy identifier |
| `name` | string | yes | Human-readable policy name |
| `version` | integer | yes | Policy schema version (currently `1`) |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `rules` | array | no | Declarative rules (see above). Evaluated in-process. |
| `executable` | string | no | Absolute path to a custom policy executable |
| `config` | object | no | Static configuration passed to the executable via `PolicyContext.policy_config` |
| `action` | string | yes | `"deny"` or `"warn"` — what happens when the policy returns `allow: false` |

A policy MUST have at least one of `rules` or `executable`. If `executable` is set, it MUST be a file with execute permission. Implementations MUST verify the executable exists and is executable at policy creation time.

## PolicyContext

The JSON object available to both declarative evaluation and custom executables:

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
    "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "name": "agent-treasury",
    "accounts": [
      {
        "account_id": "eip155:8453:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
        "address": "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
        "chain_id": "eip155:8453"
      }
    ]
  },
  "timestamp": "2026-03-22T10:35:22Z",
  "key_id": "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "key_name": "claude-agent",
  "spending": {
    "daily_total_wei": "50000000000000000",
    "daily_remaining_wei": "950000000000000000"
  },
  "policy_config": {}
}
```

| Field | Type | Always Present | Description |
|---|---|---|---|
| `operation` | string | yes | `"sign_transaction"`, `"sign_message"`, or `"sign_typed_data"` |
| `transaction` | object | yes | Chain-specific transaction fields. EVM includes parsed `to`, `value`, `data`. All chains include `raw_hex`. |
| `chain_id` | string | yes | CAIP-2 chain identifier |
| `wallet` | object | yes | Wallet descriptor (id, name, accounts — never key material) |
| `timestamp` | string | yes | ISO 8601 timestamp of the signing request |
| `key_id` | string | yes | The ID of the API key making this request |
| `key_name` | string | yes | Human-readable name of the API key |
| `spending` | object | yes | Current spending state (daily total and remaining budget) |
| `policy_config` | object | yes | Static `config` from the policy file (empty object if not set) |

The `wallet` field never contains private keys, mnemonics, or encryption parameters.

The `spending` field is populated by the policy engine from its state store. Custom executables can use it without managing their own state.

## PolicyResult

```json
{ "allow": true }
```

```json
{ "allow": false, "reason": "Daily spending limit exceeded: 0.95 / 1.0 ETH" }
```

| Field | Type | Required | Description |
|---|---|---|---|
| `allow` | boolean | yes | `true` to permit the transaction, `false` to deny |
| `reason` | string | no | Human-readable explanation (logged to audit log; returned in error on denial) |

## Timeout and Failure Semantics

For custom executable policies only (declarative rules cannot fail in these ways):

| Scenario | Behavior |
|---|---|
| Executable exits with code 0, valid JSON on stdout | Use the `PolicyResult` as the verdict |
| Executable exits with non-zero code | **Deny.** Treat as `{ "allow": false }`. Stderr is logged. |
| Executable does not produce valid JSON on stdout | **Deny.** Log a parse error to the audit log. |
| Executable does not exit within 5 seconds | **Deny.** Kill the process. Log a timeout to the audit log. |
| Executable not found or not executable | **Deny.** Log an error. This is checked at policy creation time to fail early. |
| Unknown declarative rule type | **Deny.** Fail closed on unrecognized rules. |

The default-deny stance ensures that policy failures are never silently bypassed.

## Policy Actions

| Action | Behavior |
|---|---|
| `deny` | Block the transaction and return a `POLICY_DENIED` error |
| `warn` | Log a warning to the audit log but allow the transaction to proceed |

## Policy Attachment

Policies are attached to API keys, not wallets. When an API key is created, it is scoped to specific wallets and policies:

```bash
# Create a policy
ows policy create --file base-agent-limits.json

# Create an API key with wallet scope and policy attachment
ows key create --name "claude-agent" --wallet agent-treasury --policy base-agent-limits
# => ows_key_a1b2c3d4e5f6...  (shown once, store securely)
```

An API key can have multiple policies attached. All attached policies are evaluated — every policy must allow the transaction for it to proceed (AND semantics). Evaluation short-circuits on the first denial. All denials are logged to the audit log.

## Example: Custom Simulation Policy

```python
#!/usr/bin/env python3
"""Simulate transaction via eth_call before allowing."""
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

The corresponding policy file:

```json
{
  "id": "simulate-tx",
  "name": "EVM Transaction Simulation",
  "version": 1,
  "created_at": "2026-03-22T10:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453"] }
  ],
  "executable": "/home/user/.ows/plugins/policies/simulate.py",
  "action": "deny"
}
```

This policy uses declarative rules as a pre-filter (only Base) and the executable for simulation. If the chain check fails, the subprocess is never spawned.

## References

- [Privy Policy Engine](https://privy.io/blog/turning-wallets-programmable-with-privy-policy-engine)
- [Crossmint Onchain Policy Enforcement](https://blog.crossmint.com/ai-agent-wallet-architecture/)
- [ERC-4337 Session Keys](https://eips.ethereum.org/EIPS/eip-4337)
- [Lit Protocol / Vincent Policy Framework](https://spark.litprotocol.com/meet-vincent-an-agent-wallet-and-app-store-framework-for-user-owned-automation/)
- [Turnkey Granular Policies](https://docs.turnkey.com)
- [Coinbase Agentic Wallet Guardrails](https://www.coinbase.com/developer-platform/discover/launches/agentic-wallets)
