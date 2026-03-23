# 05 - Key Isolation

> How OWS reduces private-key exposure to agents, LLMs, logs, and local process risks.

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Core dump disabling (`PR_SET_DUMPABLE` / `PT_DENY_ATTACH`) | Done | `ows-signer/src/process_hardening.rs` |
| `RLIMIT_CORE` set to 0 | Done | `process_hardening.rs` |
| Memory locking (`mlock`) for key material | Done | `ows-signer/src/zeroizing.rs` |
| Zeroization on drop (`SecretBytes`) | Done | `zeroizing.rs` uses `zeroize` crate |
| Signal handlers (SIGTERM/SIGINT/SIGHUP cleanup) | Done | `process_hardening.rs` |
| Key cache with TTL + LRU eviction | Done | `ows-signer/src/key_cache.rs` (5s TTL, 32 entries) |
| Subprocess signing enclave (child process) | Future | Optional enhancement — not a prerequisite for policy enforcement |
| Unix domain socket / pipe IPC | Future | |
| Passphrase delivery: env var (`OWS_PASSPHRASE`) with immediate clear | Partial | CLI supports env + prompt; bindings take the credential as a parameter |

**Note:** The current implementation provides in-process hardening (mlock, zeroize, anti-debug) but does NOT implement the subprocess isolation model described below. Keys are decrypted within the calling process's address space. Policy enforcement (see [03-policy-engine.md](03-policy-engine.md)) is handled by the code path, not by process isolation.

The subprocess enclave is an **optional future enhancement** for key exfiltration prevention. It is not required for policy enforcement, API key support, or any other currently planned feature. See [Current Model vs Future Enclave](#current-model-vs-future-enclave) below.

## Design Decision

**OWS currently uses in-process hardening for key handling.** Key material is decrypted only after the relevant checks pass, used for signing, and zeroized immediately after use. The current implementation relies on process hardening (`mlock`, zeroization, anti-debugging, core-dump disabling) plus the policy-gated signing path for agent credentials. A subprocess signing enclave remains an optional future enhancement, not the current execution model.

### Why This Model

The primary threat in agent wallet systems is misuse through prompt injection, runaway automation, or weak operational controls. The current implementation addresses that threat with credential-scoped access and policy evaluation before decryption, while using local memory-hardening techniques to reduce exposure during signing. We evaluated four isolation strategies:

| Strategy | Security | Performance | Complexity | Used By |
|---|---|---|---|---|
| In-process encryption only | Low — keys in same address space | Fast | Low | Most local keystores |
| TEE enclaves (AWS Nitro, SGX) | Very high — hardware isolation | Fast | High (requires cloud) | Privy, Turnkey, Coinbase |
| MPC/threshold signatures | High — key never reconstituted | Slow (multi-round) | Very high | Lit Protocol |
| **Subprocess isolation** | High — OS-level memory isolation | Fast | Medium | Future OWS enhancement |

OWS targets local-first deployments where cloud TEEs are not required. Today that means:
- The signer runs in the same process as the CLI or language binding
- Agent credentials (`ows_key_...`) trigger policy evaluation before key material is decrypted
- Decrypted key material is stored in hardened memory and zeroized on drop
- Process hardening reduces debugging, core-dump, and swap exposure

For deployments that need a stronger process boundary, the future subprocess enclave can be added without changing the wallet or policy model.

## Current Architecture

```
┌────────────────────────────────────────────┐
│           Agent / CLI / App Process        │
│                                            │
│  1. Build transaction or message           │
│  2. Call OWS signing API                   │
│  3. If credential is `ows_key_...`:        │
│     evaluate attached policies             │
│  4. Decrypt wallet secret in hardened mem  │
│  5. Derive chain-specific signing key      │
│  6. Sign payload                           │
│  7. Zeroize key material                   │
│  8. Return signature / signed tx           │
│                                            │
│  Stored on disk: encrypted wallet files,   │
│  API key files, policies, config           │
└────────────────────────────────────────────┘
```

## Future Enclave Protocol

The subprocess enclave model described below is a possible future transport for the same signing flow. It is **not implemented today**.

A future signing enclave could communicate via a simple JSON-RPC protocol over its transport (Unix socket or stdin/stdout):

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "sign",
  "params": {
    "wallet_id": "3198bc9c-...",
    "chain_id": "eip155:8453",
    "payload": "<hex-encoded-serializable-transaction>",
    "payload_type": "transaction"
  }
}
```

### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "signature": "0x...",
    "signed_payload": "0x..."
  }
}
```

### Methods

| Method | Description |
|---|---|
| `sign` | Sign a transaction payload |
| `sign_message` | Sign an arbitrary message |
| `unlock` | Provide the vault passphrase to the enclave |
| `lock` | Wipe all decrypted material and require re-authentication |
| `status` | Check if the enclave is unlocked and healthy |

## Key Lifecycle in the Current Implementation

```
1. OWS receives a sign request
2. If the credential is an API token, evaluate attached policies before decryption
3. Read the encrypted wallet or API-key-backed secret from disk
4. Derive the decryption key (scrypt for passphrases, HKDF for API tokens)
5. Decrypt key material (mnemonic or private key) into hardened memory
6. Derive the chain-specific signing key if needed
7. Sign the payload
8. Immediately zero out decrypted mnemonic/private key bytes, derived signing key bytes, and KDF-derived key bytes
9. Return only the signature or signed payload
```

Immediate zeroization is critical. In the current Rust implementation this is handled with dedicated secret containers and drop-time zeroization.

## Passphrase Handling

OWS does not currently implement a separate unlockable enclave process. Instead, credentials are supplied to the current process and used per request.

### 1. Interactive prompt (CLI mode)
The CLI can prompt for the passphrase when it is needed.

### 2. Environment variable (CLI mode)
The CLI reads `OWS_PASSPHRASE` and clears it immediately after reading.

### 3. Function parameter (bindings)
The Node and Python bindings accept the credential as a function parameter. That credential may be either the owner's passphrase or an `ows_key_...` API token.

> **Warning:** Environment variables remain the weakest supported delivery mechanism. They are convenient for automation but can leak via process inspection, crash dumps, or child-process inheritance if not cleared promptly.

## Threat Model

| Threat | Mitigation |
|---|---|
| Agent/LLM misuses a wallet via automation | API tokens scope access and trigger policy checks before decryption |
| Key leaked to logs | OWS does not log key material; audit logging records operations only |
| Core dump contains keys | Process hardening disables core dumps / attach where supported |
| Swap file contains keys | Hardened secret buffers use `mlock()` where available; failures should be treated as reduced hardening |
| Cold boot / memory forensics | Keys are zeroized immediately after signing; exposure window is short |
| Compromised process memory | **Not fully mitigated in the current model.** This is the main gap a future subprocess enclave would address |
| Passphrase brute force | Scrypt slows offline guessing; current wallet envelopes use a minimum work factor of `2^16` |

## Defense in Depth

OWS key isolation is one layer. For maximum security, deployments can add:

1. **OS-level sandboxing**: Run the enclave in a seccomp-bpf sandbox (Linux) or App Sandbox (macOS) restricting syscalls to read/write/crypto operations only.
2. **TEE backends**: Replace the subprocess with a TEE-backed signer (AWS Nitro, Intel SGX) using the same JSON-RPC protocol.
3. **Hardware wallets**: A Ledger/Trezor can serve as the signing backend, with the enclave proxying sign requests to the device.
4. **Key sharding**: Split the encrypted wallet across multiple files requiring quorum access (following Privy's SSS model).

All backends implement the same enclave protocol, making them drop-in replacements.

## Key Caching for Batch Performance

Decrypting key material via scrypt is intentionally non-trivial. That cost improves passphrase resistance, but it also adds noticeable latency if repeated for every request in a batch.

Implementations SHOULD maintain a short-lived, in-memory cache of derived key material with the following constraints:

| Property | Requirement |
|---|---|
| TTL | No more than 30 seconds; 5 seconds recommended |
| Max entries | Bounded (e.g., 32 entries) with LRU eviction |
| Memory protection | Cached key material MUST be `mlock()`'d and zeroized on eviction |
| Signal handling | Cache MUST be cleared on SIGTERM, SIGINT, and SIGHUP before process exit |
| Cache key | Derived from `SHA-256(mnemonic \|\| passphrase \|\| derivation_path \|\| curve)` — never the raw mnemonic |

The current implementation does not expose a vault unlock session. If the future enclave model is added, an explicit unlock/lock workflow could complement the key cache for interactive workflows.

## Comparison with Industry Approaches

| System | Isolation Mechanism | Local-First? |
|---|---|---|
| Privy | TEE + SSS (2-of-2 or 2-of-3 sharding) | No (cloud) |
| Turnkey | AWS Nitro Enclaves | No (cloud) |
| Coinbase CDP | TEE | No (cloud) |
| Lit Protocol | Distributed key generation across nodes | No (network) |
| Crossmint | Dual-key smart contract + TEE | No (cloud) |
| Phala Wallet | TEE (Intel SGX) on decentralized cloud | No (cloud) |
| **OWS** | **In-process hardening today; optional subprocess / TEE later** | **Yes** |

OWS is the only standard designed for local-first operation. The in-process model works on any machine with no additional infrastructure. When stronger guarantees are needed, the subprocess enclave can be added without changing the signing interface.

## Current Model vs Future Enclave

### Current: in-process hardening + code-path policy enforcement

```
Agent → sign_transaction(wallet, chain, tx, "ows_key_...")
          │
          └─► ows-lib (same process)
                ├── token lookup + policy evaluation
                ├── HKDF decrypt mnemonic (mlock'd, zeroized on drop)
                ├── sign
                └── return signature
```

Policy enforcement is handled by the code path — the `ows_key_` credential triggers policy evaluation before decryption. The agent and signer share an address space. In-process hardening (mlock, zeroize, anti-ptrace, anti-coredump) reduces the window for key extraction but does not eliminate it.

**This model defends against:** prompt injection, runaway agents, misconfigured agents, accidental overspending — the primary threats for agent wallets.

**This model does not defend against:** a compromised agent binary reading decrypted key material from shared memory.

### Future: per-request subprocess enclave

```
Agent → sign_transaction(wallet, chain, tx, "ows_key_...")
          │
          └─► ows-lib (parent process)
                ├── token lookup + policy evaluation
                └── fork/exec ows-enclave
                      ├── receive (token, wallet_id, tx) over stdin
                      ├── HKDF decrypt mnemonic
                      ├── sign
                      ├── zeroize
                      ├── write signature to stdout
                      └── exit
```

The decrypt→sign→wipe path moves to a child process. The parent (agent's process) never has the mnemonic in its address space. The child is stateless — spawned per request, no daemon, no unlock step. If it crashes, the next request spawns a new one.

This uses the same Approach B crypto (HKDF token → AES-256-GCM). The only change is which process runs the decryption. It is a mechanical refactor, not a design change.

**Additional defense:** even if the agent binary is compromised, it cannot extract key material from the parent process because the key material only exists in the child's address space.

**Not a prerequisite for:** policy enforcement, API keys, or any other feature in the current roadmap. It can be layered on independently.

## References

- [Privy: Embedded Wallet Architecture](https://privy.io/blog/embedded-wallet-architecture)
- [Privy: SSS vs MPC-TSS vs TEEs](https://privy.io/blog/embedded-wallet-architecture-breakdown)
- [Turnkey: Key Management in Nitro Enclaves](https://whitepaper.turnkey.com/principles)
- [Google Cloud: Securing Blockchain-Interacting Agents](https://cloud.google.com/blog/products/identity-security/securing-blockchain-interacting-agents)
- [Linux prctl(2) PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/prctl.2.html)
- [mlock(2) Memory Locking](https://man7.org/linux/man-pages/man2/mlock.2.html)
