## Architecture

```
Agent / CLI / App
       │
       │  OWS Interface (MCP / SDK / CLI)
       ▼
┌─────────────────────┐
│    Access Layer      │     1. Agent calls ows.sign()
│  ┌────────────────┐  │     2. Policy engine evaluates
│  │ Policy Engine   │  │     3. Key decrypted in memory
│  │ (pre-signing)   │  │     4. Transaction signed
│  └───────┬────────┘  │     5. Key wiped from memory
│  ┌───────▼────────┐  │     6. Signature returned
│  │  Signing Core   │  │
│  │                 │  │     The agent NEVER sees
│  └───────┬────────┘  │     the private key.
│  ┌───────▼────────┐  │
│  │  Wallet Vault   │  │
│  │ ~/.ows/wallets/ │  │
│  └────────────────┘  │
└─────────────────────┘
```
