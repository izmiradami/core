# Guardian Agent

> Zero-trust AI transaction layer built on OWS — agents execute blockchain transactions without ever seeing the private key.

**Repo:** [github.com/izmiradami/guardian-agent](https://github.com/izmiradami/guardian-agent)  
**Live Demo:** [izmiradami.github.io/guardian-agent](https://izmiradami.github.io/guardian-agent)

## What it does

Guardian Agent sits between an AI agent and the wallet. The agent requests a transaction. Guardian decides if it's allowed. The key is never exposed.

```
AI Agent → Interface → Policy Engine → Signer → Vault
                            ↓
                    (key never leaves here)
```

## How it uses OWS

- Uses OWS vault for local-first encrypted key storage (`~/.guardian/wallets/`)
- Leverages OWS policy engine to enforce spend limits and token allowlists
- Relies on OWS signing interface — key decrypted only during `sign()`, immediately zeroized
- Agent receives only the transaction hash — never the raw key

## Stack

- OWS core for vault + signing
- Policy engine layer on top
- Interactive demo UI (HTML, no backend)

## Key insight

> "AI agents should be powerful but never trusted with private keys. OWS makes this possible out of the box."
