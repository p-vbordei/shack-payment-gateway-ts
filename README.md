# shack-payment-gateway

An MCP server that gates tool calls behind cryptographic micropayment authorization using Ethereum EIP-191 personal message signing.

Speaks JSON-RPC 2.0 over stdio. STDOUT carries only protocol messages; all diagnostic logs go to STDERR.

## What it does

- Generates a unique EIP-191 challenge string (timestamp + nonce) that a client must sign with their Ethereum private key before calling a paid tool.
- Accepts the resulting signature, recovers the signer's Ethereum address via ECDSA key recovery, and compares it against the configured authorized wallet.
- Returns `verified: true` when the recovered address matches, `verified: false` otherwise.
- In permissive mode (no wallet configured), any valid signature is accepted and the recovered address is returned as authorized.

## MCP tools

| Tool | Description |
|---|---|
| `request_authorization` | Generates a cryptographic EIP-191 challenge string the client must sign with their Ethereum private key before calling a paid tool. |
| `verify_payment` | Verifies an EIP-191 signature against the challenge; returns the recovered signer address and whether it matches the authorized wallet. |

## Install and build

```sh
npm install
npm run build
```

## Run

```sh
# Permissive mode (any valid signature is authorized):
node dist/server.js

# With a specific authorized wallet:
node dist/server.js --authorized-wallet 0xYourWalletAddress

# Via environment variable:
SHACK_AUTHORIZED_WALLET=0xYourWalletAddress node dist/server.js
```

## Tests

```sh
npm test
```

## License

Apache-2.0
