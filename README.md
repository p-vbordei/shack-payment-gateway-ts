# shack-payment-gateway

An MCP server that gates tool calls behind cryptographic micropayment
authorization using Ethereum EIP-191 personal message signing.

Speaks JSON-RPC 2.0 over stdio.  STDOUT carries only protocol messages; all
diagnostic logs go to STDERR.

## What it does

1. A client that wants to call a paid tool first calls
   `request_authorization`, which returns a unique challenge string
   (timestamp + random nonce).
2. The client signs that challenge with their Ethereum private key using the
   EIP-191 `personal_sign` scheme and obtains a 65-byte signature.
3. The client calls `verify_payment`, passing the original challenge and the
   signature.  The server recovers the signer's Ethereum address via ECDSA
   key recovery and compares it against the configured authorized wallet.
4. If the addresses match, `verified: true` is returned.  Otherwise
   `verified: false` is returned.

In **permissive mode** (no `--authorized-wallet` flag), any valid signature
is accepted and the recovered address is returned as authorized.  This mode
is useful for development and testing.

## MCP tools

| Tool | Arguments | Description |
|---|---|---|
| `request_authorization` | `tool_name` (string), `cost` (string) | Returns a unique EIP-191 challenge string the client must sign before calling a paid tool.  `cost` must be a parseable decimal number (e.g. `"1.5"`). |
| `verify_payment` | `challenge` (string), `signature` (string) | Verifies the EIP-191 signature against the challenge.  Returns `verified`, `recovered_address`, and `authorized_address`. |

## Configuration / CLI flags

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--authorized-wallet <addr>` | `SHACK_AUTHORIZED_WALLET` | _(none)_ | Ethereum address that `verify_payment` accepts.  Omit to run in permissive mode. |

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

## Usage example

The following shows a complete JSON-RPC 2.0 exchange.  Each JSON object is
sent as a single newline-terminated line on STDIN; responses arrive on STDOUT.

**Step 1 — request a challenge:**

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"request_authorization","arguments":{"tool_name":"my_paid_tool","cost":"1.5"}}}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\"challenge\":\"Authorize execution of tool: my_paid_tool costing 1.5 Shack-Credits. Timestamp: 1716307200. Nonce: 4f3a2b1c...\",\"tool_name\":\"my_paid_tool\",\"cost\":\"1.5\"}"
    }]
  }
}
```

**Step 2 — sign the challenge with your Ethereum private key** (client-side,
not handled by this server) and call `verify_payment`:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"verify_payment","arguments":{"challenge":"Authorize execution of tool: my_paid_tool costing 1.5 Shack-Credits. Timestamp: 1716307200. Nonce: 4f3a2b1c...","signature":"0xe9d4cfdd...1b"}}}
```

Response (permissive mode):

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\"verified\":true,\"recovered_address\":\"0x1a642f0e3c3af545e7acbd38b07251b3990914f1\",\"authorized_address\":null}"
    }]
  }
}
```

## License

Apache-2.0
