#!/usr/bin/env node
/**
 * shack-payment-gateway MCP server.
 *
 * Speaks JSON-RPC 2.0 over stdio. STDOUT carries only protocol messages;
 * all diagnostic output goes to STDERR.
 */

import * as readline from "readline";
import * as crypto from "crypto";
import { eip191Hash, recoverEthAddress, validateEthAddress } from "./crypto.js";

const SERVER_INFO = { name: "shack-payment-gateway", version: "0.1.0" };
const PROTOCOL_VERSION = "2024-11-05";

const TOOLS = [
  {
    name: "request_authorization",
    description:
      "Generates a cryptographic EIP-191 challenge string that the client must " +
      "sign with their Ethereum private key before calling a paid tool.",
    inputSchema: {
      type: "object",
      properties: {
        tool_name: {
          type: "string",
          description: "Name of the tool the client wants to call",
        },
        cost: {
          type: "string",
          description: 'Cost in Shack-Credits (e.g. "1.5")',
        },
      },
      required: ["tool_name", "cost"],
    },
  },
  {
    name: "verify_payment",
    description:
      "Verifies an EIP-191 signature against the challenge returned by " +
      "request_authorization. On success, returns the recovered signer address " +
      "and whether it matches the authorized wallet.",
    inputSchema: {
      type: "object",
      properties: {
        challenge: {
          type: "string",
          description: "The exact challenge string returned by request_authorization",
        },
        signature: {
          type: "string",
          description:
            "Hex-encoded 65-byte EIP-191 signature (with or without 0x prefix)",
        },
      },
      required: ["challenge", "signature"],
    },
  },
];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonValue = any;

function ok(id: JsonValue, result: JsonValue): object {
  return { jsonrpc: "2.0", result, id };
}

function err(id: JsonValue, code: number, message: string): object {
  return { jsonrpc: "2.0", error: { code, message }, id };
}

function textContent(payload: object): object {
  return { content: [{ type: "text", text: JSON.stringify(payload) }] };
}

function handleRequestAuthorization(args: JsonValue): object {
  const toolName: string = args?.tool_name ?? "";
  const cost: string = args?.cost ?? "";

  if (!toolName) throw new Error("tool_name must not be empty");
  if (!cost) throw new Error("cost must not be empty");
  if (isNaN(Number(cost))) throw new Error(`cost is not a valid number: ${cost}`);

  const now = Math.floor(Date.now() / 1000);
  // 16-byte random nonce makes each challenge globally unique.
  const nonce = crypto.randomBytes(16).toString("hex");

  const challenge =
    `Authorize execution of tool: ${toolName} costing ${cost} Shack-Credits. ` +
    `Timestamp: ${now}. Nonce: ${nonce}`;

  process.stderr.write(`Challenge issued for tool '${toolName}' at cost ${cost}\n`);

  return textContent({ challenge, tool_name: toolName, cost });
}

function handleVerifyPayment(args: JsonValue, authorizedWallet: string | null): object {
  const challenge: string = args?.challenge ?? "";
  const signature: string = args?.signature ?? "";

  if (!challenge) throw new Error("challenge must not be empty");
  if (!signature) throw new Error("signature must not be empty");

  const msgHash = eip191Hash(challenge);
  const signerAddr = recoverEthAddress(msgHash, signature);

  let verified: boolean;
  if (authorizedWallet !== null) {
    verified = authorizedWallet.toLowerCase() === signerAddr.toLowerCase();
  } else {
    // Permissive mode: any valid signature is accepted.
    verified = true;
  }

  process.stderr.write(
    `Verification result: verified=${verified}, recovered=${signerAddr}\n`
  );

  return textContent({
    verified,
    recovered_address: signerAddr,
    authorized_address: authorizedWallet,
  });
}

function dispatchTool(
  name: string,
  toolArgs: JsonValue,
  authorizedWallet: string | null
): object {
  if (name === "request_authorization") {
    return handleRequestAuthorization(toolArgs);
  }
  if (name === "verify_payment") {
    return handleVerifyPayment(toolArgs, authorizedWallet);
  }
  throw new Error(`Unknown tool: ${name}`);
}

function handleMessage(
  req: JsonValue,
  authorizedWallet: string | null
): object | null {
  const id = req?.id ?? null;
  const method = req?.method;

  if (typeof method !== "string") {
    return err(id, -32600, "Invalid Request: missing method");
  }

  if (method === "initialize") {
    return ok(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
    });
  }

  if (method === "notifications/initialized") {
    // Notification: no response.
    return null;
  }

  if (method === "tools/list") {
    return ok(id, { tools: TOOLS });
  }

  if (method === "tools/call") {
    const params = req?.params ?? {};
    const toolName = params?.name;
    if (typeof toolName !== "string") {
      return err(id, -32602, "Invalid params: missing tool name");
    }
    const toolArgs = params?.arguments ?? {};

    try {
      const result = dispatchTool(toolName, toolArgs, authorizedWallet);
      return ok(id, result);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      process.stderr.write(`Tool '${toolName}' error: ${msg}\n`);
      return err(id, -32603, msg);
    }
  }

  return err(id, -32601, `Method not found: ${method}`);
}

function run(authorizedWallet: string | null): void {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let req: JsonValue;
    try {
      req = JSON.parse(trimmed);
    } catch (e) {
      const resp = err(null, -32700, `Parse error: ${e}`);
      process.stdout.write(JSON.stringify(resp) + "\n");
      return;
    }

    const resp = handleMessage(req, authorizedWallet);
    if (resp !== null) {
      process.stdout.write(JSON.stringify(resp) + "\n");
    }
  });
}

function parseArgs(): { authorizedWallet: string | null } {
  const args = process.argv.slice(2);
  let authorizedWallet: string | null = process.env.SHACK_AUTHORIZED_WALLET ?? null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--authorized-wallet" && i + 1 < args.length) {
      authorizedWallet = args[i + 1];
      i++;
    }
  }
  return { authorizedWallet };
}

function main(): void {
  const { authorizedWallet } = parseArgs();

  if (authorizedWallet !== null) {
    try {
      validateEthAddress(authorizedWallet);
    } catch (e) {
      process.stderr.write(`Invalid --authorized-wallet address: ${e}\n`);
      process.exit(1);
    }
    process.stderr.write(
      `Payment gateway running. Authorized wallet: ${authorizedWallet}\n`
    );
  } else {
    process.stderr.write(
      "Payment gateway running in permissive mode (no wallet restriction).\n"
    );
  }

  run(authorizedWallet);
}

main();
