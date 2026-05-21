/**
 * EIP-191 hashing and secp256k1 public-key recovery.
 *
 * EIP-191 personal_sign format:
 *   "\x19Ethereum Signed Message:\n" + len(msg) + msg
 * The Keccak-256 hash of that string is what the signer signs.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

/** Returns the 32-byte EIP-191 Keccak-256 digest of message. */
export function eip191Hash(message: string): Uint8Array {
  const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
  const enc = new TextEncoder();
  const data = new Uint8Array([...enc.encode(prefix), ...enc.encode(message)]);
  return keccak_256(data);
}

/**
 * Recover the Ethereum address that produced an EIP-191 signature.
 *
 * signatureHex is a 65-byte hex string (with or without 0x prefix).
 * The last byte is the recovery identifier v (0, 1, 27, 28, or EIP-155).
 * Returns the recovered address as a lowercase "0x..." string.
 */
export function recoverEthAddress(
  messageHash: Uint8Array,
  signatureHex: string
): string {
  const stripped = signatureHex.startsWith("0x")
    ? signatureHex.slice(2)
    : signatureHex;

  if (!/^[0-9a-fA-F]+$/.test(stripped)) {
    throw new Error("Signature contains non-hex characters");
  }

  if (stripped.length !== 130) {
    const byteLen = stripped.length / 2;
    throw new Error(
      `Signature must be exactly 65 bytes (130 hex chars); got ${byteLen}`
    );
  }

  const sigBytes = hexToBytes(stripped);
  const vByte = sigBytes[64];

  // Normalize v to a 0/1 recovery bit.
  let recId: number;
  if (vByte === 0 || vByte === 1) {
    recId = vByte;
  } else if (vByte === 27) {
    recId = 0;
  } else if (vByte === 28) {
    recId = 1;
  } else if (vByte >= 35) {
    // EIP-155: v = 35 + chain_id*2 + recovery_bit
    recId = (vByte - 35) & 1;
  } else {
    throw new Error(`Invalid recovery byte v=${vByte}`);
  }

  // @noble/curves expects the 64-byte r+s as a hex string, plus recovery id.
  const rsBigInt = BigInt("0x" + stripped.slice(0, 128));
  const sig = secp256k1.Signature.fromCompact(stripped.slice(0, 128)).addRecoveryBit(recId);

  let pubKey: { toRawBytes(compressed: boolean): Uint8Array };
  try {
    pubKey = sig.recoverPublicKey(messageHash);
  } catch (e) {
    throw new Error(`Key recovery failed: ${e}`);
  }

  // Uncompressed public key is 65 bytes: 0x04 + x(32) + y(32).
  // Ethereum address = last 20 bytes of keccak256(x||y).
  const uncompressed = pubKey.toRawBytes(false); // 65 bytes with 0x04 prefix
  const xyBytes = uncompressed.slice(1); // skip 0x04
  const addrHash = keccak_256(xyBytes);
  const addrBytes = addrHash.slice(12); // last 20 bytes

  return "0x" + bytesToHex(addrBytes);
}

/**
 * Validate that addr is a well-formed Ethereum address.
 * Accepts checksummed or lowercase, with or without 0x prefix.
 * Throws on invalid input.
 */
export function validateEthAddress(addr: string): void {
  const stripped = addr.startsWith("0x") ? addr.slice(2) : addr;
  if (stripped.length !== 40) {
    throw new Error(
      `Expected 40 hex chars after 0x prefix, got ${stripped.length}`
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(stripped)) {
    throw new Error("Address contains non-hex characters");
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
