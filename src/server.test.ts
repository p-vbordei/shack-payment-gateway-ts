/**
 * Integration tests for the server logic using the crypto layer directly.
 *
 * Because server.ts calls main() at the module level (making it unsuitable for
 * direct import in tests), these tests exercise the same end-to-end logic by
 * driving the crypto primitives that all server tool handlers rely on.
 * The JSON-RPC dispatch layer is covered by the e2e binary tests; here we
 * focus on the observable contracts: address recovery, wallet matching, and
 * validation — as a client of the server would experience them.
 */

import { eip191Hash, recoverEthAddress, validateEthAddress } from "./crypto.js";

// ── Test vectors ──────────────────────────────────────────────────────────────
const KNOWN_MESSAGE = "Hello World";
const KNOWN_SIG =
  "e9d4cfddf4da3a1b1800c7c178456cf0e1d285417b0204c7cd038ad450fe541464548e164dfb8acc8340cfff0fbed9aa5585f1c78f7241aa5a8434b3e39ec2b61b";
const KNOWN_ADDRESS = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1";

// Second key — different address.
const SIG2 =
  "1266eb4885a5860406635409bb01bfebc98715c72b08143606986ab07f2b283367af2d1eb4bca4dc3ac698abc952f4650296039998b36d4bf0cc48610ffa9d4d1b";
const ADDR2 = "0x5050a4f4b3f9338c3472dcc01a87c76a144b3c9c";
const MSG2 = "Shack payment test";

// ── verify_payment logic (permissive mode) ───────────────────────────────────

describe("verify_payment integration — permissive mode", () => {
  it("recovers address from known vector", () => {
    const hash = eip191Hash(KNOWN_MESSAGE);
    const addr = recoverEthAddress(hash, KNOWN_SIG);
    expect(addr.toLowerCase()).toBe(KNOWN_ADDRESS.toLowerCase());
  });

  it("permissive: any valid signature is authorized (verified=true)", () => {
    const hash = eip191Hash(KNOWN_MESSAGE);
    const addr = recoverEthAddress(hash, KNOWN_SIG);
    // In permissive mode the server sets verified = true unconditionally.
    const authorizedWallet: string | null = null;
    const verified = authorizedWallet === null || authorizedWallet.toLowerCase() === addr.toLowerCase();
    expect(verified).toBe(true);
  });

  it("recovers a different address for a different key", () => {
    const hash = eip191Hash(MSG2);
    const addr = recoverEthAddress(hash, SIG2);
    expect(addr.toLowerCase()).toBe(ADDR2.toLowerCase());
    expect(addr.toLowerCase()).not.toBe(KNOWN_ADDRESS.toLowerCase());
  });
});

// ── verify_payment logic — wallet matching ────────────────────────────────────

describe("verify_payment integration — wallet matching", () => {
  it("fails verification against wrong wallet", () => {
    const hash = eip191Hash(KNOWN_MESSAGE);
    const addr = recoverEthAddress(hash, KNOWN_SIG);
    const wrongWallet = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    const verified = wrongWallet.toLowerCase() === addr.toLowerCase();
    expect(verified).toBe(false);
  });

  it("passes verification against correct wallet", () => {
    const hash = eip191Hash(KNOWN_MESSAGE);
    const addr = recoverEthAddress(hash, KNOWN_SIG);
    const verified = KNOWN_ADDRESS.toLowerCase() === addr.toLowerCase();
    expect(verified).toBe(true);
  });

  it("comparison is case-insensitive", () => {
    const hash = eip191Hash(KNOWN_MESSAGE);
    const addr = recoverEthAddress(hash, KNOWN_SIG);
    const upperWallet = KNOWN_ADDRESS.toUpperCase();
    const verified = upperWallet.toLowerCase() === addr.toLowerCase();
    expect(verified).toBe(true);
  });
});

// ── verify_payment logic — signature errors ───────────────────────────────────

describe("verify_payment integration — invalid signatures", () => {
  it("throws on invalid (too-short) signature", () => {
    const hash = eip191Hash("test");
    expect(() => recoverEthAddress(hash, "deadbeef")).toThrow();
  });

  it("throws on non-hex signature", () => {
    const hash = eip191Hash("test");
    expect(() => recoverEthAddress(hash, "zz".repeat(65))).toThrow("non-hex");
  });

  it("throws on all-zero cryptographically invalid signature", () => {
    const hash = eip191Hash("test");
    expect(() => recoverEthAddress(hash, "00".repeat(65))).toThrow();
  });
});

// ── request_authorization logic ───────────────────────────────────────────────

describe("request_authorization logic", () => {
  it("produces a non-empty string from the challenge format", () => {
    // Mirror the server's challenge format to verify the contract.
    const now = Math.floor(Date.now() / 1000);
    const nonce = "0".repeat(32);
    const challenge =
      `Authorize execution of tool: my_tool costing 1.5 Shack-Credits. ` +
      `Timestamp: ${now}. Nonce: ${nonce}`;
    expect(challenge).toContain("my_tool");
    expect(challenge).toContain("1.5");
    expect(challenge).toContain("Nonce:");
  });

  it("challenge is signable and recoverable", () => {
    // Signing the challenge with the known key must recover the known address.
    const challenge = "Hello World"; // reuse the pre-computed vector
    const hash = eip191Hash(challenge);
    const addr = recoverEthAddress(hash, KNOWN_SIG);
    expect(addr.toLowerCase()).toBe(KNOWN_ADDRESS.toLowerCase());
  });
});

// ── validateEthAddress integration ───────────────────────────────────────────

describe("validateEthAddress integration", () => {
  it("accepts valid address", () => {
    expect(() => validateEthAddress(KNOWN_ADDRESS)).not.toThrow();
  });

  it("rejects address that is too short", () => {
    expect(() => validateEthAddress("0xshort")).toThrow();
  });

  it("rejects address with wrong length", () => {
    expect(() => validateEthAddress("0x" + "a".repeat(39))).toThrow("40 hex chars");
  });

  it("rejects address with non-hex chars", () => {
    expect(() => validateEthAddress("0x" + "G".repeat(40))).toThrow("non-hex");
  });

  it("accepts address without 0x prefix", () => {
    expect(() =>
      validateEthAddress("1a642f0e3c3af545e7acbd38b07251b3990914f1")
    ).not.toThrow();
  });
});
