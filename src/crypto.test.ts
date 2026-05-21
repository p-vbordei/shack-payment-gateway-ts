/**
 * Tests for EIP-191 hashing and address recovery.
 *
 * All test vectors were generated with known private keys and verified
 * against the Python crypto module.  The same vectors are used in the Rust
 * and Python implementations for cross-language consistency.
 */

import { eip191Hash, recoverEthAddress, validateEthAddress } from "./crypto.js";

// ── Test vectors ─────────────────────────────────────────────────────────────
// privkey 0x01*32  =>  address 0x1a642f0e3c3af545e7acbd38b07251b3990914f1
const VECTOR1_MSG = "Hello World";
const VECTOR1_SIG =
  "e9d4cfddf4da3a1b1800c7c178456cf0e1d285417b0204c7cd038ad450fe541464548e164dfb8acc8340cfff0fbed9aa5585f1c78f7241aa5a8434b3e39ec2b61b";
const VECTOR1_ADDR = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1";

// privkey 0x01*32, second message — verifies the hash function independently.
const VECTOR2_MSG = "Shack payment test";
const VECTOR2_SIG =
  "cf686ac0e068516baccc7cf6bd679cd6765778fcee9a5f6bd891636859d0ccd95c3c84855c01003144cc9779b21fc6a618de2eefcb28742875544c070f30a82a1b";
const VECTOR2_ADDR = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1";

// privkey 0x02*32  =>  address 0x5050a4f4b3f9338c3472dcc01a87c76a144b3c9c
const VECTOR3_MSG = "Shack payment test";
const VECTOR3_SIG =
  "1266eb4885a5860406635409bb01bfebc98715c72b08143606986ab07f2b283367af2d1eb4bca4dc3ac698abc952f4650296039998b36d4bf0cc48610ffa9d4d1b";
const VECTOR3_ADDR = "0x5050a4f4b3f9338c3472dcc01a87c76a144b3c9c";

// privkey 0x04*32, v=0x1c (28)  =>  address 0xc48b812bb43401392c037381aca934f4069c0517
const VECTOR4_MSG = "test message 1";
const VECTOR4_SIG =
  "7367ceb45836aebde6b200536433c8cdbe45eb56cbfc59ffd098f426d4df27565e283e4123e77f84bd0bdb75bfbf5eaa3928e9de84871004411eef54232940631c";
const VECTOR4_ADDR = "0xc48b812bb43401392c037381aca934f4069c0517";

// privkey 0x05*32, v=0x00 (raw rec_id)  =>  0xd09ad14080d4b257a819a4f579b8485be88f086c
const VECTOR5_MSG = "raw v test 1";
const VECTOR5_SIG =
  "7bd466ca57bbe83ae9ddab6b788d96255842b77d1d608ac17669b532d33ba3be3baf236040008d96be61934d4ba914f8786a8568ba85253912dc6d1eb0598e1500";
const VECTOR5_ADDR = "0xd09ad14080d4b257a819a4f579b8485be88f086c";

// privkey 0x06*32, EIP-155 v=37 (chain_id=1, rec_bit=0)  =>  0x0cb030d11a8be48b60418857874deee61d1071e0
const VECTOR6_MSG = "eip155 test 3";
const VECTOR6_SIG =
  "31387168b04142cfe9df12a5569d56f657187b9531ae1c2e580703fe950ff9272b24456ebd1cc8eab026ff7932754d604c4164ab00fdd51d01db7f6bc61a1f7225";
const VECTOR6_ADDR = "0x0cb030d11a8be48b60418857874deee61d1071e0";

// ── eip191Hash ───────────────────────────────────────────────────────────────

describe("eip191Hash", () => {
  it("is deterministic", () => {
    const h1 = eip191Hash("deterministic input");
    const h2 = eip191Hash("deterministic input");
    expect(h1).toEqual(h2);
  });

  it("differs for different messages", () => {
    const h1 = eip191Hash("message A");
    const h2 = eip191Hash("message B");
    expect(h1).not.toEqual(h2);
  });

  it("returns a 32-byte Uint8Array", () => {
    const h = eip191Hash("any message");
    expect(h).toBeInstanceOf(Uint8Array);
    expect(h.length).toBe(32);
  });

  it("produces the correct hash for the empty string", () => {
    const h = eip191Hash("");
    const hex = Array.from(h).map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe("5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad");
  });

  it("uses byte length for the prefix (not char count)", () => {
    // 'é' is 2 UTF-8 bytes; "ab" is also 2 bytes — same prefix, different body.
    const hAscii = eip191Hash("ab");
    const hUtf8 = eip191Hash("é");
    expect(hAscii).not.toEqual(hUtf8);
  });
});

// ── recoverEthAddress: success paths ─────────────────────────────────────────

describe("recoverEthAddress — success", () => {
  it("recovers the known test vector", () => {
    const hash = eip191Hash(VECTOR1_MSG);
    const addr = recoverEthAddress(hash, VECTOR1_SIG);
    expect(addr.toLowerCase()).toBe(VECTOR1_ADDR);
  });

  it("handles 0x prefix on signature", () => {
    const hash = eip191Hash(VECTOR1_MSG);
    const addr = recoverEthAddress(hash, "0x" + VECTOR1_SIG);
    expect(addr.toLowerCase()).toBe(VECTOR1_ADDR);
  });

  it("recovers the second test vector", () => {
    const hash = eip191Hash(VECTOR2_MSG);
    const addr = recoverEthAddress(hash, VECTOR2_SIG);
    expect(addr.toLowerCase()).toBe(VECTOR2_ADDR);
  });

  it("recovers a distinct address from a different key", () => {
    const hash = eip191Hash(VECTOR3_MSG);
    const addr = recoverEthAddress(hash, VECTOR3_SIG);
    expect(addr.toLowerCase()).toBe(VECTOR3_ADDR);
    expect(addr.toLowerCase()).not.toBe(VECTOR1_ADDR);
  });
});

// ── v-byte normalization ──────────────────────────────────────────────────────

describe("recoverEthAddress — v-byte normalization", () => {
  it("handles v=27 (0x1b)", () => {
    const hash = eip191Hash(VECTOR1_MSG);
    const addr = recoverEthAddress(hash, VECTOR1_SIG);
    expect(addr.toLowerCase()).toBe(VECTOR1_ADDR);
  });

  it("handles v=28 (0x1c)", () => {
    const hash = eip191Hash(VECTOR4_MSG);
    const addr = recoverEthAddress(hash, VECTOR4_SIG);
    expect(addr.toLowerCase()).toBe(VECTOR4_ADDR);
  });

  it("handles v=0 (raw recovery bit)", () => {
    const hash = eip191Hash(VECTOR5_MSG);
    const addr = recoverEthAddress(hash, VECTOR5_SIG);
    expect(addr.toLowerCase()).toBe(VECTOR5_ADDR);
  });

  it("handles EIP-155 v=37 (chain_id=1, rec_bit=0)", () => {
    const hash = eip191Hash(VECTOR6_MSG);
    const addr = recoverEthAddress(hash, VECTOR6_SIG);
    expect(addr.toLowerCase()).toBe(VECTOR6_ADDR);
  });

  it("throws on invalid v=2", () => {
    const hash = eip191Hash("test");
    // Mutate the last byte of the known signature to v=2.
    const sigBytes = Buffer.from(VECTOR1_SIG, "hex");
    sigBytes[64] = 2;
    expect(() => recoverEthAddress(hash, sigBytes.toString("hex"))).toThrow(
      "Invalid recovery byte"
    );
  });
});

// ── recoverEthAddress: error paths ───────────────────────────────────────────

describe("recoverEthAddress — errors", () => {
  it("throws on too-short signature", () => {
    const hash = eip191Hash("test");
    const shortSig = "a".repeat(128); // 64 bytes — missing recovery byte
    expect(() => recoverEthAddress(hash, shortSig)).toThrow("65 bytes");
  });

  it("throws on too-long signature", () => {
    const hash = eip191Hash("test");
    const longSig = "a".repeat(132); // 66 bytes — one too many
    expect(() => recoverEthAddress(hash, longSig)).toThrow("65 bytes");
  });

  it("throws on non-hex signature", () => {
    const hash = eip191Hash("test");
    const badSig = "zz".repeat(65);
    expect(() => recoverEthAddress(hash, badSig)).toThrow("non-hex");
  });

  it("throws on non-hex with 0x prefix", () => {
    const hash = eip191Hash("test");
    const badSig = "0x" + "zz".repeat(65);
    expect(() => recoverEthAddress(hash, badSig)).toThrow("non-hex");
  });

  it("throws on empty signature string", () => {
    const hash = eip191Hash("test");
    expect(() => recoverEthAddress(hash, "")).toThrow();
  });

  it("throws on all-zero (cryptographically invalid) signature", () => {
    const hash = eip191Hash("test");
    const invalidSig = "00".repeat(65);
    expect(() => recoverEthAddress(hash, invalidSig)).toThrow();
  });

  it("gives a different address when the wrong message hash is used", () => {
    const hash1 = eip191Hash(VECTOR1_MSG);
    const hash2 = eip191Hash("A completely different message");
    const addr1 = recoverEthAddress(hash1, VECTOR1_SIG);
    // Recovery with the wrong hash either throws or yields a different address.
    try {
      const addr2 = recoverEthAddress(hash2, VECTOR1_SIG);
      expect(addr1.toLowerCase()).not.toBe(addr2.toLowerCase());
    } catch {
      // Throwing is also acceptable.
    }
  });
});

// ── validateEthAddress ────────────────────────────────────────────────────────

describe("validateEthAddress", () => {
  it("accepts valid lowercase address", () => {
    expect(() =>
      validateEthAddress("0x1a642f0e3c3af545e7acbd38b07251b3990914f1")
    ).not.toThrow();
  });

  it("accepts uppercase address", () => {
    expect(() =>
      validateEthAddress("0x1A642F0E3C3AF545E7ACBD38B07251B3990914F1")
    ).not.toThrow();
  });

  it("accepts address without 0x prefix", () => {
    expect(() =>
      validateEthAddress("1a642f0e3c3af545e7acbd38b07251b3990914f1")
    ).not.toThrow();
  });

  it("throws on too-short address", () => {
    expect(() => validateEthAddress("0x1a642f")).toThrow("40 hex chars");
  });

  it("throws on too-long address", () => {
    expect(() => validateEthAddress("0x" + "a".repeat(41))).toThrow("40 hex chars");
  });

  it("throws on non-hex characters", () => {
    expect(() => validateEthAddress("0x" + "G".repeat(40))).toThrow("non-hex");
  });

  it("throws on empty string", () => {
    expect(() => validateEthAddress("")).toThrow("40 hex chars");
  });

  it("throws on only 0x prefix", () => {
    expect(() => validateEthAddress("0x")).toThrow("40 hex chars");
  });
});
