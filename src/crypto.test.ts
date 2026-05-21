/**
 * Tests for EIP-191 hashing and address recovery.
 *
 * The known test vector is identical to the one in the Rust implementation.
 */

import { eip191Hash, recoverEthAddress, validateEthAddress } from "./crypto.js";

const KNOWN_MESSAGE = "Hello World";
const KNOWN_SIG =
  "e9d4cfddf4da3a1b1800c7c178456cf0e1d285417b0204c7cd038ad450fe541464548e164dfb8acc8340cfff0fbed9aa5585f1c78f7241aa5a8434b3e39ec2b61b";
const KNOWN_ADDRESS = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1";

describe("recoverEthAddress", () => {
  it("recovers the known test vector", () => {
    const hash = eip191Hash(KNOWN_MESSAGE);
    const addr = recoverEthAddress(hash, KNOWN_SIG);
    expect(addr.toLowerCase()).toBe(KNOWN_ADDRESS.toLowerCase());
  });

  it("handles 0x prefix on signature", () => {
    const hash = eip191Hash(KNOWN_MESSAGE);
    const addr = recoverEthAddress(hash, "0x" + KNOWN_SIG);
    expect(addr.toLowerCase()).toBe(KNOWN_ADDRESS.toLowerCase());
  });

  it("throws on too-short signature", () => {
    const hash = eip191Hash("test");
    const shortSig = "a".repeat(128); // 64 bytes, missing recovery byte
    expect(() => recoverEthAddress(hash, shortSig)).toThrow("65 bytes");
  });

  it("throws on non-hex signature", () => {
    const hash = eip191Hash("test");
    const badSig = "zz".repeat(65);
    expect(() => recoverEthAddress(hash, badSig)).toThrow("non-hex");
  });

  it("handles v=27 normalization", () => {
    // The known vector already has v=0x1b (27).
    const hash = eip191Hash(KNOWN_MESSAGE);
    const addr = recoverEthAddress(hash, KNOWN_SIG);
    expect(addr.toLowerCase()).toBe(KNOWN_ADDRESS.toLowerCase());
  });
});

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
});

describe("validateEthAddress", () => {
  it("accepts valid checksummed address", () => {
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

  it("throws on non-hex characters", () => {
    expect(() => validateEthAddress("0x" + "G".repeat(40))).toThrow("non-hex");
  });
});
