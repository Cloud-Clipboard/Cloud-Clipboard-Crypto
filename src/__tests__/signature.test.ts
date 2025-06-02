/* eslint-disable prettier/prettier */
import { describe, it, expect, beforeEach, vi, beforeAll } from "vitest";
import * as edDSA from '@noble/ed25519';

import { Signature } from "../signature";
import { Kdf } from "../kdf";

/**
 * Tests for the Signature class
 */
describe("Signature", () => {
  let signature: Signature;
  let mockKdf: Kdf;

  // Test parameters and precomputed expected values
  const testKeyphrase = "test-phrase";
  const testSalt = "test-salt";
  const testMessage = new TextEncoder().encode('test');

  const expectedPrivateKey = new Uint8Array([161, 129, 108, 86, 198, 15, 190, 54, 108, 66, 2, 37, 17, 240, 183, 114, 65, 42, 23, 57, 228, 98, 81, 30, 81, 163, 183, 83, 214, 160, 142, 79]);
  const expectedPublicKey = new Uint8Array([174, 102, 30, 113, 133, 115, 68, 135, 85, 210, 88, 223, 107, 240, 148, 114, 161, 64, 25, 116, 2, 110, 46, 148, 94, 35, 0, 247, 124, 240, 27, 11]);
  const expectedSignature = new Uint8Array([245, 103, 11, 250, 108, 74, 255, 119, 89, 172, 19, 67, 179, 74, 210, 164, 89, 168, 160, 76, 255, 145, 15, 100, 8, 229, 200, 107, 83, 143, 123, 86, 25, 192, 55, 197, 56, 68, 124, 36, 202, 230, 209, 143, 224, 170, 98, 18, 234, 166, 22, 112, 31, 74, 195, 244, 237, 172, 96, 133, 116, 12, 36, 3]);

  beforeAll(() => {
    // We need to update the sha512Async method to make it work in the node enviroment
    // @typescript-eslint/no-unused-expressions
    edDSA.etc.sha512Async = async (...messages) => {
      const m = edDSA.etc.concatBytes(...messages);

      return new Uint8Array(await crypto.subtle.digest('SHA-512', m));
    };
  })

  beforeEach(() => {
    // Only mock the KDF, but use real edDSA functions
    mockKdf = {
      hash: vi.fn().mockResolvedValue(expectedPrivateKey)
    } as unknown as Kdf;

    // Create signature instance with mocked KDF
    signature = new Signature(mockKdf);
  });

  it('should create a valid keypair', async () => {
    const result = await signature.createKeyPairFromKeyPhrase(testKeyphrase, testSalt);

    // Check that KDF was called correctly
    expect(mockKdf.hash).toHaveBeenCalledWith(testKeyphrase, testSalt);

    // Check that keypair has expected structure
    expect(result.privateKey).toBeInstanceOf(Uint8Array);
    expect(result.privateKey.length).toBe(32); // Ed25519 private key is 32 bytes
    expect(result.privateKey).toEqual(expectedPrivateKey);
    expect(result.publicKey).toBeInstanceOf(Uint8Array);
    expect(result.publicKey.length).toBe(32); // Ed25519 public key is 32 bytes
    expect(result.publicKey).toEqual(expectedPublicKey);
  });

  it('should sign message correctly', async () => {
    const signatureValue = await signature.sign(testMessage, expectedPrivateKey);

    expect(signatureValue).toBeInstanceOf(Uint8Array);
    expect(signatureValue.length).toBe(64); // Ed25519 signature is 64 bytes
    expect(signatureValue).toEqual(expectedSignature);
  });

  it('should verify signed message', async () => {
    const valid = await signature.verify(testMessage, expectedSignature, expectedPublicKey);

    expect(valid).toBe(true);
  });

  it('should fail verification with tampered message', async () => {
    const originalMessage = new Uint8Array([1, 2, 3, 4, 5]);
    const tamperedMessage = new Uint8Array([1, 2, 3, 4, 6]); // Changed last byte

    // Generate a real signature for the original message
    const signatureValue = await signature.sign(originalMessage, expectedPrivateKey);

    // Verify the signature with the tampered message
    const isValid = await signature.verify(tamperedMessage, signatureValue, expectedPublicKey);

    expect(isValid).toBe(false);
  });

  it('should fail verification with incorrect public key', async () => {
    const testMessage = new Uint8Array([1, 2, 3, 4, 5]);

    // Generate a different key pair
    const differentPrivateKey = edDSA.utils.randomPrivateKey();
    const differentPublicKey = await edDSA.getPublicKeyAsync(differentPrivateKey);

    // Generate a signature with the original private key
    const signatureValue = await signature.sign(testMessage, expectedPrivateKey);

    // Try to verify with a different public key
    const isValid = await signature.verify(testMessage, signatureValue, differentPublicKey);

    expect(isValid).toBe(false);
  });
});
