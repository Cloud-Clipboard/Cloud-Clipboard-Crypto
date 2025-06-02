import { describe, it, expect, beforeEach, vi, MockInstance } from "vitest";

import { SymmetricEncryption } from "../symmetric-encryption";
import type { Kdf as KdfType } from "../kdf"; // only for typing – we will fake it

const KEYPHRASE = "test123";
const SALT = "my-clipboard";
const FILE_NUMBER = 2;

// 32-byte key returned by Kdf.hash(KEYPHRASE, SALT)
const PRECOMPUTED_DERIVED_KEY_FIRST_PASS = Uint8Array.from([
  31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7,
  6, 5, 4, 3, 2, 1, 0,
]);
// 32-byte key returned by Kdf.hash(KEYPHRASE, SALT)
const PRECOMPUTED_DERIVED_KEY_NEXT_PASS = Uint8Array.from([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
  27, 28, 29, 30, 31,
]);

// 32-byte precomputed hashed salt
const PRECOMPUTED_HASHED_SALT = Uint8Array.from([
  28, 29, 30, 31, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, 26, 27,
]);

// The metadata object that was encrypted to produce PRECOMPUTED_ENCRYPTED_METADATA
const PLAINTEXT_METADATA = {
  contentKeyBase64: "MzItYnl0ZS1jb250ZW50LWtleS1iYXNlNjQtZW5jb2Q=",
  fileName: "test.txt",
};

// 16-byte deterministic IV you used while creating reference ciphertexts
const PREDEFINED_IV = Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

// Encrypted (IV + ciphertext + Tag) metadata bytes
const PRECOMPUTED_ENCRYPTED_METADATA = Uint8Array.from([
  ...PREDEFINED_IV,
  ...[
    28, 78, 195, 25, 87, 144, 47, 70, 233, 180, 190, 80, 23, 197, 95, 214, 98, 135, 73, 155, 69,
    192, 169, 10, 48, 103, 35, 185, 190, 163, 159, 251, 2, 29, 187, 193, 77, 26, 135, 251, 210, 101,
    97, 34, 141, 83, 182, 67, 62, 41, 18, 20, 224, 90, 42, 208, 212, 231, 241, 46, 139, 73, 112,
    215, 46, 201, 87, 134, 166, 13, 235, 250, 113, 48, 205, 83, 80, 69, 119, 192, 190, 240, 114,
    130, 154, 69, 59, 160, 251, 180, 169, 105, 180, 222, 161, 175, 41, 125, 1, 190, 175, 42, 37,
    236, 36,
  ],
]);

// Plaintext file contents (arbitrary)
const SAMPLE_FILE_PLAINTEXT = new TextEncoder().encode("test-content");

// Encrypted (IV + ciphertext + tag) file bytes
const PRECOMPUTED_ENCRYPTED_FILE = Uint8Array.from([
  ...PREDEFINED_IV,
  ...[
    37, 208, 104, 227, 254, 247, 17, 96, 74, 244, 40, 42, 70, 246, 169, 40, 221, 61, 252, 62, 179,
    98, 105, 129, 238, 248, 76, 147,
  ],
]);

/**
 * Fake Kdf class that always returns the same derived key.
 * We have to mock the KDF here unfortunately because the KDF is not
 * working in the test environment.
 */
class FakeKdf implements Partial<KdfType> {
  hash = vi.fn(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async (_key: string, _salt?: string, _hashedSalt?: Uint8Array) =>
      PRECOMPUTED_DERIVED_KEY_FIRST_PASS,
  );
  fastHash = vi.fn(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async (_key: Uint8Array, _salt?: string, _hashedSalt?: Uint8Array) =>
      PRECOMPUTED_DERIVED_KEY_NEXT_PASS,
  );
  hashSalt = vi.fn(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async (_salt: string) => PRECOMPUTED_HASHED_SALT,
  );
}

describe("SymmetricEncryption", () => {
  let cryptoStub: MockInstance<<T extends ArrayBufferView | null>(array: T) => T>;
  let symmetricEncryption: SymmetricEncryption;
  let fakeKdf: FakeKdf;

  beforeEach(() => {
    cryptoStub?.mockRestore();

    // We have to stub/mock the random function so we can make the
    // test deterministic. The IV is always the same for the tests.
    cryptoStub = vi
      .spyOn(globalThis.crypto, "getRandomValues")
      // @ts-expect-error – stub the crypto random API
      .mockImplementation((arr: Uint8Array) => {
        arr.set(PREDEFINED_IV);

        return arr;
      });

    // We have to stub the KDF because it is not working in the test environment.
    fakeKdf = new FakeKdf();

    symmetricEncryption = new SymmetricEncryption(crypto, fakeKdf);

    // Clear the wretch cache to ensure that the tests are deterministic
    SymmetricEncryption.clearWretchCache();
  });

  it("encrypts metadata deterministically", async () => {
    const encrypted = await symmetricEncryption.encryptMetadata(
      KEYPHRASE,
      SALT,
      FILE_NUMBER,
      PLAINTEXT_METADATA,
    );

    // verify that the first pass of the KDF was used
    expect(fakeKdf.hash).toHaveBeenCalledWith(KEYPHRASE, undefined, PRECOMPUTED_HASHED_SALT);
    // verify that the second pass of the KDF was used
    expect(fakeKdf.fastHash).toHaveBeenCalledWith(
      PRECOMPUTED_DERIVED_KEY_FIRST_PASS,
      undefined,
      PRECOMPUTED_HASHED_SALT,
    );

    expect(encrypted).toEqual(PRECOMPUTED_ENCRYPTED_METADATA);
  });

  it("decrypts metadata correctly", async () => {
    const decrypted = await symmetricEncryption.decryptMetadata(
      KEYPHRASE,
      SALT,
      FILE_NUMBER,
      PRECOMPUTED_ENCRYPTED_METADATA,
    );

    // verify that the first pass of the KDF was used
    expect(fakeKdf.hash).toHaveBeenCalledWith(KEYPHRASE, undefined, PRECOMPUTED_HASHED_SALT);
    // verify that the second pass of the KDF was used
    expect(fakeKdf.fastHash).toHaveBeenCalledWith(
      PRECOMPUTED_DERIVED_KEY_FIRST_PASS,
      undefined,
      PRECOMPUTED_HASHED_SALT,
    );

    expect(decrypted).toEqual(PLAINTEXT_METADATA);
  });

  it("ensure wretched key is cached correctly", async () => {
    await symmetricEncryption.decryptMetadata(
      KEYPHRASE,
      SALT,
      FILE_NUMBER,
      PRECOMPUTED_ENCRYPTED_METADATA,
    );

    const decrypted = await symmetricEncryption.decryptMetadata(
      KEYPHRASE,
      SALT,
      FILE_NUMBER,
      PRECOMPUTED_ENCRYPTED_METADATA,
    );

    // verify that the first pass of the KDF was used only once and otherwise cached
    expect(fakeKdf.hash).toBeCalledTimes(1);
    // verify that the second pass of the KDF was used only once and otherwise cached
    expect(fakeKdf.fastHash).toBeCalledTimes(1);

    expect(decrypted).toEqual(PLAINTEXT_METADATA);
  });

  it("encrypts a file deterministically", async () => {
    const encryptedFile = await symmetricEncryption.encryptFile(
      PLAINTEXT_METADATA,
      SAMPLE_FILE_PLAINTEXT,
    );

    expect(encryptedFile).toEqual(PRECOMPUTED_ENCRYPTED_FILE);
  });

  it("decrypts a file correctly (round-trip with reference vector)", async () => {
    const decryptedFile = await symmetricEncryption.decryptFile(
      PLAINTEXT_METADATA,
      PRECOMPUTED_ENCRYPTED_FILE,
    );

    expect(decryptedFile).toEqual(new Uint8Array(SAMPLE_FILE_PLAINTEXT));
  });

  it("generates a 32-byte content key", () => {
    const key = symmetricEncryption.createContentKey();

    expect(key).instanceOf(Uint8Array);
    expect(key.byteLength).toBe(32);
  });

  it("throws when wretchCount ≤ 0", async () => {
    await expect(
      symmetricEncryption.encryptMetadata(KEYPHRASE, SALT, 0, PLAINTEXT_METADATA),
    ).rejects.toThrow(/wretch/i);
  });
});
