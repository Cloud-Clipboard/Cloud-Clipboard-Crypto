import base64js from "base64-js";

import { Kdf } from "./kdf";

export type Metadata = {
  contentKeyBase64: string;
  [key: string]: unknown;
};

/**
 * Symmetric Encryption class to encrypt the metadata and the actual
 * file with AES-256 GCM
 */
export class SymmetricEncryption {
  /**
   * Constructs a new SymmetricEncryption instance.
   * @param webcrypto - The webcrypto implementation to use (default is the global crypto).
   * @param kdf - The key derivation function to use (default is a new instance of Kdf).
   */
  constructor(
    private readonly webcrypto: typeof crypto = crypto,
    private readonly kdf: Kdf = new Kdf(),
  ) {}

  private static readonly AES_ALGORITHM = "AES-GCM";

  /**
   * Encrypts the metadata with the keyphrase and salt.
   * The keyphrase is ratcheted the amount of times as the file number
   * and used as the key for the metadata. The IV is prepended to the encrypted value.
   *
   * @param keyphrase - The keyphrase used for encryption.
   * @param salt - The salt used for the kdf.
   * @param fileNumber - The number of times to ratchet the keyphrase.
   * @param metadata - The metadata to encrypt.
   * @returns A promise that resolves to the encrypted metadata as an Uint8Array.
   * @throws Error if the file number is smaller than 1.
   */
  async encryptMetadata(
    keyphrase: string,
    salt: string,
    fileNumber: number,
    metadata: Metadata,
  ): Promise<Uint8Array> {
    const ratchetedKey = await this.ratchetKey(keyphrase, salt, fileNumber);

    // Check if the metadata is a valid object
    if (metadata && typeof metadata !== "object") {
      throw new Error("Metadata must be an object");
    }

    // We stringify the metadata
    const metadataString = JSON.stringify(metadata);
    // Get the metadata as a buffer
    const metadataBuffer = new TextEncoder().encode(metadataString);
    // We encrypt the metadata with the ratcheted key
    // @ts-ignore Somehow the Uint8Array is not considered a BufferSource in typescript
    const encryptedMetadata = await this.encrypt(ratchetedKey, metadataBuffer);

    // We return the encrypted metadata
    return encryptedMetadata;
  }

  /**
   * Decrypts the metadata with the keyphrase and salt according to the encryption method.
   * The keyphrase is ratcheted the amount of times as the file number
   * and used as the key for the metadata. The IV has to be prepended to the encrypted value.
   *
   * @param keyphrase - The keyphrase used for decryption.
   * @param salt - The salt used for the kdf.
   * @param fileNumber - The number of times to ratchet the keyphrase.
   * @param encryptedMetadata - The encrypted metadata to decrypt.
   * @returns A promise that resolves to the decrypted metadata as an object.
   * @throws Error if the file number is smaller than 1 or if the metadata is not an object.
   * @throws Error if the content key is not found in the decrypted metadata.
   */
  async decryptMetadata(
    keyphrase: string,
    salt: string,
    fileNumber: number,
    encryptedMetadata: Uint8Array,
  ): Promise<Metadata> {
    const ratchetedKey = await this.ratchetKey(keyphrase, salt, fileNumber);

    // We decrypt the metadata with the ratcheted key
    // @ts-ignore Somehow the Uint8Array is not a BufferSource
    const decryptedMetadata = await this.decrypt(ratchetedKey, encryptedMetadata);
    // We parse the metadata
    const metadataString = new TextDecoder().decode(decryptedMetadata);
    const metadata = JSON.parse(metadataString);

    // We check if the metadata is a valid object
    if (metadata && typeof metadata !== "object") {
      throw new Error("Metadata must be an object");
    }
    // We check if the content key exists in the metadata
    if (!metadata.contentKeyBase64) {
      throw new Error("content key not found in metadata");
    }

    // We return the decrypted metadata
    return metadata;
  }

  /**
   * Creates a new content key for encrypting a file.
   * The content key is a random 32 byte key.
   * @returns A Uint8Array representing the content key.
   */
  createContentKey(): Uint8Array {
    return this.webcrypto.getRandomValues(new Uint8Array(32));
  }

  /**
   * Creates a new content key for encrypting a file and base64 encodes it.
   * See {@link createContentKey} for more information.
   * @returns A base64 encoded string representing the content key.
   */
  createContentKeyBase64(): string {
    const contentKey = this.createContentKey();

    // We base64 encode the content key
    const contentKeyBase64 = base64js.fromByteArray(contentKey);

    return contentKeyBase64;
  }

  /**
   * Encrypts a file with the content key from the metadata. The IV is prepended to the encrypted value.
   * @param metadata - The metadata containing the content key.
   * @param file - The file to encrypt.
   * @returns A promise that resolves to the encrypted file as an Uint8Array.
   */
  async encryptFile(metadata: Metadata, file: BufferSource): Promise<Uint8Array> {
    const contentKey = base64js.toByteArray(metadata.contentKeyBase64);

    // We encrypt the file with the content key
    // @ts-ignore Somehow the Uint8Array is not a BufferSource
    const encryptedFile = await this.encrypt(contentKey, file);

    return encryptedFile;
  }

  /**
   * Decrypts a file with the content key from the metadata.
   * @param metadata - The metadata containing the content key.
   * @param encryptedFile - The encrypted file to decrypt with the IV prepended to the encrypted value.
   * @returns A promise that resolves to the decrypted file as an Uint8Array.
   */
  async decryptFile(metadata: Metadata, encryptedFile: Uint8Array): Promise<Uint8Array> {
    const contentKey = base64js.toByteArray(metadata.contentKeyBase64);

    // We decrypt the file with the content key
    // @ts-ignore Somehow the Uint8Array is not a BufferSource
    const decryptedFile = await this.decrypt(contentKey, encryptedFile);

    return decryptedFile;
  }

  /**
   * Encrypts a value with the given key using AES-GCM.
   * The IV is prepended to the encrypted value.
   *
   * @param key - The key used for encryption.
   * @param value - The value to encrypt.
   * @returns A promise that resolves to the encrypted value as an Uint8Array.
   */
  private async encrypt(key: BufferSource, value: BufferSource): Promise<Uint8Array> {
    // We create a new iv for each encryption
    const iv = this.webcrypto.getRandomValues(new Uint8Array(16));
    const aesKey = await this.webcrypto.subtle.importKey(
      "raw",
      key,
      {
        name: SymmetricEncryption.AES_ALGORITHM,
        length: 256,
      },
      false,
      ["encrypt"],
    );

    const encryptedValue = await this.webcrypto.subtle.encrypt(
      {
        name: SymmetricEncryption.AES_ALGORITHM,
        iv,
        length: 256,
      },
      aesKey,
      value,
    );

    // We prepend the iv to the encrypted value
    const encryptedValueWithIv = new Uint8Array(iv.byteLength + encryptedValue.byteLength);

    encryptedValueWithIv.set(iv);
    encryptedValueWithIv.set(new Uint8Array(encryptedValue), iv.byteLength);

    return encryptedValueWithIv;
  }

  /**
   * Decrypts a value with the given key using AES-GCM.
   * The IV has to be prepended to the encrypted value.
   *
   * @param key - The key used for decryption.
   * @param value - The value to decrypt.
   * @returns A promise that resolves to the decrypted value as an Uint8Array.
   */
  private async decrypt(key: BufferSource, value: ArrayBuffer): Promise<Uint8Array> {
    // We need to extract the iv from the encrypted value
    const iv = new Uint8Array(value.slice(0, 16));
    const encryptedValue = new Uint8Array(value.slice(16));

    const aesKey = await this.webcrypto.subtle.importKey(
      "raw",
      key,
      {
        name: SymmetricEncryption.AES_ALGORITHM,
        length: 256,
      },
      false,
      ["decrypt"],
    );

    const decryptedValue = await this.webcrypto.subtle.decrypt(
      {
        name: SymmetricEncryption.AES_ALGORITHM,
        iv,
        length: 256,
      },
      aesKey,
      encryptedValue,
    );

    return new Uint8Array(decryptedValue);
  }

  /**
   * Cache for ratcheted keys to avoid recalculating them multiple times.
   * The cache is initialized with the key and salt used for ratcheting.
   * This cache is static to ensure that it is shared across all instances of the SymmetricEncryption class.
   * It should be cleared when the user logs out or when the keyphrase changes.
   */
  private static ratchetCache?: {
    key: string;
    salt: string;
    hashes: Map<number, Uint8Array>;
  };

  /**
   * Ratchetes the key the amount of times as defined in the ratchetCount.
   *
   * @param key - The key to ratchet.
   * @param salt - The salt to use for the ratcheting/kdf.
   * @param ratchetCount - The amount of times to ratchet the key. Has to be larger than 0.
   * @returns A promise that resolves to the ratcheted key as an Uint8Array.
   * @throws Error if the ratchetCount is smaller than 1.
   */
  private async ratchetKey(key: string, salt: string, ratchetCount: number): Promise<Uint8Array> {
    // We need to ensure that ratchetCount is larger than 0
    if (ratchetCount <= 0) {
      throw new Error("Ratchet count must be larger than 0");
    }

    // We check if the cache is initialized for the ratcheting
    this.initalizeRatchetCache(key, salt);

    // We check if the ratcheted key is already cached
    if (SymmetricEncryption.ratchetCache?.hashes.get(ratchetCount)) {
      return SymmetricEncryption.ratchetCache!.hashes.get(ratchetCount)!;
    }

    // We ratchet the key the amount of times as the ratchet count
    // and use that as the key for the metadata.
    // For the first ratchet we use the regular/strong kdf to hash the key and salt.
    // We precalculate the salt hash to avoid hashing it multiple times.
    const saltHash = await this.kdf.hashSalt(salt);
    // We use the cached ratcheted key if it exists, otherwise we hash the key with the kdf
    let ratchetedKey =
      SymmetricEncryption.ratchetCache?.hashes.get(1) ??
      (await this.kdf.hash(key, undefined, saltHash));

    // We cache the ratcheted key
    SymmetricEncryption.ratchetCache!.hashes.set(1, ratchetedKey);

    for (let i = 2; i <= ratchetCount; i++) {
      // We ratchet the key by hashing it with the kdf again
      // If we have already cached the ratcheted key, we use that instead
      ratchetedKey =
        SymmetricEncryption.ratchetCache?.hashes.get(i) ??
        (await this.kdf.fastHash(ratchetedKey, undefined, saltHash));

      // We cache the ratcheted key again
      SymmetricEncryption.ratchetCache!.hashes.set(i, ratchetedKey);
    }

    return ratchetedKey;
  }

  /**
   * Initializes the ratchet cache with the provided key and salt.
   * If the cache is already initialized with the same key and salt,
   * this method does nothing.
   * @param key The key to initialize the cache with.
   * @param salt The salt to initialize the cache with.
   */
  private initalizeRatchetCache(key: string, salt: string): void {
    if (
      SymmetricEncryption.ratchetCache?.key !== key ||
      SymmetricEncryption.ratchetCache?.salt !== salt
    ) {
      SymmetricEncryption.ratchetCache = {
        key,
        salt,
        hashes: new Map<number, Uint8Array>(),
      };
    }
  }

  /**
   * Clears any cached ratcheted keys.
   * This should be used when a user logs out or when the keyphrase changes.
   */
  static clearRatchetCache(): void {
    SymmetricEncryption.ratchetCache = undefined;
  }
}
