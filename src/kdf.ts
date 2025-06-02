// We have to ts-ignore the import of argon2-browser because the minified version
// is missing the typescript typing. Vite otherwise complains about the import during the build.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import argon2 from "argon2-browser/dist/argon2-bundled.min.js";

/**
 * Kdf class for hashing keyphrases using Argon2id.
 */
export class Kdf {
  /**
   * Hashes a keyphrase using Argon2id.
   *
   * Configuration as recommended by OWASP (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)
   * m=19456 (19 MiB), t=2, p=1
   * This configuration was chosen to strike a balance between memory usage and performance.
   *
   * @param keyphrase that should be hashed.
   * @param salt that should be used for hashing. For the Cloud Clipboard this is the dataspace name
   * @param hashedSalt an optional pre-hashed salt as a Uint8Array. If provided, this will be used instead of hashing the salt.
   * @returns the hashed keyphrase as a Uint8Array.
   * @throws Error if neither salt nor hashedSalt is provided.
   */
  async hash(keyphrase: string, salt?: string, hashedSalt?: Uint8Array): Promise<Uint8Array> {
    if (salt === undefined && hashedSalt === undefined) {
      throw new Error("Either salt or hashedSalt must be provided.");
    }

    // To ensure that the salt is a Uint8Array with a fixed length we hash the salt before
    const saltHash = hashedSalt ?? (await this.hashSalt(salt!));

    const hashedKeyphrase = await argon2.hash({
      pass: keyphrase,
      salt: saltHash,
      type: argon2.ArgonType.Argon2id,
      mem: 19456, // 19 MiB
      time: 2, // 2 iterations
      parallelism: 1, // 1 thread (JavaScript implementation only supports 1 thread)
      hashLen: 32,
    });

    return hashedKeyphrase.hash;
  }

  /**
   * Hashes a given keyphrase using Argon2id with a low memory and time cost.
   *
   * This method should only be used after a first pass of hashing with the `hash` method
   * has been performed. `fastHash` is intended for use in scenarios where the keyphrase
   * needs to be hashed multiple times like when a file needs to be encrypted or decrypted
   * in the wrenching process.
   *
   * @param key that should be hashed.
   * @param salt that should be used for hashing. For the Cloud Clipboard this is the dataspace name
   * @param saltHash an optional pre-hashed salt as a Uint8Array. If provided, this will be used instead of hashing the salt.
   * @returns the hashed keyphrase as a Uint8Array.
   * @throws Error if neither salt nor saltHash is provided.
   * @remarks This method is not suitable for initial keyphrase hashing due to its low memory and time cost.
   */
  async fastHash(key: Uint8Array, salt?: string, hashedSalt?: Uint8Array): Promise<Uint8Array> {
    if (salt === undefined && hashedSalt === undefined) {
      throw new Error("Either salt or saltHash must be provided.");
    }

    // To ensure that the salt is a Uint8Array with a fixed length we hash the salt before
    const saltHash = hashedSalt ?? (await this.hashSalt(salt!));

    const hashedKeyphrase = await argon2.hash({
      pass: key,
      salt: saltHash,
      type: argon2.ArgonType.Argon2id,
      mem: 10, // 64 KiB
      time: 1, // 1 iteration
      parallelism: 1, // 1 thread (JavaScript implementation only supports 1 thread)
      hashLen: 32,
    });

    return hashedKeyphrase.hash;
  }

  /**
   * Hashes a salt string using SHA-256. This is used to ensure that the salt is
   * a Uint8Array with a fixed length.
   *
   * **Important**: This method should **not** be used for cryptographic or security-critical
   * purposes, this is simply a solution to ensure that the salt is a Uint8Array with a fixed length.
   *
   * For proper cryptographic hashing use {@link Kdf.hash} instead.
   *
   * @param salt the salt string to be hashed.
   * @returns the hashed salt as a Uint8Array.
   */
  async hashSalt(salt: string): Promise<Uint8Array> {
    const saltBuffer = new TextEncoder().encode(salt);
    const saltHash = await crypto.subtle.digest("SHA-256", saltBuffer);

    return new Uint8Array(saltHash);
  }
}
