import * as edDSA from "@noble/ed25519";

import { Kdf } from "./kdf";

/**
 * Signature class for generating EdDSA signatures.
 */
export class Signature {
  /**
   * Constructs a new Signature instance.
   *
   * @param kdf The KDF instance to use for key derivation. If not provided, a new instance will be created.
   */
  constructor(private readonly kdf = new Kdf()) {}

  /**
   * Creates a new keypair (public and private key) from the given keyphrase and salt.
   * It utilizes the kdf to generate they private key and drive the public key from that.
   *
   * @param keyphrase The keyphrase to be used for key derivation.
   * @param salt The salt to be used for key derivation.
   * @returns A promise that resolves to an object containing the public and private key.
   */
  async createKeyPairFromKeyPhrase(
    keyphrase: string,
    salt: string,
  ): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
    const privateKey = await this.kdf.hash(keyphrase, salt);
    const publicKey = await edDSA.getPublicKeyAsync(privateKey);

    return { publicKey, privateKey };
  }

  /**
   * Signs a message using the provided private key.
   *
   * @param message The message to be signed.
   * @param privateKey The private key to be used for signing.
   * @returns A promise that resolves to the signature.
   */
  async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    return await edDSA.signAsync(message, privateKey);
  }

  /**
   * Verifies a message using the provided public key.
   *
   * This method is not used by the Cloud Clipboard client, however it's included for verification in the unit tests.
   *
   * @param message The message to be verified.
   * @param signature The signature to be verified.
   * @param publicKey The public key to be used for verification.
   * @returns A promise that resolves to a boolean indicating whether the signature is valid.
   */
  async verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
  ): Promise<boolean> {
    return await edDSA.verifyAsync(signature, message, publicKey);
  }
}
