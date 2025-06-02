import { describe, it, expect, beforeEach, vi } from "vitest";
import argon2Browser from "argon2-browser/dist/argon2-bundled.min.js";

import { Kdf } from "../kdf";

/**
 * Tests for the Kdf class
 */
describe("Kdf", () => {
  let kdf: Kdf;

  beforeEach(() => {
    kdf = new Kdf();
  });

  describe("hash salt method", () => {
    it("Produces consistent hash of salt value", async () => {
      // Since the hashSalt method is private, we need to
      // access it via the dynamic property
      // Using a type cast to access private methods in tests
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const hashSalt = (kdf as any).hashSalt;

      const result = await hashSalt("test-salt");

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
      // precomputed expected result
      // https://gchq.github.io/CyberChef/#recipe=SHA2('256',64,160)From_Hex('None')To_Hex('0x%20with%20comma',0)&input=dGVzdC1zYWx0&oeol=VT
      const expected = new Uint8Array([
        0x08, 0x72, 0x80, 0x35, 0x7d, 0xfd, 0xc5, 0xa3, 0x17, 0x7e, 0x17, 0xb7, 0x42, 0x4c, 0x7d,
        0xfb, 0x1e, 0xab, 0x2d, 0x08, 0xba, 0x3b, 0xed, 0xeb, 0x24, 0x3d, 0xc5, 0x1d, 0x5c, 0x18,
        0xdc, 0x88,
      ]);

      expect(result).toEqual(expected);
    });

    it("Null is handled correctly", async () => {
      // Since the hashSalt method is private, we need to
      // access it via the dynamic property
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = await (kdf as any).hashSalt(null);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
      // precomputed expected result
      // https://gchq.github.io/CyberChef/#recipe=SHA2('256',64,160)From_Hex('None')To_Hex('0x%20with%20comma',0)&input=bnVsbA&oeol=VT
      const expected = new Uint8Array([
        0x74, 0x23, 0x4e, 0x98, 0xaf, 0xe7, 0x49, 0x8f, 0xb5, 0xda, 0xf1, 0xf3, 0x6a, 0xc2, 0xd7,
        0x8a, 0xcc, 0x33, 0x94, 0x64, 0xf9, 0x50, 0x70, 0x3b, 0x8c, 0x01, 0x98, 0x92, 0xf9, 0x82,
        0xb9, 0x0b,
      ]);

      expect(result).toEqual(expected);
    });

    it("Special unicode characters are handled correctly", async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const result = await (kdf as any).hashSalt("您好世界😀🌍🔒");

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
      // precomputed expected result
      // https://gchq.github.io/CyberChef/#recipe=SHA2('256',64,160)From_Hex('None')To_Hex('0x%20with%20comma',0)&input=5oKo5aW95LiW55WM8J%2BYgPCfjI3wn5SS&oeol=VT
      const expected = new Uint8Array([
        0xdb, 0x57, 0x04, 0xe6, 0xab, 0x52, 0x47, 0xcd, 0x0b, 0x7b, 0xc2, 0xb5, 0x27, 0x39, 0xd0,
        0xcd, 0x42, 0x8a, 0x85, 0xfd, 0x34, 0xa8, 0xe0, 0xce, 0x04, 0xf7, 0xe2, 0x67, 0x27, 0x5b,
        0x22, 0xe9,
      ]);

      expect(result).toEqual(expected);
    });
  });

  describe("hash method", () => {
    it("Produces hash of key phrase", async () => {
      // Unfortunately the argon2-browser library does not work in the node test environment
      // So we mock the hash method
      const mockedHash = Uint8Array.from([
        75, 89, 197, 210, 253, 175, 243, 188, 80, 214, 122, 170, 61, 6, 164, 114, 201, 197, 97, 118,
        197, 217, 87, 101,
      ]);

      argon2Browser.hash = vi.fn().mockResolvedValue({
        hash: mockedHash,
      });

      const result = await kdf.hash("test-phrase", "test-salt");

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result).toEqual(mockedHash);
    });
  });
});
