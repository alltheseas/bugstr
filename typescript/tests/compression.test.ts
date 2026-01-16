import { describe, it, expect } from "vitest";
import {
  compressPayload,
  decompressPayload,
  shouldCompress,
  maybeCompressPayload,
} from "../src/compression";

describe("compression", () => {
  describe("compressPayload", () => {
    it("produces valid envelope", () => {
      const plaintext = "Hello, World!";
      const envelope = compressPayload(plaintext);
      const parsed = JSON.parse(envelope);

      expect(parsed.v).toBe(1);
      expect(parsed.compression).toBe("gzip");
      expect(parsed.payload).toBeDefined();
    });
  });

  describe("decompressPayload", () => {
    it("round-trips correctly", () => {
      const plaintext = `Test crash report with stack trace
Error: NullPointerException
    at MyClass.method (MyClass.ts:42)`;

      const compressed = compressPayload(plaintext);
      const decompressed = decompressPayload(compressed);

      expect(decompressed).toBe(plaintext);
    });

    it("handles raw plaintext", () => {
      const plaintext = "This is not compressed";
      const result = decompressPayload(plaintext);

      expect(result).toBe(plaintext);
    });

    it("handles non-compression JSON", () => {
      const json = '{"message": "error", "code": 500}';
      const result = decompressPayload(json);

      expect(result).toBe(json);
    });
  });

  describe("shouldCompress", () => {
    it("returns false for small payloads", () => {
      expect(shouldCompress("tiny", 1024)).toBe(false);
    });

    it("returns true for large payloads", () => {
      const large = "x".repeat(2000);
      expect(shouldCompress(large, 1024)).toBe(true);
    });
  });

  describe("maybeCompressPayload", () => {
    it("skips small payloads", () => {
      const small = "tiny";
      const result = maybeCompressPayload(small, 1024);

      expect(result).toBe(small);
    });

    it("compresses large payloads", () => {
      const large = "x".repeat(2000);
      const result = maybeCompressPayload(large, 1024);
      const parsed = JSON.parse(result);

      expect(parsed.compression).toBe("gzip");
      expect(decompressPayload(result)).toBe(large);
    });
  });

  describe("compression ratio", () => {
    it("achieves significant size reduction for text", () => {
      const stackTrace = Array(100)
        .fill(null)
        .map((_, i) => `Error: RuntimeException ${i}\n    at Class${i}.method (Class${i}.ts:${i})`)
        .join("\n");

      const compressed = compressPayload(stackTrace);
      const originalSize = Buffer.byteLength(stackTrace, "utf-8");
      const compressedSize = Buffer.byteLength(compressed, "utf-8");

      // Text should compress to less than 50% of original
      expect(compressedSize).toBeLessThan(originalSize / 2);
    });
  });
});
