import { gzipSync, gunzipSync } from "zlib";

const COMPRESSION_VERSION = 1;
const COMPRESSION_TYPE = "gzip";

export type CompressedEnvelope = {
  v: number;
  compression: string;
  payload: string;
};

/**
 * Compresses a plaintext string using gzip and wraps it in a versioned envelope.
 *
 * @param plaintext The string to compress
 * @returns JSON string containing compressed payload
 */
export function compressPayload(plaintext: string): string {
  const compressed = gzipSync(Buffer.from(plaintext, "utf-8"));
  const base64 = compressed.toString("base64");
  const envelope: CompressedEnvelope = {
    v: COMPRESSION_VERSION,
    compression: COMPRESSION_TYPE,
    payload: base64,
  };
  return JSON.stringify(envelope);
}

/**
 * Decompresses a payload envelope back to plaintext.
 *
 * Handles both compressed envelopes and raw plaintext (for backwards compatibility).
 *
 * @param envelope The JSON envelope or raw plaintext
 * @returns Decompressed plaintext string
 */
export function decompressPayload(envelope: string): string {
  const trimmed = envelope.trim();
  if (!trimmed.startsWith("{")) {
    return envelope; // raw plaintext
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (!parsed.compression || !parsed.payload) {
      return envelope; // not a compression envelope
    }

    const compressed = Buffer.from(parsed.payload, "base64");
    const decompressed = gunzipSync(compressed);
    return decompressed.toString("utf-8");
  } catch {
    return envelope; // parse error, treat as raw
  }
}

/**
 * Checks if a payload should be compressed based on size.
 *
 * @param plaintext The string to check
 * @param threshold Minimum size in bytes to trigger compression (default 1KB)
 * @returns true if the payload should be compressed
 */
export function shouldCompress(plaintext: string, threshold = 1024): boolean {
  return Buffer.byteLength(plaintext, "utf-8") >= threshold;
}

/**
 * Compresses payload only if it exceeds the size threshold.
 *
 * @param plaintext The string to potentially compress
 * @param threshold Minimum size in bytes to trigger compression (default 1KB)
 * @returns Compressed envelope if above threshold, otherwise raw plaintext
 */
export function maybeCompressPayload(plaintext: string, threshold = 1024): string {
  return shouldCompress(plaintext, threshold) ? compressPayload(plaintext) : plaintext;
}
