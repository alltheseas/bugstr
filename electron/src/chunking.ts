/**
 * CHK (Content Hash Key) chunking for large crash reports.
 *
 * Implements hashtree-core compatible encryption where:
 * - Data is split into fixed-size chunks
 * - Each chunk's content hash is derived via HKDF to get the encryption key
 * - AES-256-GCM with zero nonce encrypts each chunk
 * - A root hash is computed from all chunk hashes
 * - Only the manifest (with root hash) needs to be encrypted via NIP-17
 * - Chunks are public but opaque without the root hash
 *
 * **CRITICAL**: Must match hashtree-core crypto exactly:
 * - Key derivation: HKDF-SHA256(content_hash, salt="hashtree-chk", info="encryption-key")
 * - Cipher: AES-256-GCM with 12-byte zero nonce
 * - Format: [ciphertext][16-byte auth tag]
 */
import { createHash, createCipheriv, createDecipheriv, hkdfSync } from "crypto";
import { MAX_CHUNK_SIZE } from "./transport.js";

/** HKDF salt for CHK derivation (must match hashtree-core) */
const CHK_SALT = Buffer.from("hashtree-chk");

/** HKDF info for key derivation (must match hashtree-core) */
const CHK_INFO = Buffer.from("encryption-key");

/** Nonce size for AES-GCM (96 bits) */
const NONCE_SIZE = 12;

/** Auth tag size for AES-GCM (128 bits) */
const TAG_SIZE = 16;

export type ChunkData = {
  index: number;
  hash: string;
  encrypted: Buffer;
};

export type ChunkingResult = {
  rootHash: string;
  totalSize: number;
  chunks: ChunkData[];
};

/**
 * Computes SHA-256 hash of data.
 */
function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

/**
 * Derives encryption key from content hash using HKDF-SHA256.
 * Must match hashtree-core: HKDF(content_hash, salt="hashtree-chk", info="encryption-key")
 */
function deriveKey(contentHash: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", contentHash, CHK_SALT, CHK_INFO, 32));
}

/**
 * Encrypts data using AES-256-GCM with zero nonce (CHK-safe).
 * Returns: [ciphertext][16-byte auth tag]
 *
 * Zero nonce is safe for CHK because same key = same content (convergent encryption).
 */
function chkEncrypt(data: Buffer, contentHash: Buffer): Buffer {
  const key = deriveKey(contentHash);
  const zeroNonce = Buffer.alloc(NONCE_SIZE); // All zeros

  const cipher = createCipheriv("aes-256-gcm", key, zeroNonce);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // GCM format: [ciphertext][auth tag]
  return Buffer.concat([ciphertext, authTag]);
}

/**
 * Decrypts data using AES-256-GCM with zero nonce.
 * Expects: [ciphertext][16-byte auth tag]
 */
function chkDecrypt(data: Buffer, contentHash: Buffer): Buffer {
  const key = deriveKey(contentHash);
  const zeroNonce = Buffer.alloc(NONCE_SIZE);

  const ciphertext = data.subarray(0, data.length - TAG_SIZE);
  const authTag = data.subarray(data.length - TAG_SIZE);

  const decipher = createDecipheriv("aes-256-gcm", key, zeroNonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Splits payload into chunks and encrypts each using CHK.
 *
 * Each chunk is encrypted with a key derived from its content hash via HKDF.
 * The root hash is computed by hashing all chunk hashes concatenated.
 *
 * **CRITICAL**: Uses hashtree-core compatible encryption:
 * - HKDF-SHA256 key derivation with salt="hashtree-chk"
 * - AES-256-GCM with zero nonce
 *
 * @param payload The data to chunk and encrypt
 * @param chunkSize Maximum size of each chunk (default 48KB)
 * @returns Chunking result with root hash and encrypted chunks
 */
export function chunkPayload(
  payload: Buffer,
  chunkSize = MAX_CHUNK_SIZE
): ChunkingResult {
  const chunks: ChunkData[] = [];
  const chunkHashes: Buffer[] = [];

  let offset = 0;
  let index = 0;

  while (offset < payload.length) {
    const end = Math.min(offset + chunkSize, payload.length);
    const chunkData = payload.subarray(offset, end);

    // Compute hash of plaintext chunk (used for key derivation)
    const hash = sha256(chunkData);
    chunkHashes.push(hash);

    // Encrypt chunk using HKDF-derived key from hash
    const encrypted = chkEncrypt(chunkData, hash);

    chunks.push({
      index,
      hash: hash.toString("hex"),
      encrypted,
    });

    offset = end;
    index++;
  }

  // Compute root hash from all chunk hashes
  const rootHashInput = Buffer.concat(chunkHashes);
  const rootHash = sha256(rootHashInput).toString("hex");

  return {
    rootHash,
    totalSize: payload.length,
    chunks,
  };
}

/**
 * Reassembles payload from chunks using the root hash for verification.
 *
 * @param rootHash Expected root hash (from manifest)
 * @param chunks Encrypted chunks with their hashes
 * @returns Reassembled original payload
 * @throws Error if root hash doesn't match or decryption fails
 */
export function reassemblePayload(
  rootHash: string,
  chunks: ChunkData[]
): Buffer {
  // Sort by index to ensure correct order
  const sorted = [...chunks].sort((a, b) => a.index - b.index);

  // Verify root hash
  const chunkHashes = sorted.map((c) => Buffer.from(c.hash, "hex"));
  const computedRoot = sha256(Buffer.concat(chunkHashes)).toString("hex");

  if (computedRoot !== rootHash) {
    throw new Error(
      `Root hash mismatch: expected ${rootHash}, got ${computedRoot}`
    );
  }

  // Decrypt and concatenate chunks
  const decrypted: Buffer[] = [];
  for (const chunk of sorted) {
    const contentHash = Buffer.from(chunk.hash, "hex");
    const plaintext = chkDecrypt(chunk.encrypted, contentHash);
    decrypted.push(plaintext);
  }

  return Buffer.concat(decrypted);
}

/**
 * Estimates the number of chunks needed for a payload size.
 */
export function estimateChunkCount(
  payloadSize: number,
  chunkSize = MAX_CHUNK_SIZE
): number {
  return Math.ceil(payloadSize / chunkSize);
}
