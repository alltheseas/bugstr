/**
 * CHK (Content Hash Key) chunking for large crash reports.
 *
 * Implements hashtree-style encryption where:
 * - Data is split into fixed-size chunks
 * - Each chunk is encrypted using its content hash as the key
 * - A root hash is computed from all chunk hashes
 * - Only the manifest (with root hash) needs to be encrypted via NIP-17
 * - Chunks are public but opaque without the root hash
 */
import { createHash, createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { MAX_CHUNK_SIZE } from "./transport.js";

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
 * Encrypts data using AES-256-CBC with the given key.
 * IV is prepended to the ciphertext.
 */
function chkEncrypt(data: Buffer, key: Buffer): Buffer {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([iv, encrypted]);
}

/**
 * Decrypts data using AES-256-CBC with the given key.
 * Expects IV prepended to the ciphertext.
 */
function chkDecrypt(data: Buffer, key: Buffer): Buffer {
  const iv = data.subarray(0, 16);
  const ciphertext = data.subarray(16);
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Splits payload into chunks and encrypts each using CHK.
 *
 * Each chunk is encrypted with its own content hash as the key.
 * The root hash is computed by hashing all chunk hashes concatenated.
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

    // Compute hash of plaintext chunk (this becomes the encryption key)
    const hash = sha256(chunkData);
    chunkHashes.push(hash);

    // Encrypt chunk using its hash as the key
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
    const key = Buffer.from(chunk.hash, "hex");
    const plaintext = chkDecrypt(chunk.encrypted, key);
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
