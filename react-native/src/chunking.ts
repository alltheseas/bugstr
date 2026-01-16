/**
 * CHK (Content Hash Key) chunking for large crash reports.
 *
 * Uses @noble/hashes and @noble/ciphers for cross-platform crypto
 * that works in React Native without native modules.
 */
import { sha256 } from '@noble/hashes/sha256';
import { cbc } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { MAX_CHUNK_SIZE } from './transport';

export type ChunkData = {
  index: number;
  hash: string;
  encrypted: Uint8Array;
};

export type ChunkingResult = {
  rootHash: string;
  totalSize: number;
  chunks: ChunkData[];
};

/**
 * Encrypts data using AES-256-CBC with the given key.
 * IV is prepended to the ciphertext.
 */
function chkEncrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
  const iv = randomBytes(16);
  const cipher = cbc(key, iv);
  const encrypted = cipher.encrypt(data);
  // Prepend IV to ciphertext
  const result = new Uint8Array(iv.length + encrypted.length);
  result.set(iv);
  result.set(encrypted, iv.length);
  return result;
}

/**
 * Decrypts data using AES-256-CBC with the given key.
 * Expects IV prepended to the ciphertext.
 */
function chkDecrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
  const iv = data.slice(0, 16);
  const ciphertext = data.slice(16);
  const cipher = cbc(key, iv);
  return cipher.decrypt(ciphertext);
}

/**
 * Converts string to UTF-8 bytes.
 */
function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts UTF-8 bytes to string.
 */
function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Base64 encode bytes.
 */
function bytesToBase64(bytes: Uint8Array): string {
  // Works in both browser and React Native
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Base64 decode to bytes.
 */
function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Splits payload into chunks and encrypts each using CHK.
 *
 * Each chunk is encrypted with its own content hash as the key.
 * The root hash is computed by hashing all chunk hashes concatenated.
 *
 * @param payload The string data to chunk and encrypt
 * @param chunkSize Maximum size of each chunk (default 48KB)
 * @returns Chunking result with root hash and encrypted chunks
 */
export function chunkPayload(payload: string, chunkSize = MAX_CHUNK_SIZE): ChunkingResult {
  const data = stringToBytes(payload);
  const chunks: ChunkData[] = [];
  const chunkHashes: Uint8Array[] = [];

  let offset = 0;
  let index = 0;

  while (offset < data.length) {
    const end = Math.min(offset + chunkSize, data.length);
    const chunkData = data.slice(offset, end);

    // Compute hash of plaintext chunk (this becomes the encryption key)
    const hash = sha256(chunkData);
    chunkHashes.push(hash);

    // Encrypt chunk using its hash as the key
    const encrypted = chkEncrypt(chunkData, hash);

    chunks.push({
      index,
      hash: bytesToHex(hash),
      encrypted,
    });

    offset = end;
    index++;
  }

  // Compute root hash from all chunk hashes
  const rootHashInput = new Uint8Array(chunkHashes.reduce((acc, h) => acc + h.length, 0));
  let pos = 0;
  for (const h of chunkHashes) {
    rootHashInput.set(h, pos);
    pos += h.length;
  }
  const rootHash = bytesToHex(sha256(rootHashInput));

  return {
    rootHash,
    totalSize: data.length,
    chunks,
  };
}

/**
 * Reassembles payload from chunks using the root hash for verification.
 *
 * @param rootHash Expected root hash (from manifest)
 * @param chunks Encrypted chunks with their hashes
 * @returns Reassembled original payload string
 * @throws Error if root hash doesn't match or decryption fails
 */
export function reassemblePayload(
  rootHash: string,
  chunks: Array<{ index: number; hash: string; data: string }>
): string {
  // Sort by index to ensure correct order
  const sorted = [...chunks].sort((a, b) => a.index - b.index);

  // Verify root hash
  const chunkHashes = sorted.map((c) => hexToBytes(c.hash));
  const rootHashInput = new Uint8Array(chunkHashes.reduce((acc, h) => acc + h.length, 0));
  let pos = 0;
  for (const h of chunkHashes) {
    rootHashInput.set(h, pos);
    pos += h.length;
  }
  const computedRoot = bytesToHex(sha256(rootHashInput));

  if (computedRoot !== rootHash) {
    throw new Error(`Root hash mismatch: expected ${rootHash}, got ${computedRoot}`);
  }

  // Decrypt and concatenate chunks
  const decrypted: Uint8Array[] = [];
  for (const chunk of sorted) {
    const key = hexToBytes(chunk.hash);
    const encrypted = base64ToBytes(chunk.data);
    const plaintext = chkDecrypt(encrypted, key);
    decrypted.push(plaintext);
  }

  // Concatenate all decrypted chunks
  const totalLength = decrypted.reduce((acc, d) => acc + d.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const d of decrypted) {
    result.set(d, offset);
    offset += d.length;
  }

  return bytesToString(result);
}

/**
 * Estimates the number of chunks needed for a payload size.
 */
export function estimateChunkCount(payloadSize: number, chunkSize = MAX_CHUNK_SIZE): number {
  return Math.ceil(payloadSize / chunkSize);
}

/**
 * Converts chunk data to base64 for transport.
 */
export function encodeChunkData(chunk: ChunkData): string {
  return bytesToBase64(chunk.encrypted);
}
