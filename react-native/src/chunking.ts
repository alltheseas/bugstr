/**
 * CHK (Content Hash Key) chunking for large crash reports.
 *
 * Uses @noble/hashes and @noble/ciphers for cross-platform crypto
 * that works in React Native without native modules.
 *
 * **CRITICAL**: Must match hashtree-core crypto exactly:
 * - Key derivation: HKDF-SHA256(content_hash, salt="hashtree-chk", info="encryption-key")
 * - Cipher: AES-256-GCM with 12-byte zero nonce
 * - Format: [ciphertext][16-byte auth tag]
 */
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { gcm } from '@noble/ciphers/aes';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { MAX_CHUNK_SIZE } from './transport';

/** HKDF salt for CHK derivation (must match hashtree-core) */
const CHK_SALT = new TextEncoder().encode('hashtree-chk');

/** HKDF info for key derivation (must match hashtree-core) */
const CHK_INFO = new TextEncoder().encode('encryption-key');

/** Nonce size for AES-GCM (96 bits) */
const NONCE_SIZE = 12;

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
 * Derives encryption key from content hash using HKDF-SHA256.
 * Must match hashtree-core: HKDF(content_hash, salt="hashtree-chk", info="encryption-key")
 */
function deriveKey(contentHash: Uint8Array): Uint8Array {
  return hkdf(sha256, contentHash, CHK_SALT, CHK_INFO, 32);
}

/**
 * Encrypts data using AES-256-GCM with zero nonce (CHK-safe).
 * Returns: [ciphertext][16-byte auth tag]
 *
 * Zero nonce is safe for CHK because same key = same content (convergent encryption).
 */
function chkEncrypt(data: Uint8Array, contentHash: Uint8Array): Uint8Array {
  const key = deriveKey(contentHash);
  const zeroNonce = new Uint8Array(NONCE_SIZE); // All zeros
  const cipher = gcm(key, zeroNonce);
  return cipher.encrypt(data); // GCM appends auth tag
}

/**
 * Decrypts data using AES-256-GCM with zero nonce.
 * Expects: [ciphertext][16-byte auth tag]
 */
function chkDecrypt(data: Uint8Array, contentHash: Uint8Array): Uint8Array {
  const key = deriveKey(contentHash);
  const zeroNonce = new Uint8Array(NONCE_SIZE);
  const cipher = gcm(key, zeroNonce);
  return cipher.decrypt(data);
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
 * Each chunk is encrypted with a key derived from its content hash via HKDF.
 * The root hash is computed by hashing all chunk hashes concatenated.
 *
 * **CRITICAL**: Uses hashtree-core compatible encryption:
 * - HKDF-SHA256 key derivation with salt="hashtree-chk"
 * - AES-256-GCM with zero nonce
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

    // Compute hash of plaintext chunk (used for key derivation)
    const hash = sha256(chunkData);
    chunkHashes.push(hash);

    // Encrypt chunk using HKDF-derived key from hash
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
    const contentHash = hexToBytes(chunk.hash);
    const encrypted = base64ToBytes(chunk.data);
    const plaintext = chkDecrypt(encrypted, contentHash);
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
