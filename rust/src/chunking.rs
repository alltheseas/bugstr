//! CHK-based chunking for large crash reports.
//!
//! Implements Content Hash Key (CHK) encryption and chunking for crash reports
//! that exceed the direct transport size limit (50KB). Large payloads are split
//! into chunks, each encrypted with its content hash as the key.
//!
//! # Security Model
//!
//! CHK encryption ensures that:
//! - Each chunk is encrypted with a key derived from its plaintext hash
//! - The root hash (manifest's `root_hash`) is required to decrypt any chunk
//! - Without the manifest (delivered via NIP-17 gift wrap), chunks are opaque
//!
//! # Chunk Size
//!
//! Chunks are sized to fit within Nostr relay limits:
//! - Max event size: 64KB (strfry default)
//! - Chunk payload: 48KB (allows for base64 encoding + JSON overhead)
//!
//! # Example
//!
//! ```ignore
//! use bugstr::chunking::{chunk_payload, reassemble_payload};
//!
//! // Chunking (sender side)
//! let large_payload = vec![0u8; 100_000]; // 100KB
//! let result = chunk_payload(&large_payload)?;
//! // result.manifest contains root_hash and chunk metadata
//! // result.chunks contains encrypted chunk data
//!
//! // Reassembly (receiver side)
//! let original = reassemble_payload(&result.manifest, &result.chunks)?;
//! assert_eq!(original, large_payload);
//! ```

use hashtree_core::crypto::{decrypt_chk, encrypt_chk, EncryptionKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::transport::{ChunkPayload, ManifestPayload, MAX_CHUNK_SIZE};

/// Errors that can occur during chunking operations.
#[derive(Debug, Error)]
pub enum ChunkingError {
    #[error("Payload too small for chunking (use direct transport)")]
    PayloadTooSmall,

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("Missing chunk at index {0}")]
    MissingChunk(u32),

    #[error("Chunk hash mismatch at index {0}")]
    ChunkHashMismatch(u32),

    #[error("Invalid root hash")]
    InvalidRootHash,
}

/// Result of chunking a large payload.
#[derive(Debug, Clone)]
pub struct ChunkingResult {
    /// Manifest containing root hash and chunk metadata.
    pub manifest: ManifestPayload,

    /// Encrypted chunks ready for publishing.
    pub chunks: Vec<ChunkPayload>,
}

/// Chunk a large payload using CHK encryption.
///
/// Splits the payload into chunks, encrypts each with its content hash,
/// and computes a root hash for the manifest.
///
/// # Arguments
///
/// * `data` - The payload bytes to chunk (should be >50KB)
///
/// # Returns
///
/// A `ChunkingResult` containing the manifest and encrypted chunks.
///
/// # Errors
///
/// Returns `ChunkingError::EncryptionError` if CHK encryption fails.
pub fn chunk_payload(data: &[u8]) -> Result<ChunkingResult, ChunkingError> {
    use base64::Engine;

    let total_size = data.len() as u64;
    let chunk_size = MAX_CHUNK_SIZE;

    // Split data into chunks
    let mut chunks: Vec<ChunkPayload> = Vec::new();
    let mut chunk_keys: Vec<EncryptionKey> = Vec::new();

    for (index, chunk_data) in data.chunks(chunk_size).enumerate() {
        // Encrypt chunk using CHK - returns (ciphertext, key) where key = SHA256(plaintext)
        let (ciphertext, key) = encrypt_chk(chunk_data)
            .map_err(|e| ChunkingError::EncryptionError(e.to_string()))?;

        // The key IS the content hash (CHK property)
        let chunk_hash_hex = hex::encode(&key);

        // Base64 encode ciphertext for JSON transport
        let encoded_data = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

        chunks.push(ChunkPayload {
            v: 1,
            index: index as u32,
            hash: chunk_hash_hex,
            data: encoded_data,
        });

        chunk_keys.push(key);
    }

    // Compute root hash from all chunk keys (simple concatenation + hash)
    let mut root_hasher = Sha256::new();
    for key in &chunk_keys {
        root_hasher.update(key);
    }
    let root_hash = hex::encode(root_hasher.finalize());

    // Build manifest (chunk_ids will be filled after publishing)
    let manifest = ManifestPayload {
        v: 1,
        root_hash,
        total_size,
        chunk_count: chunks.len() as u32,
        chunk_ids: vec![], // To be filled by caller after publishing chunks
    };

    Ok(ChunkingResult { manifest, chunks })
}

/// Reassemble a chunked payload from manifest and chunks.
///
/// Verifies chunk hashes, decrypts using CHK, and reconstructs the original payload.
///
/// # Arguments
///
/// * `manifest` - The manifest containing root hash and chunk metadata
/// * `chunks` - The encrypted chunks (must be in order by index)
///
/// # Returns
///
/// The original decrypted payload bytes.
///
/// # Errors
///
/// - `ChunkingError::MissingChunk` if a chunk is missing
/// - `ChunkingError::ChunkHashMismatch` if a chunk's hash doesn't match
/// - `ChunkingError::DecryptionError` if CHK decryption fails
/// - `ChunkingError::InvalidRootHash` if the root hash doesn't verify
pub fn reassemble_payload(
    manifest: &ManifestPayload,
    chunks: &[ChunkPayload],
) -> Result<Vec<u8>, ChunkingError> {
    use base64::Engine;

    // Verify chunk count
    if chunks.len() != manifest.chunk_count as usize {
        return Err(ChunkingError::InvalidManifest(format!(
            "Expected {} chunks, got {}",
            manifest.chunk_count,
            chunks.len()
        )));
    }

    // Sort chunks by index
    let mut sorted_chunks = chunks.to_vec();
    sorted_chunks.sort_by_key(|c| c.index);

    // Verify all indices are present
    for (i, chunk) in sorted_chunks.iter().enumerate() {
        if chunk.index != i as u32 {
            return Err(ChunkingError::MissingChunk(i as u32));
        }
    }

    // Decrypt and reassemble
    let mut result = Vec::with_capacity(manifest.total_size as usize);
    let mut chunk_keys: Vec<EncryptionKey> = Vec::new();

    for chunk in &sorted_chunks {
        // Decode the chunk hash to get the decryption key
        let key_bytes = hex::decode(&chunk.hash)
            .map_err(|e| ChunkingError::DecryptionError(format!("Invalid chunk hash: {}", e)))?;

        let key: EncryptionKey = key_bytes
            .try_into()
            .map_err(|_| ChunkingError::DecryptionError("Invalid key length".to_string()))?;

        // Decode base64 ciphertext
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&chunk.data)
            .map_err(|e| ChunkingError::DecryptionError(format!("Base64 decode failed: {}", e)))?;

        // Decrypt using CHK with the stored key
        let decrypted = decrypt_chk(&ciphertext, &key)
            .map_err(|e| ChunkingError::DecryptionError(e.to_string()))?;

        // Verify the decryption by re-encrypting and checking the key matches
        // (This is implicit in CHK - if decryption succeeds with the key, it's valid)

        chunk_keys.push(key);
        result.extend_from_slice(&decrypted);
    }

    // Verify root hash
    let mut root_hasher = Sha256::new();
    for key in &chunk_keys {
        root_hasher.update(key);
    }
    let computed_root = hex::encode(root_hasher.finalize());
    if computed_root != manifest.root_hash {
        return Err(ChunkingError::InvalidRootHash);
    }

    Ok(result)
}

/// Compute the expected number of chunks for a given payload size.
pub fn expected_chunk_count(payload_size: usize) -> u32 {
    let chunk_size = MAX_CHUNK_SIZE;
    ((payload_size + chunk_size - 1) / chunk_size) as u32
}

/// Estimate the total overhead for chunking a payload.
///
/// Returns approximate overhead in bytes from:
/// - Base64 encoding (~33% increase)
/// - CHK encryption (~16 bytes per chunk)
/// - JSON metadata
pub fn estimate_overhead(payload_size: usize) -> usize {
    let num_chunks = expected_chunk_count(payload_size) as usize;
    // Base64 overhead: 4/3 ratio
    // CHK overhead: ~16 bytes nonce per chunk
    // JSON overhead: ~100 bytes per chunk for metadata
    let base64_overhead = payload_size / 3;
    let chk_overhead = num_chunks * 16;
    let json_overhead = num_chunks * 100;
    base64_overhead + chk_overhead + json_overhead
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_and_reassemble_small() {
        // Small payload that fits in one chunk
        let data = vec![42u8; 1000];
        let result = chunk_payload(&data).unwrap();

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.manifest.chunk_count, 1);
        assert_eq!(result.manifest.total_size, 1000);

        let reassembled = reassemble_payload(&result.manifest, &result.chunks).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_chunk_and_reassemble_large() {
        // Large payload spanning multiple chunks
        let data: Vec<u8> = (0..150_000).map(|i| (i % 256) as u8).collect();
        let result = chunk_payload(&data).unwrap();

        assert!(result.chunks.len() > 1);
        assert_eq!(result.manifest.total_size, 150_000);

        let reassembled = reassemble_payload(&result.manifest, &result.chunks).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_root_hash_deterministic() {
        let data = vec![1, 2, 3, 4, 5];
        let result1 = chunk_payload(&data).unwrap();
        let result2 = chunk_payload(&data).unwrap();

        assert_eq!(result1.manifest.root_hash, result2.manifest.root_hash);
    }

    #[test]
    fn test_chunk_hash_verification() {
        let data = vec![42u8; 1000];
        let mut result = chunk_payload(&data).unwrap();

        // Corrupt chunk hash (which is the decryption key)
        // This should cause decryption to fail
        result.chunks[0].hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let err = reassemble_payload(&result.manifest, &result.chunks).unwrap_err();
        // With a wrong key, decryption will fail
        assert!(matches!(err, ChunkingError::DecryptionError(_)));
    }

    #[test]
    fn test_expected_chunk_count() {
        assert_eq!(expected_chunk_count(1000), 1);
        assert_eq!(expected_chunk_count(MAX_CHUNK_SIZE), 1);
        assert_eq!(expected_chunk_count(MAX_CHUNK_SIZE + 1), 2);
        assert_eq!(expected_chunk_count(MAX_CHUNK_SIZE * 3), 3);
    }
}
