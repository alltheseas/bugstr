//! Transport layer for crash report delivery.
//!
//! Defines event kinds and payload structures for delivering crash reports
//! via Nostr. Supports both direct delivery (≤50KB) and hashtree-based
//! chunked delivery (>50KB) for large crash reports.
//!
//! # Event Kinds
//!
//! | Kind | Name | Description |
//! |------|------|-------------|
//! | 10420 | Direct | Small crash report delivered directly in event content |
//! | 10421 | Manifest | Hashtree manifest with root hash and chunk metadata |
//! | 10422 | Chunk | CHK-encrypted chunk data (public, content-addressed) |
//!
//! # Transport Selection
//!
//! ```text
//! payload_size ≤ 50KB → kind 10420 (direct)
//! payload_size > 50KB → kind 10421 manifest + kind 10422 chunks
//! ```
//!
//! # Security Model
//!
//! - **Direct (10420)**: Gift-wrapped via NIP-17 for end-to-end encryption
//! - **Manifest (10421)**: Gift-wrapped via NIP-17; contains root hash (decryption key)
//! - **Chunks (10422)**: Public events with CHK encryption; root hash required to decrypt
//!
//! The root hash serves as the Content Hash Key (CHK) - without the manifest,
//! chunks are opaque encrypted blobs that cannot be decrypted.

use serde::{Deserialize, Serialize};

/// Event kind for direct crash report delivery (≤50KB).
///
/// Used when the compressed crash report fits within relay message limits.
/// The event is gift-wrapped via NIP-17 for end-to-end encryption.
pub const KIND_DIRECT: u16 = 10420;

/// Event kind for hashtree manifest (>50KB crash reports).
///
/// Contains the root hash (decryption key) and chunk metadata needed
/// to reconstruct and decrypt a large crash report. Gift-wrapped via NIP-17.
pub const KIND_MANIFEST: u16 = 10421;

/// Event kind for CHK-encrypted chunk data.
///
/// Public events containing encrypted chunk data. Cannot be decrypted
/// without the root hash from the corresponding manifest.
pub const KIND_CHUNK: u16 = 10422;

/// Size threshold for switching from direct to chunked transport.
///
/// Crash reports ≤50KB use direct transport (kind 10420).
/// Crash reports >50KB use chunked transport (kind 10421 + 10422).
///
/// This threshold accounts for:
/// - 64KB relay message limit (strfry default)
/// - Gift wrap overhead (~14KB for NIP-17 envelope)
pub const DIRECT_SIZE_THRESHOLD: usize = 50 * 1024; // 50KB

/// Maximum chunk size for hashtree transport.
///
/// Each chunk must fit within the 64KB relay limit after base64 encoding
/// and event envelope overhead.
pub const MAX_CHUNK_SIZE: usize = 48 * 1024; // 48KB

/// Direct crash report payload (kind 10420).
///
/// Used for crash reports that fit within the direct transport threshold.
/// The payload is JSON-serialized and placed in the event content field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPayload {
    /// Protocol version for forward compatibility.
    pub v: u8,

    /// Crash report data (JSON object).
    ///
    /// Contains fields like: message, stack, timestamp, environment, release, platform
    pub crash: serde_json::Value,
}

impl DirectPayload {
    /// Creates a new direct payload with the given crash data.
    pub fn new(crash: serde_json::Value) -> Self {
        Self { v: 1, crash }
    }

    /// Serializes the payload to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserializes a payload from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Hashtree manifest payload (kind 10421).
///
/// Contains metadata needed to fetch and decrypt a chunked crash report.
/// The root_hash serves as the CHK (Content Hash Key) for decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPayload {
    /// Protocol version for forward compatibility.
    pub v: u8,

    /// Root hash of the hashtree (hex-encoded).
    ///
    /// This is the CHK - the key needed to decrypt the chunks.
    /// Keeping this secret (via NIP-17 gift wrap) ensures only the
    /// intended recipient can decrypt the crash report.
    pub root_hash: String,

    /// Total size of the original unencrypted crash report in bytes.
    pub total_size: u64,

    /// Number of chunks.
    pub chunk_count: u32,

    /// Event IDs of the chunk events (kind 10422).
    ///
    /// Ordered list of chunk event IDs for retrieval.
    pub chunk_ids: Vec<String>,
}

impl ManifestPayload {
    /// Serializes the manifest to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserializes a manifest from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Chunk payload (kind 10422).
///
/// Contains a single CHK-encrypted chunk of crash report data.
/// Public event - encryption via CHK prevents unauthorized decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPayload {
    /// Protocol version for forward compatibility.
    pub v: u8,

    /// Chunk index (0-based).
    pub index: u32,

    /// Hash of this chunk (hex-encoded).
    ///
    /// Used for content addressing and integrity verification.
    pub hash: String,

    /// CHK-encrypted chunk data (base64-encoded).
    pub data: String,
}

impl ChunkPayload {
    /// Serializes the chunk to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserializes a chunk from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Determines the appropriate transport for a given payload size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Direct transport for small payloads (≤50KB).
    Direct,
    /// Chunked transport for large payloads (>50KB).
    Chunked,
}

impl TransportKind {
    /// Determines transport kind based on payload size in bytes.
    pub fn for_size(size: usize) -> Self {
        if size <= DIRECT_SIZE_THRESHOLD {
            Self::Direct
        } else {
            Self::Chunked
        }
    }

    /// Returns the event kind number for this transport.
    pub fn event_kind(&self) -> u16 {
        match self {
            Self::Direct => KIND_DIRECT,
            Self::Chunked => KIND_MANIFEST,
        }
    }
}

/// Checks if an event kind is a recognized bugstr crash report kind.
///
/// Returns true for:
/// - kind 14 (legacy NIP-17 DM)
/// - kind 10420 (direct crash report)
/// - kind 10421 (manifest)
pub fn is_crash_report_kind(kind: u16) -> bool {
    matches!(kind, 14 | KIND_DIRECT | KIND_MANIFEST)
}

/// Checks if an event kind requires chunked assembly.
pub fn is_chunked_kind(kind: u16) -> bool {
    kind == KIND_MANIFEST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_kind_selection() {
        // Small payload → direct
        assert_eq!(TransportKind::for_size(1024), TransportKind::Direct);
        assert_eq!(TransportKind::for_size(50 * 1024), TransportKind::Direct);

        // Large payload → chunked
        assert_eq!(TransportKind::for_size(50 * 1024 + 1), TransportKind::Chunked);
        assert_eq!(TransportKind::for_size(100 * 1024), TransportKind::Chunked);
    }

    #[test]
    fn test_direct_payload_serialization() {
        let crash = serde_json::json!({
            "message": "Test error",
            "stack": "at test.rs:42",
            "timestamp": 1234567890
        });
        let payload = DirectPayload::new(crash.clone());

        let json = payload.to_json().unwrap();
        let parsed = DirectPayload::from_json(&json).unwrap();

        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.crash, crash);
    }

    #[test]
    fn test_manifest_payload_serialization() {
        let manifest = ManifestPayload {
            v: 1,
            root_hash: "abc123".to_string(),
            total_size: 100000,
            chunk_count: 3,
            chunk_ids: vec!["id1".into(), "id2".into(), "id3".into()],
        };

        let json = manifest.to_json().unwrap();
        let parsed = ManifestPayload::from_json(&json).unwrap();

        assert_eq!(parsed.root_hash, "abc123");
        assert_eq!(parsed.chunk_count, 3);
    }

    #[test]
    fn test_is_crash_report_kind() {
        assert!(is_crash_report_kind(14)); // Legacy
        assert!(is_crash_report_kind(KIND_DIRECT));
        assert!(is_crash_report_kind(KIND_MANIFEST));
        assert!(!is_crash_report_kind(1)); // Regular note
        assert!(!is_crash_report_kind(KIND_CHUNK)); // Chunks are not standalone reports
    }
}
