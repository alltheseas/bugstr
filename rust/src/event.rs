//! Nostr event types and utilities.
//!
//! Implements NIP-01 event structure and ID computation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Minimal unsigned Nostr event representation.
///
/// Per NIP-17, rumors (kind 14) must include:
/// - `id`: SHA256 hash of serialized event data
/// - `sig`: Empty string (not omitted) to indicate unsigned status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedNostrEvent {
    /// Event ID (computed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Public key of event author (lowercase hex, 64 chars)
    pub pubkey: String,

    /// Unix timestamp in seconds
    pub created_at: u64,

    /// Event kind (14 for chat, 15 for file, 13 for seal, 1059 for gift wrap)
    pub kind: u16,

    /// List of tag arrays
    pub tags: Vec<Vec<String>>,

    /// Event content
    pub content: String,

    /// Signature (empty string for unsigned rumors)
    pub sig: String,
}

impl UnsignedNostrEvent {
    /// Creates a new unsigned event.
    pub fn new(
        pubkey: impl Into<String>,
        created_at: u64,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            pubkey: pubkey.into().to_lowercase(),
            created_at,
            kind,
            tags,
            content: content.into(),
            sig: String::new(),
        }
    }

    /// Computes the event ID per NIP-01.
    ///
    /// ID = SHA256([0, pubkey, created_at, kind, tags, content])
    pub fn compute_id(&self) -> String {
        let serialized = serde_json::json!([
            0,
            self.pubkey.to_lowercase(),
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]);

        let json = serde_json::to_string(&serialized).expect("JSON serialization failed");
        let hash = Sha256::digest(json.as_bytes());
        hex::encode(hash)
    }

    /// Returns a copy with the computed ID field set.
    pub fn with_id(mut self) -> Self {
        self.id = Some(self.compute_id());
        self
    }

    /// Serializes to JSON with all required fields including id.
    pub fn to_json(&self) -> String {
        let event = UnsignedNostrEvent {
            id: Some(self.compute_id()),
            pubkey: self.pubkey.to_lowercase(),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
            sig: self.sig.clone(),
        };
        serde_json::to_string(&event).expect("JSON serialization failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_id_returns_valid_hex() {
        let event = UnsignedNostrEvent::new(
            "a".repeat(64),
            1234567890,
            14,
            vec![],
            "test",
        );

        let id = event.compute_id();

        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn compute_id_is_deterministic() {
        let event = UnsignedNostrEvent::new(
            "a".repeat(64),
            1234567890,
            14,
            vec![vec!["p".into(), "b".repeat(64)]],
            "hello",
        );

        let id1 = event.compute_id();
        let id2 = event.compute_id();

        assert_eq!(id1, id2);
    }

    #[test]
    fn compute_id_changes_with_content() {
        let event1 = UnsignedNostrEvent::new("a".repeat(64), 1234567890, 14, vec![], "hello");
        let event2 = UnsignedNostrEvent::new("a".repeat(64), 1234567890, 14, vec![], "world");

        assert_ne!(event1.compute_id(), event2.compute_id());
    }

    #[test]
    fn to_json_includes_id_and_sig() {
        let event = UnsignedNostrEvent::new(
            "A".repeat(64), // uppercase to test normalization
            1234567890,
            14,
            vec![vec!["p".into(), "b".repeat(64)]],
            "crash report",
        );

        let json = event.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed["id"].is_string());
        assert_eq!(parsed["sig"], "");
        assert_eq!(parsed["pubkey"], "a".repeat(64)); // should be lowercase
        assert_eq!(parsed["kind"], 14);
    }

    #[test]
    fn sig_defaults_to_empty() {
        let event = UnsignedNostrEvent::new("a".repeat(64), 1234567890, 14, vec![], "test");

        assert_eq!(event.sig, "");
    }
}
