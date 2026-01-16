//! Compression utilities for crash report payloads.
//!
//! Provides gzip compression with a versioned envelope format
//! for efficient transmission of crash reports.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use thiserror::Error;

const COMPRESSION_VERSION: u8 = 1;
const COMPRESSION_TYPE: &str = "gzip";
/// Default compression threshold in bytes (1KB).
pub const DEFAULT_THRESHOLD: usize = 1024;

/// Compressed payload envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct CompressedEnvelope {
    /// Envelope version
    pub v: u8,
    /// Compression algorithm
    pub compression: String,
    /// Base64-encoded compressed payload
    pub payload: String,
}

/// Compression errors.
#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("Compression failed: {0}")]
    CompressionFailed(#[from] std::io::Error),

    #[error("Base64 decode failed: {0}")]
    Base64DecodeFailed(#[from] base64::DecodeError),

    #[error("JSON serialization failed: {0}")]
    JsonFailed(#[from] serde_json::Error),

    #[error("UTF-8 decode failed: {0}")]
    Utf8Failed(#[from] std::string::FromUtf8Error),
}

/// Compresses a plaintext string using gzip and wraps it in a versioned envelope.
///
/// Output format: `{"v":1,"compression":"gzip","payload":"<base64>"}`
///
/// # Example
///
/// ```
/// use bugstr::compress_payload;
///
/// let envelope = compress_payload("crash report...").unwrap();
/// assert!(envelope.contains("\"compression\":\"gzip\""));
/// ```
pub fn compress_payload(plaintext: &str) -> Result<String, CompressionError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plaintext.as_bytes())?;
    let compressed = encoder.finish()?;

    let envelope = CompressedEnvelope {
        v: COMPRESSION_VERSION,
        compression: COMPRESSION_TYPE.into(),
        payload: BASE64.encode(&compressed),
    };

    Ok(serde_json::to_string(&envelope)?)
}

/// Decompresses a payload envelope back to plaintext.
///
/// Handles both compressed envelopes and raw plaintext (for backwards compatibility).
///
/// # Example
///
/// ```
/// use bugstr::{compress_payload, decompress_payload};
///
/// let envelope = compress_payload("hello").unwrap();
/// let plaintext = decompress_payload(&envelope).unwrap();
/// assert_eq!(plaintext, "hello");
/// ```
pub fn decompress_payload(envelope: &str) -> Result<String, CompressionError> {
    let trimmed = envelope.trim();

    // Check if it looks like a compression envelope
    if !trimmed.starts_with('{') || !trimmed.contains("\"compression\"") {
        return Ok(envelope.to_string()); // raw plaintext
    }

    // Try to parse as envelope
    let parsed: CompressedEnvelope = match serde_json::from_str(trimmed) {
        Ok(env) => env,
        Err(_) => return Ok(envelope.to_string()), // not a valid envelope
    };

    let compressed = BASE64.decode(&parsed.payload)?;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    Ok(String::from_utf8(decompressed)?)
}

/// Checks if a payload should be compressed based on size.
///
/// Small payloads may not benefit from compression overhead.
pub fn should_compress(plaintext: &str, threshold: usize) -> bool {
    plaintext.len() >= threshold
}

/// Compresses payload only if it exceeds the size threshold.
///
/// # Example
///
/// ```
/// use bugstr::maybe_compress_payload;
///
/// // Small payload - not compressed
/// let small = maybe_compress_payload("tiny", 1024).unwrap();
/// assert_eq!(small, "tiny");
///
/// // Large payload - compressed
/// let large = "x".repeat(2000);
/// let result = maybe_compress_payload(&large, 1024).unwrap();
/// assert!(result.contains("gzip"));
/// ```
pub fn maybe_compress_payload(plaintext: &str, threshold: usize) -> Result<String, CompressionError> {
    if should_compress(plaintext, threshold) {
        compress_payload(plaintext)
    } else {
        Ok(plaintext.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_produces_valid_envelope() {
        let envelope = compress_payload("Hello, World!").unwrap();
        let parsed: CompressedEnvelope = serde_json::from_str(&envelope).unwrap();

        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.compression, "gzip");
        assert!(!parsed.payload.is_empty());
    }

    #[test]
    fn decompress_round_trips() {
        let plaintext = "Test crash report\njava.lang.NullPointerException\n\tat Class.method";
        let compressed = compress_payload(plaintext).unwrap();
        let decompressed = decompress_payload(&compressed).unwrap();

        assert_eq!(decompressed, plaintext);
    }

    #[test]
    fn decompress_handles_raw_plaintext() {
        let plaintext = "This is not compressed";
        let result = decompress_payload(plaintext).unwrap();

        assert_eq!(result, plaintext);
    }

    #[test]
    fn should_compress_small_returns_false() {
        assert!(!should_compress("tiny", DEFAULT_THRESHOLD));
    }

    #[test]
    fn should_compress_large_returns_true() {
        let large = "x".repeat(2000);
        assert!(should_compress(&large, DEFAULT_THRESHOLD));
    }

    #[test]
    fn maybe_compress_skips_small() {
        let result = maybe_compress_payload("tiny", DEFAULT_THRESHOLD).unwrap();
        assert_eq!(result, "tiny");
    }

    #[test]
    fn maybe_compress_compresses_large() {
        let large = "x".repeat(2000);
        let result = maybe_compress_payload(&large, DEFAULT_THRESHOLD).unwrap();

        assert!(result.contains("\"compression\":\"gzip\""));
        assert_eq!(decompress_payload(&result).unwrap(), large);
    }

    #[test]
    fn compression_achieves_significant_reduction() {
        let stack_trace: String = (0..100)
            .map(|i| format!("Error: RuntimeException {}\n\tat Class{}.method", i, i))
            .collect::<Vec<_>>()
            .join("\n");

        let compressed = compress_payload(&stack_trace).unwrap();

        // Text should compress to less than 50% of original
        assert!(
            compressed.len() < stack_trace.len() / 2,
            "Expected compression ratio < 0.5, got {}",
            compressed.len() as f64 / stack_trace.len() as f64
        );
    }
}
