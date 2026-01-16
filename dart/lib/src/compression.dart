/// Compression utilities for crash report payloads.
///
/// Provides gzip compression with a versioned envelope format
/// for efficient transmission of crash reports.
library;

import 'dart:convert';
import 'dart:io';

const _compressionVersion = 1;
const _compressionType = 'gzip';

/// Compresses a plaintext string using gzip and wraps it in a versioned envelope.
///
/// Output format: {"v":1,"compression":"gzip","payload":"<base64>"}
///
/// ```dart
/// final envelope = compressPayload('crash report...');
/// ```
String compressPayload(String plaintext) {
  final bytes = utf8.encode(plaintext);
  final compressed = gzip.encode(bytes);
  final base64Payload = base64.encode(compressed);

  return jsonEncode({
    'v': _compressionVersion,
    'compression': _compressionType,
    'payload': base64Payload,
  });
}

/// Decompresses a payload envelope back to plaintext.
///
/// Handles both compressed envelopes and raw plaintext (for backwards compatibility).
///
/// ```dart
/// final plaintext = decompressPayload(envelope);
/// ```
String decompressPayload(String envelope) {
  final trimmed = envelope.trim();
  if (!trimmed.startsWith('{')) {
    return envelope; // raw plaintext
  }

  try {
    final parsed = jsonDecode(trimmed) as Map<String, dynamic>;
    if (!parsed.containsKey('compression') || !parsed.containsKey('payload')) {
      return envelope; // not a compression envelope
    }

    final base64Payload = parsed['payload'] as String;
    final compressed = base64.decode(base64Payload);
    final decompressed = gzip.decode(compressed);
    return utf8.decode(decompressed);
  } catch (_) {
    return envelope; // parse error, treat as raw
  }
}

/// Checks if a payload should be compressed based on size.
///
/// Small payloads may not benefit from compression overhead.
///
/// [threshold] is the minimum size in bytes to trigger compression (default 1KB).
bool shouldCompress(String plaintext, {int threshold = 1024}) {
  return utf8.encode(plaintext).length >= threshold;
}

/// Compresses payload only if it exceeds the size threshold.
///
/// ```dart
/// final result = maybeCompressPayload(crashReport);
/// ```
String maybeCompressPayload(String plaintext, {int threshold = 1024}) {
  return shouldCompress(plaintext, threshold: threshold)
      ? compressPayload(plaintext)
      : plaintext;
}
