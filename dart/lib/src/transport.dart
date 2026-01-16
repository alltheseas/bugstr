/// Transport layer constants and types for crash report delivery.
///
/// Supports both direct delivery (<=50KB) and hashtree-based chunked
/// delivery (>50KB) for large crash reports.
library;

/// Event kind for direct crash report delivery (<=50KB).
const int kindDirect = 10420;

// ---------------------------------------------------------------------------
// Relay Rate Limiting
// ---------------------------------------------------------------------------

/// Known relay rate limits in milliseconds between posts.
/// Based on strfry + noteguard default: 8 posts/minute = 7500ms between posts.
const Map<String, int> relayRateLimits = {
  'wss://relay.damus.io': 7500,
  'wss://nos.lol': 7500,
  'wss://relay.primal.net': 7500,
};

/// Default rate limit for unknown relays (conservative: 8 posts/min).
const int defaultRelayRateLimit = 7500;

/// Get rate limit for a relay URL.
int getRelayRateLimit(String relayUrl) {
  return relayRateLimits[relayUrl] ?? defaultRelayRateLimit;
}

// ---------------------------------------------------------------------------
// Progress Reporting (Apple HIG Compliant)
// ---------------------------------------------------------------------------

/// Phase of crash report upload.
enum BugstrProgressPhase {
  preparing,
  uploading,
  finalizing,
}

/// Progress state for crash report upload.
/// Designed for HIG-compliant determinate progress indicators.
class BugstrProgress {
  /// Current phase of upload.
  final BugstrProgressPhase phase;

  /// Current chunk being uploaded (1-indexed for display).
  final int currentChunk;

  /// Total number of chunks.
  final int totalChunks;

  /// Progress as fraction 0.0 to 1.0 (for UIProgressView/ProgressView).
  final double fractionCompleted;

  /// Estimated seconds remaining.
  final int estimatedSecondsRemaining;

  /// Human-readable status for accessibility/display.
  final String localizedDescription;

  const BugstrProgress({
    required this.phase,
    required this.currentChunk,
    required this.totalChunks,
    required this.fractionCompleted,
    required this.estimatedSecondsRemaining,
    required this.localizedDescription,
  });

  /// Create progress for preparing phase.
  factory BugstrProgress.preparing(int totalChunks, int estimatedSeconds) {
    return BugstrProgress(
      phase: BugstrProgressPhase.preparing,
      currentChunk: 0,
      totalChunks: totalChunks,
      fractionCompleted: 0.0,
      estimatedSecondsRemaining: estimatedSeconds,
      localizedDescription: 'Preparing crash report...',
    );
  }

  /// Create progress for uploading phase.
  factory BugstrProgress.uploading(
      int current, int total, int estimatedSeconds) {
    return BugstrProgress(
      phase: BugstrProgressPhase.uploading,
      currentChunk: current,
      totalChunks: total,
      fractionCompleted: current / total * 0.95, // Reserve 5% for finalizing
      estimatedSecondsRemaining: estimatedSeconds,
      localizedDescription: 'Uploading chunk $current of $total',
    );
  }

  /// Create progress for finalizing phase.
  factory BugstrProgress.finalizing(int totalChunks) {
    return BugstrProgress(
      phase: BugstrProgressPhase.finalizing,
      currentChunk: totalChunks,
      totalChunks: totalChunks,
      fractionCompleted: 0.95,
      estimatedSecondsRemaining: 2,
      localizedDescription: 'Finalizing...',
    );
  }

  /// Create progress for completion.
  factory BugstrProgress.completed(int totalChunks) {
    return BugstrProgress(
      phase: BugstrProgressPhase.finalizing,
      currentChunk: totalChunks,
      totalChunks: totalChunks,
      fractionCompleted: 1.0,
      estimatedSecondsRemaining: 0,
      localizedDescription: 'Complete',
    );
  }
}

/// Callback type for progress updates.
typedef BugstrProgressCallback = void Function(BugstrProgress progress);

// ---------------------------------------------------------------------------
// Event Kinds
// ---------------------------------------------------------------------------

/// Event kind for hashtree manifest (>50KB crash reports).
const int kindManifest = 10421;

/// Event kind for CHK-encrypted chunk data.
const int kindChunk = 10422;

/// Size threshold for switching from direct to chunked transport (50KB).
const int directSizeThreshold = 50 * 1024;

/// Maximum chunk size (48KB, accounts for base64 + relay overhead).
const int maxChunkSize = 48 * 1024;

/// Transport kind enumeration.
enum TransportKind {
  direct,
  chunked,
}

/// Determines transport kind based on payload size.
TransportKind getTransportKind(int size) {
  return size <= directSizeThreshold ? TransportKind.direct : TransportKind.chunked;
}

/// Direct crash report payload (kind 10420).
class DirectPayload {
  final int v;
  final Map<String, dynamic> crash;

  const DirectPayload({this.v = 1, required this.crash});

  Map<String, dynamic> toJson() => {'v': v, 'crash': crash};
}

/// Hashtree manifest payload (kind 10421).
class ManifestPayload {
  final int v;
  final String rootHash;
  final int totalSize;
  final int chunkCount;
  final List<String> chunkIds;

  /// Optional relay hints for each chunk (for optimized fetching).
  /// Maps chunk ID to list of relay URLs where that chunk was published.
  final Map<String, List<String>>? chunkRelays;

  const ManifestPayload({
    this.v = 1,
    required this.rootHash,
    required this.totalSize,
    required this.chunkCount,
    required this.chunkIds,
    this.chunkRelays,
  });

  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'v': v,
      'root_hash': rootHash,
      'total_size': totalSize,
      'chunk_count': chunkCount,
      'chunk_ids': chunkIds,
    };
    if (chunkRelays != null && chunkRelays!.isNotEmpty) {
      json['chunk_relays'] = chunkRelays;
    }
    return json;
  }
}

/// Chunk payload (kind 10422).
class ChunkPayload {
  final int v;
  final int index;
  final String hash;
  final String data;

  const ChunkPayload({
    this.v = 1,
    required this.index,
    required this.hash,
    required this.data,
  });

  Map<String, dynamic> toJson() => {
        'v': v,
        'index': index,
        'hash': hash,
        'data': data,
      };
}
