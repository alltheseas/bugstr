/// Transport layer constants and types for crash report delivery.
///
/// Supports both direct delivery (<=50KB) and hashtree-based chunked
/// delivery (>50KB) for large crash reports.
library;

/// Event kind for direct crash report delivery (<=50KB).
const int kindDirect = 10420;

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

  const ManifestPayload({
    this.v = 1,
    required this.rootHash,
    required this.totalSize,
    required this.chunkCount,
    required this.chunkIds,
  });

  Map<String, dynamic> toJson() => {
        'v': v,
        'root_hash': rootHash,
        'total_size': totalSize,
        'chunk_count': chunkCount,
        'chunk_ids': chunkIds,
      };
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
