package com.bugstr.nostr.crypto

/**
 * Transport layer constants and types for crash report delivery.
 *
 * Supports both direct delivery (<=50KB) and hashtree-based chunked
 * delivery (>50KB) for large crash reports.
 *
 * Event kinds:
 * - 10420: Direct crash report (small payloads, gift-wrapped)
 * - 10421: Manifest with root hash and chunk metadata (gift-wrapped)
 * - 10422: CHK-encrypted chunk data (public, content-addressed)
 */
object Transport {
    /** Event kind for direct crash report delivery (<=50KB). */
    const val KIND_DIRECT = 10420

    /** Event kind for hashtree manifest (>50KB crash reports). */
    const val KIND_MANIFEST = 10421

    /** Event kind for CHK-encrypted chunk data. */
    const val KIND_CHUNK = 10422

    /** Size threshold for switching from direct to chunked transport (50KB). */
    const val DIRECT_SIZE_THRESHOLD = 50 * 1024

    /** Maximum chunk size (48KB, accounts for base64 + relay overhead). */
    const val MAX_CHUNK_SIZE = 48 * 1024

    /** Determines transport kind based on payload size. */
    fun getTransportKind(size: Int): TransportKind =
        if (size <= DIRECT_SIZE_THRESHOLD) TransportKind.Direct else TransportKind.Chunked
}

enum class TransportKind {
    Direct,
    Chunked,
}

/** Direct crash report payload (kind 10420). */
data class DirectPayload(
    val v: Int = 1,
    val crash: Map<String, Any>,
)

/** Hashtree manifest payload (kind 10421). */
data class ManifestPayload(
    val v: Int = 1,
    val rootHash: String,
    val totalSize: Int,
    val chunkCount: Int,
    val chunkIds: List<String>,
)

/** Chunk payload (kind 10422). */
data class ChunkPayload(
    val v: Int = 1,
    val index: Int,
    val hash: String,
    val data: String,
)
