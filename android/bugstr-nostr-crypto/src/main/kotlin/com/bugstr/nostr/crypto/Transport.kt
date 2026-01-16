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

    // -------------------------------------------------------------------------
    // Relay Rate Limiting
    // -------------------------------------------------------------------------

    /**
     * Known relay rate limits in milliseconds between posts.
     * Based on strfry + noteguard default: 8 posts/minute = 7500ms between posts.
     */
    val RELAY_RATE_LIMITS = mapOf(
        "wss://relay.damus.io" to 7500L,
        "wss://nos.lol" to 7500L,
        "wss://relay.primal.net" to 7500L,
    )

    /** Default rate limit for unknown relays (conservative: 8 posts/min). */
    const val DEFAULT_RELAY_RATE_LIMIT = 7500L

    /** Get rate limit for a relay URL. */
    fun getRelayRateLimit(relayUrl: String): Long =
        RELAY_RATE_LIMITS[relayUrl] ?: DEFAULT_RELAY_RATE_LIMIT

    /** Estimate upload time in seconds for given chunks and relays. */
    fun estimateUploadSeconds(totalChunks: Int, numRelays: Int): Int {
        // With round-robin, effective rate is numRelays * (1 post / 7.5s)
        val msPerChunk = DEFAULT_RELAY_RATE_LIMIT / numRelays
        return ((totalChunks * msPerChunk) / 1000).toInt().coerceAtLeast(1)
    }
}

enum class TransportKind {
    Direct,
    Chunked,
}

// -------------------------------------------------------------------------
// Progress Reporting (Apple HIG Compliant)
// -------------------------------------------------------------------------

/** Phase of crash report upload. */
enum class BugstrProgressPhase {
    Preparing,
    Uploading,
    Finalizing,
}

/**
 * Progress state for crash report upload.
 * Designed for HIG-compliant determinate progress indicators.
 */
data class BugstrProgress(
    /** Current phase of upload. */
    val phase: BugstrProgressPhase,
    /** Current chunk being uploaded (1-indexed for display). */
    val currentChunk: Int,
    /** Total number of chunks. */
    val totalChunks: Int,
    /** Progress as fraction 0.0 to 1.0 (for ProgressBar). */
    val fractionCompleted: Float,
    /** Estimated seconds remaining. */
    val estimatedSecondsRemaining: Int,
    /** Human-readable status for accessibility/display. */
    val localizedDescription: String,
) {
    companion object {
        fun preparing(totalChunks: Int, estimatedSeconds: Int) = BugstrProgress(
            phase = BugstrProgressPhase.Preparing,
            currentChunk = 0,
            totalChunks = totalChunks,
            fractionCompleted = 0f,
            estimatedSecondsRemaining = estimatedSeconds,
            localizedDescription = "Preparing crash report...",
        )

        fun uploading(current: Int, total: Int, estimatedSeconds: Int) = BugstrProgress(
            phase = BugstrProgressPhase.Uploading,
            currentChunk = current,
            totalChunks = total,
            fractionCompleted = (current.toFloat() / total) * 0.95f,
            estimatedSecondsRemaining = estimatedSeconds,
            localizedDescription = "Uploading chunk $current of $total",
        )

        fun finalizing(totalChunks: Int) = BugstrProgress(
            phase = BugstrProgressPhase.Finalizing,
            currentChunk = totalChunks,
            totalChunks = totalChunks,
            fractionCompleted = 0.95f,
            estimatedSecondsRemaining = 2,
            localizedDescription = "Finalizing...",
        )

        fun completed(totalChunks: Int) = BugstrProgress(
            phase = BugstrProgressPhase.Finalizing,
            currentChunk = totalChunks,
            totalChunks = totalChunks,
            fractionCompleted = 1f,
            estimatedSecondsRemaining = 0,
            localizedDescription = "Complete",
        )
    }
}

/** Callback type for progress updates. */
typealias BugstrProgressCallback = (BugstrProgress) -> Unit

// -------------------------------------------------------------------------
// Payload Types
// -------------------------------------------------------------------------

/** Direct crash report payload (kind 10420). */
data class DirectPayload(
    val v: Int = 1,
    val crash: Map<String, Any>,
)

/**
 * Hashtree manifest payload (kind 10421).
 * @param chunkRelays Optional relay hints for each chunk (for optimized fetching).
 */
data class ManifestPayload(
    val v: Int = 1,
    val rootHash: String,
    val totalSize: Int,
    val chunkCount: Int,
    val chunkIds: List<String>,
    val chunkRelays: Map<String, List<String>>? = null,
)

/** Chunk payload (kind 10422). */
data class ChunkPayload(
    val v: Int = 1,
    val index: Int,
    val hash: String,
    val data: String,
)
