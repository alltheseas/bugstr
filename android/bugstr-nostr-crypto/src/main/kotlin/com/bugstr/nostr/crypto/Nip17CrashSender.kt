package com.bugstr.nostr.crypto

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/**
 * Glue helper for hosts: builds gift wraps, signs seal/gift-wrap, and hands signed events off to a publisher.
 * This keeps networking and signing pluggable so existing stacks (e.g., Primal) can wire in their own components.
 *
 * For large payloads (>50KB), uses CHK chunking:
 * - Chunks are published as public events (kind 10422)
 * - Manifest with root hash is gift-wrapped (kind 10421)
 * - Only the recipient can decrypt chunks using the root hash
 *
 * Uses round-robin relay distribution to maximize throughput while respecting
 * per-relay rate limits (8 posts/min for strfry+noteguard).
 */
class Nip17CrashSender(
    private val payloadBuilder: Nip17PayloadBuilder,
    private val signer: NostrEventSigner,
    private val publisher: NostrEventPublisher,
) {
    /** Track last post time per relay for rate limiting. */
    private val lastPostTime = mutableMapOf<String, Long>()

    /**
     * Send a crash report via NIP-17 gift wrap.
     *
     * For large reports (>50KB), chunks are distributed across relays using
     * round-robin to maximize throughput while respecting rate limits.
     *
     * @param request The send request containing payload and relay list.
     * @param onProgress Optional callback for upload progress (fires asynchronously).
     */
    suspend fun send(
        request: Nip17SendRequest,
        onProgress: BugstrProgressCallback? = null,
    ): Result<Unit> {
        val payloadSize = request.plaintext.toByteArray(Charsets.UTF_8).size

        return if (payloadSize <= Transport.DIRECT_SIZE_THRESHOLD) {
            sendDirect(request)
        } else {
            sendChunked(request, onProgress)
        }
    }

    private suspend fun sendDirect(request: Nip17SendRequest): Result<Unit> {
        // Wrap in DirectPayload format
        val directPayload = JSONObject().apply {
            put("v", 1)
            put("crash", JSONObject(request.plaintext))
        }

        val directRequest = request.copy(
            plaintext = directPayload.toString(),
            messageKind = Nip17MessageKind.Chat,
        )

        val wraps = payloadBuilder.buildGiftWraps(directRequest.toNip17Request())
        if (wraps.isEmpty()) return Result.success(Unit)

        val signedWraps = wraps.mapNotNull { wrap ->
            val signedSeal = signer.sign(
                event = wrap.seal,
                privateKeyHex = wrap.sealSignerPrivateKeyHex,
            ).getOrElse { return Result.failure(it) }

            val signedGift = signer.sign(
                event = wrap.giftWrap,
                privateKeyHex = wrap.giftWrapPrivateKeyHex,
            ).getOrElse { return Result.failure(it) }

            SignedGiftWrap(
                rumor = wrap.rumor,
                seal = signedSeal,
                giftWrap = signedGift,
            )
        }

        return publisher.publishGiftWraps(signedWraps)
    }

    /** Wait for relay rate limit if needed. */
    private suspend fun waitForRateLimit(relayUrl: String) {
        val rateLimit = Transport.getRelayRateLimit(relayUrl)
        val lastTime = lastPostTime[relayUrl] ?: 0L
        val now = System.currentTimeMillis()
        val elapsed = now - lastTime

        if (elapsed < rateLimit) {
            val waitMs = rateLimit - elapsed
            kotlinx.coroutines.delay(waitMs)
        }
    }

    /** Record post time for rate limiting. */
    private fun recordPostTime(relayUrl: String) {
        lastPostTime[relayUrl] = System.currentTimeMillis()
    }

    /**
     * Publish chunk with verification and retry on failure.
     * @return The relay URL where the chunk was successfully published, or null if all failed.
     */
    private suspend fun publishChunkWithVerify(
        chunk: SignedNostrEvent,
        relays: List<String>,
        startIndex: Int,
    ): String? {
        val numRelays = relays.size

        // Try each relay starting from startIndex (round-robin)
        for (attempt in 0 until numRelays) {
            val relayUrl = relays[(startIndex + attempt) % numRelays]

            // Publish with rate limiting
            waitForRateLimit(relayUrl)
            val publishResult = publisher.publishChunkToRelay(chunk, relayUrl)
            recordPostTime(relayUrl)

            if (publishResult.isFailure) {
                continue // Try next relay
            }

            // Brief delay before verification to allow relay to process
            kotlinx.coroutines.delay(500)

            // Verify the chunk exists
            if (publisher.verifyChunkExists(chunk.id, relayUrl)) {
                return relayUrl
            }
            // Verification failed, try next relay
        }

        return null // All relays failed
    }

    private suspend fun sendChunked(
        request: Nip17SendRequest,
        onProgress: BugstrProgressCallback?,
    ): Result<Unit> {
        val payloadBytes = request.plaintext.toByteArray(Charsets.UTF_8)
        val chunkingResult = Chunking.chunkPayload(payloadBytes)
        val totalChunks = chunkingResult.chunks.size
        val relays = request.relays.ifEmpty {
            listOf("wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net")
        }

        // Report initial progress
        val estimatedSeconds = Transport.estimateUploadSeconds(totalChunks, relays.size)
        onProgress?.invoke(BugstrProgress.preparing(totalChunks, estimatedSeconds))

        // Build and publish chunk events with round-robin distribution and verification
        val chunkIds = mutableListOf<String>()
        val chunkRelays = mutableMapOf<String, List<String>>()

        for ((index, chunk) in chunkingResult.chunks.withIndex()) {
            val chunkPayload = ChunkPayload(
                index = chunk.index,
                hash = Chunking.encodeChunkHash(chunk),
                data = Chunking.encodeChunkData(chunk),
            )

            val chunkEvent = buildChunkEvent(chunkPayload, request.senderPrivateKeyHex)
            val signedChunk = signer.sign(
                event = chunkEvent,
                privateKeyHex = request.senderPrivateKeyHex,
            ).getOrElse { return Result.failure(it) }

            chunkIds.add(signedChunk.id)

            // Publish with verification and retry (starts at round-robin relay)
            val successRelay = publishChunkWithVerify(signedChunk, relays, index % relays.size)
            if (successRelay != null) {
                chunkRelays[signedChunk.id] = listOf(successRelay)
            }
            // If all relays failed, chunk is lost - receiver will report missing chunk

            // Report progress
            val remainingChunks = totalChunks - index - 1
            val remainingSeconds = Transport.estimateUploadSeconds(remainingChunks, relays.size)
            onProgress?.invoke(BugstrProgress.uploading(index + 1, totalChunks, remainingSeconds))
        }

        // Report finalizing
        onProgress?.invoke(BugstrProgress.finalizing(totalChunks))

        // Build manifest with relay hints
        val manifest = ManifestPayload(
            rootHash = chunkingResult.rootHash,
            totalSize = chunkingResult.totalSize,
            chunkCount = totalChunks,
            chunkIds = chunkIds,
            chunkRelays = chunkRelays,
        )

        val chunkRelaysJson = JSONObject().apply {
            chunkRelays.forEach { (id, urls) ->
                put(id, JSONArray(urls))
            }
        }

        val manifestJson = JSONObject().apply {
            put("v", manifest.v)
            put("root_hash", manifest.rootHash)
            put("total_size", manifest.totalSize)
            put("chunk_count", manifest.chunkCount)
            put("chunk_ids", JSONArray(manifest.chunkIds))
            if (chunkRelays.isNotEmpty()) {
                put("chunk_relays", chunkRelaysJson)
            }
        }

        // Build gift wrap for manifest using kind 10421
        val manifestRequest = Nip17Request(
            senderPubKey = request.senderPubKey,
            senderPrivateKeyHex = request.senderPrivateKeyHex,
            recipients = request.recipients,
            plaintext = manifestJson.toString(),
            expirationSeconds = request.expirationSeconds,
        )

        val wraps = payloadBuilder.buildGiftWraps(manifestRequest)
        if (wraps.isEmpty()) return Result.success(Unit)

        val signedWraps = wraps.mapNotNull { wrap ->
            val signedSeal = signer.sign(
                event = wrap.seal,
                privateKeyHex = wrap.sealSignerPrivateKeyHex,
            ).getOrElse { return Result.failure(it) }

            val signedGift = signer.sign(
                event = wrap.giftWrap,
                privateKeyHex = wrap.giftWrapPrivateKeyHex,
            ).getOrElse { return Result.failure(it) }

            SignedGiftWrap(
                rumor = wrap.rumor,
                seal = signedSeal,
                giftWrap = signedGift,
            )
        }

        val result = publisher.publishGiftWraps(signedWraps)

        // Report completion
        if (result.isSuccess) {
            onProgress?.invoke(BugstrProgress.completed(totalChunks))
        }

        return result
    }

    private fun buildChunkEvent(chunk: ChunkPayload, privateKeyHex: String): UnsignedNostrEvent {
        val content = JSONObject().apply {
            put("v", chunk.v)
            put("index", chunk.index)
            put("hash", chunk.hash)
            put("data", chunk.data)
        }.toString()

        return UnsignedNostrEvent(
            pubKey = RandomSource().randomPrivateKeyHex().let { QuartzPubKeyDeriver().derivePubKeyHex(it) },
            createdAt = TimestampRandomizer().randomize(java.time.Instant.now().epochSecond),
            kind = Transport.KIND_CHUNK,
            tags = emptyList(),
            content = content,
        )
    }
}

data class Nip17SendRequest(
    val senderPubKey: String,
    val senderPrivateKeyHex: String,
    val recipients: List<Nip17Recipient>,
    val plaintext: String,
    val relays: List<String> = emptyList(),
    val expirationSeconds: Long? = null,
    val replyToEventId: String? = null,
    val replyRelayHint: String? = null,
    val subject: String? = null,
    val messageKind: Nip17MessageKind = Nip17MessageKind.Chat,
) {
    fun toNip17Request(): Nip17Request =
        Nip17Request(
            senderPubKey = senderPubKey,
            senderPrivateKeyHex = senderPrivateKeyHex,
            recipients = recipients,
            plaintext = plaintext,
            expirationSeconds = expirationSeconds,
            replyToEventId = replyToEventId,
            replyRelayHint = replyRelayHint,
            subject = subject,
            messageKind = messageKind,
        )
}

data class SignedGiftWrap(
    val rumor: UnsignedNostrEvent,
    val seal: SignedNostrEvent,
    val giftWrap: SignedNostrEvent,
)

data class SignedNostrEvent(
    val id: String,
    val pubKey: String,
    val createdAt: Long,
    val kind: Int,
    val tags: List<List<String>>,
    val content: String,
    val sig: String,
)

fun interface NostrEventSigner {
    fun sign(event: UnsignedNostrEvent, privateKeyHex: String): Result<SignedNostrEvent>
}

interface NostrEventPublisher {
    suspend fun publishGiftWraps(wraps: List<SignedGiftWrap>): Result<Unit>

    /**
     * Publish a chunk event to a specific relay.
     * Used for round-robin distribution to maximize throughput while respecting rate limits.
     *
     * @param chunk The signed chunk event to publish.
     * @param relayUrl The relay URL to publish to.
     */
    suspend fun publishChunkToRelay(chunk: SignedNostrEvent, relayUrl: String): Result<Unit>

    /**
     * Verify a chunk event exists on a relay.
     * Used for publish verification before moving to the next chunk.
     *
     * @param eventId The event ID to check.
     * @param relayUrl The relay URL to query.
     * @return True if the event exists on the relay.
     */
    suspend fun verifyChunkExists(eventId: String, relayUrl: String): Boolean {
        // Default implementation: assume success (for backwards compatibility)
        return true
    }

    /**
     * Publish a chunk event to all relays for redundancy.
     * @deprecated Use publishChunkToRelay for round-robin distribution.
     */
    @Deprecated("Use publishChunkToRelay for round-robin distribution")
    suspend fun publishChunk(chunk: SignedNostrEvent): Result<Unit> {
        // Default: just publish as a standalone event
        return Result.success(Unit)
    }
}
