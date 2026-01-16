package com.bugstr.nostr.crypto

import android.util.Base64
import org.json.JSONObject

/**
 * Glue helper for hosts: builds gift wraps, signs seal/gift-wrap, and hands signed events off to a publisher.
 * This keeps networking and signing pluggable so existing stacks (e.g., Primal) can wire in their own components.
 *
 * For large payloads (>50KB), uses CHK chunking:
 * - Chunks are published as public events (kind 10422)
 * - Manifest with root hash is gift-wrapped (kind 10421)
 * - Only the recipient can decrypt chunks using the root hash
 */
class Nip17CrashSender(
    private val payloadBuilder: Nip17PayloadBuilder,
    private val signer: NostrEventSigner,
    private val publisher: NostrEventPublisher,
) {
    suspend fun send(request: Nip17SendRequest): Result<Unit> {
        val payloadSize = request.plaintext.toByteArray(Charsets.UTF_8).size

        return if (payloadSize <= Transport.DIRECT_SIZE_THRESHOLD) {
            sendDirect(request)
        } else {
            sendChunked(request)
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

    private suspend fun sendChunked(request: Nip17SendRequest): Result<Unit> {
        val payloadBytes = request.plaintext.toByteArray(Charsets.UTF_8)
        val chunkingResult = Chunking.chunkPayload(payloadBytes)

        // Build and publish chunk events
        val chunkIds = mutableListOf<String>()
        for (chunk in chunkingResult.chunks) {
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

            // Publish chunk to all relays
            publisher.publishChunk(signedChunk).getOrElse { return Result.failure(it) }
        }

        // Build manifest
        val manifest = ManifestPayload(
            rootHash = chunkingResult.rootHash,
            totalSize = chunkingResult.totalSize,
            chunkCount = chunkingResult.chunks.size,
            chunkIds = chunkIds,
        )

        val manifestJson = JSONObject().apply {
            put("v", manifest.v)
            put("root_hash", manifest.rootHash)
            put("total_size", manifest.totalSize)
            put("chunk_count", manifest.chunkCount)
            put("chunk_ids", manifest.chunkIds)
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

        return publisher.publishGiftWraps(signedWraps)
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

fun interface NostrEventPublisher {
    suspend fun publishGiftWraps(wraps: List<SignedGiftWrap>): Result<Unit>

    /**
     * Publish a chunk event to all relays for redundancy.
     * Default implementation calls publishGiftWraps with a single item.
     */
    suspend fun publishChunk(chunk: SignedNostrEvent): Result<Unit> {
        // Default: just publish as a standalone event
        return Result.success(Unit)
    }
}
