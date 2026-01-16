package com.bugstr.nostr.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import kotlin.math.absoluteValue

private const val KIND_CHAT_MESSAGE = 14
private const val KIND_FILE_MESSAGE = 15
private const val KIND_SEAL = 13
private const val KIND_GIFT_WRAP = 1059
private const val MAX_NIP44_PAYLOAD = 65_535
private const val TWO_DAYS_SECONDS: Long = 2 * 24 * 60 * 60

/**
 * Builds unsigned NIP-17 gift wraps (kind 1059) around unsigned chat/file rumors.
 * Hosts are expected to sign and publish the returned events with their own relay stack.
 */
class Nip17PayloadBuilder(
    private val giftWrapper: Nip59GiftWrapper,
    private val timestampRandomizer: TimestampRandomizer = TimestampRandomizer(),
) {
    fun buildGiftWraps(request: Nip17Request): List<Nip17GiftWrap> {
        require(request.recipients.isNotEmpty()) { "At least one recipient is required." }
        require(request.plaintext.isNotEmpty()) { "Plaintext must not be empty." }
        require(request.plaintext.length <= MAX_NIP44_PAYLOAD) {
            "Plaintext exceeds $MAX_NIP44_PAYLOAD characters."
        }
        require(request.senderPrivateKeyHex.isNotBlank()) { "Sender private key is required." }
        require(request.senderPubKey.isNotBlank()) { "Sender pubkey is required." }

        val rumor = buildRumor(request)
        val createdAt = timestampRandomizer.randomize(Instant.now().epochSecond)

        return request.recipients.map { recipient ->
            giftWrapper.wrap(
                rumor = rumor.copy(createdAt = createdAt),
                senderPubKey = request.senderPubKey,
                senderPrivateKeyHex = request.senderPrivateKeyHex,
                recipient = recipient,
                expirationSeconds = request.expirationSeconds,
                createdAt = createdAt,
            )
        }
    }

    private fun buildRumor(request: Nip17Request): UnsignedNostrEvent {
        require(request.senderPubKey.isNotBlank()) { "Rumor pubkey is required." }
        if (request.messageKind == Nip17MessageKind.File) {
            requireNotNull(request.fileMetadata) { "File metadata required for file messages." }
        }

        val tags = mutableListOf<List<String>>()
        request.recipients.forEach { recipient ->
            val tag = buildList(2 + if (recipient.relayHint != null) 1 else 0) {
                add("p")
                add(recipient.pubKeyHex)
                recipient.relayHint?.let { add(it) }
            }
            tags += tag
        }
        request.replyToEventId?.let { replyId ->
            tags += listOf("e", replyId, request.replyRelayHint ?: "")
        }
        request.subject?.let { subject ->
            tags += listOf("subject", subject)
        }
        if (request.messageKind == Nip17MessageKind.File) {
            request.fileMetadata?.let { meta ->
                tags += listOf("file-type", meta.mimeType)
                meta.encryptionAlgorithm?.let { tags += listOf("encryption-algorithm", it) }
                meta.decryptionKey?.let { tags += listOf("decryption-key", it) }
                meta.decryptionNonce?.let { tags += listOf("decryption-nonce", it) }
                meta.sha256?.let { tags += listOf("x", it) }
                meta.originalSha256?.let { tags += listOf("ox", it) }
                meta.sizeBytes?.let { tags += listOf("size", it.toString()) }
                meta.dimensions?.let { tags += listOf("dim", it) }
                meta.blurhash?.let { tags += listOf("blurhash", it) }
                meta.thumbnailUrl?.let { tags += listOf("thumb", it) }
                meta.fallbackUrls.forEach { url -> tags += listOf("fallback", url) }
            }
        }

        val kind =
            when (request.messageKind) {
                Nip17MessageKind.Chat -> KIND_CHAT_MESSAGE
                Nip17MessageKind.File -> KIND_FILE_MESSAGE
            }

        return UnsignedNostrEvent(
            pubKey = request.senderPubKey,
            createdAt = 0, // overwritten per gift wrap with randomized timestamp
            kind = kind,
            tags = tags,
            content = request.plaintext,
        )
    }
}

data class Nip17Request(
    val senderPubKey: String,
    val senderPrivateKeyHex: String,
    val recipients: List<Nip17Recipient>,
    val plaintext: String,
    val expirationSeconds: Long? = null,
    val replyToEventId: String? = null,
    val replyRelayHint: String? = null,
    val subject: String? = null,
    val messageKind: Nip17MessageKind = Nip17MessageKind.Chat,
    val fileMetadata: Nip17FileMetadata? = null,
)

data class Nip17Recipient(
    val pubKeyHex: String,
    val relayHint: String? = null,
)

enum class Nip17MessageKind {
    Chat,
    File,
}

data class Nip17FileMetadata(
    val mimeType: String,
    val encryptionAlgorithm: String? = null,
    val decryptionKey: String? = null,
    val decryptionNonce: String? = null,
    val sha256: String? = null,
    val originalSha256: String? = null,
    val sizeBytes: Long? = null,
    val dimensions: String? = null,
    val blurhash: String? = null,
    val thumbnailUrl: String? = null,
    val fallbackUrls: List<String> = emptyList(),
)

data class Nip17GiftWrap(
    val rumor: UnsignedNostrEvent,
    val sealSignerPrivateKeyHex: String,
    val seal: UnsignedNostrEvent,
    val giftWrapPrivateKeyHex: String,
    val giftWrap: UnsignedNostrEvent,
)

/**
 * Helper that creates seals and gift wraps from a rumor using NIP-59 rules.
 */
class Nip59GiftWrapper(
    private val nip44Encryptor: Nip44Encryptor = QuartzNip44Encryptor(),
    private val pubKeyDeriver: PubKeyDeriver = QuartzPubKeyDeriver(),
    private val randomSource: RandomSource = RandomSource(),
    private val timestampRandomizer: TimestampRandomizer = TimestampRandomizer(),
) {
    fun wrap(
        rumor: UnsignedNostrEvent,
        senderPubKey: String,
        senderPrivateKeyHex: String,
        recipient: Nip17Recipient,
        expirationSeconds: Long?,
        createdAt: Long,
    ): Nip17GiftWrap {
        require(rumor.pubKey == senderPubKey) { "Seal pubkey must match sender." }
        val sealCreatedAt = timestampRandomizer.randomize(createdAt)
        val giftCreatedAt = timestampRandomizer.randomize(createdAt)

        val sealedContent =
            nip44Encryptor.encrypt(
                senderPrivateKeyHex = senderPrivateKeyHex,
                receiverPubKeyHex = recipient.pubKeyHex,
                plaintext = rumor.copy(createdAt = sealCreatedAt).toJson(),
            )

        val sealTags = buildList {
            expirationSeconds?.let { add(listOf("expiration", it.toString())) }
        }

        val seal =
            UnsignedNostrEvent(
                pubKey = senderPubKey,
                createdAt = sealCreatedAt,
                kind = KIND_SEAL,
                tags = sealTags,
                content = sealedContent,
            )

        val giftWrapTags =
            buildList {
                add(listOf("p", recipient.pubKeyHex, recipient.relayHint ?: ""))
                expirationSeconds?.let { add(listOf("expiration", it.toString())) }
            }

        val giftWrapPrivateKey = randomSource.randomPrivateKeyHex()
        val giftWrapPubKey = pubKeyDeriver.derivePubKeyHex(giftWrapPrivateKey)

        val giftWrap =
            UnsignedNostrEvent(
                pubKey = giftWrapPubKey,
                createdAt = giftCreatedAt,
                kind = KIND_GIFT_WRAP,
                tags = giftWrapTags,
                content =
                    nip44Encryptor.encrypt(
                        senderPrivateKeyHex = giftWrapPrivateKey,
                        receiverPubKeyHex = recipient.pubKeyHex,
                        plaintext = seal.toJson(),
                    ),
            )

        return Nip17GiftWrap(
            rumor = rumor,
            sealSignerPrivateKeyHex = senderPrivateKeyHex,
            seal = seal,
            giftWrapPrivateKeyHex = giftWrapPrivateKey,
            giftWrap = giftWrap,
        )
    }
}

/**
 * Minimal unsigned Nostr event representation.
 *
 * Per NIP-17, rumors (kind 14/15) must include:
 * - `id`: SHA256 hash of the serialized event data
 * - `sig`: Empty string (not omitted) to indicate unsigned status
 *
 * The event ID is computed as: sha256([0, pubkey, created_at, kind, tags, content])
 *
 * @property pubKey The public key of the event author (lowercase hex, 64 chars)
 * @property createdAt Unix timestamp in seconds
 * @property kind The event kind (14 for chat, 15 for file, 13 for seal, 1059 for gift wrap)
 * @property tags List of tag arrays
 * @property content The event content (plaintext for rumors, encrypted for seals/wraps)
 * @property sig Signature field - empty string for rumors, actual signature for signed events
 */
data class UnsignedNostrEvent(
    val pubKey: String,
    val createdAt: Long,
    val kind: Int,
    val tags: List<List<String>>,
    val content: String,
    val sig: String = "",
) {
    /**
     * Computes the event ID per NIP-01.
     *
     * The ID is the SHA256 hash of the JSON-serialized array:
     * [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
     *
     * @return Lowercase hex string (64 characters)
     */
    fun computeId(): String {
        val serialized = buildString {
            append("[0,\"")
            append(pubKey.lowercase())
            append("\",")
            append(createdAt)
            append(",")
            append(kind)
            append(",")
            appendTagsJson(tags)
            append(",\"")
            append(content.escapeJson())
            append("\"]")
        }
        return sha256Hex(serialized)
    }

    /**
     * Serializes this event to JSON with all required fields including id and sig.
     *
     * Output format matches NIP-01 event structure:
     * {"id":"...","pubkey":"...","created_at":...,"kind":...,"tags":[...],"content":"...","sig":"..."}
     *
     * @return JSON string representation of the event
     */
    fun toJson(): String =
        buildString {
            append("{\"id\":\"")
            append(computeId())
            append("\",\"pubkey\":\"")
            append(pubKey.lowercase())
            append("\",\"created_at\":")
            append(createdAt)
            append(",\"kind\":")
            append(kind)
            append(",\"tags\":")
            appendTagsJson(tags)
            append(",\"content\":\"")
            append(content.escapeJson())
            append("\",\"sig\":\"")
            append(sig)
            append("\"}")
        }

    private fun StringBuilder.appendTagsJson(tags: List<List<String>>) {
        append('[')
        tags.forEachIndexed { index, tag ->
            if (index > 0) append(',')
            append('[')
            tag.forEachIndexed { tagIndex, value ->
                if (tagIndex > 0) append(',')
                append('"')
                append(value.escapeJson())
                append('"')
            }
            append(']')
        }
        append(']')
    }
}

fun interface Nip44Encryptor {
    fun encrypt(senderPrivateKeyHex: String, receiverPubKeyHex: String, plaintext: String): String
}

fun interface PubKeyDeriver {
    fun derivePubKeyHex(privateKeyHex: String): String
}

class TimestampRandomizer(
    private val randomSource: RandomSource = RandomSource(),
) {
    fun randomize(baseEpochSeconds: Long): Long {
        val offset = randomSource.randomSeconds(maxSeconds = TWO_DAYS_SECONDS)
        return baseEpochSeconds - offset
    }
}

open class RandomSource(
    private val secureRandom: SecureRandom = SecureRandom(),
) {
    open fun randomSeconds(maxSeconds: Long): Long {
        if (maxSeconds <= 0) return 0
        return secureRandom.nextLong(maxSeconds).absoluteValue
    }

    open fun randomPrivateKeyHex(): String {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        return bytes.joinToString(separator = "") { byte -> "%02x".format(byte) }
    }
}

/**
 * Escapes special characters for JSON string values.
 */
private fun String.escapeJson(): String =
    this
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

/**
 * Computes SHA256 hash of a string and returns lowercase hex.
 *
 * @param input The string to hash (UTF-8 encoded)
 * @return Lowercase hex string (64 characters)
 */
private fun sha256Hex(input: String): String {
    val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
    return bytes.joinToString(separator = "") { byte -> "%02x".format(byte) }
}
