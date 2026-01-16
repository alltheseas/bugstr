package com.bugstr.nostr.crypto

/**
 * Glue helper for hosts: builds gift wraps, signs seal/gift-wrap, and hands signed events off to a publisher.
 * This keeps networking and signing pluggable so existing stacks (e.g., Primal) can wire in their own components.
 */
class Nip17CrashSender(
    private val payloadBuilder: Nip17PayloadBuilder,
    private val signer: NostrEventSigner,
    private val publisher: NostrEventPublisher,
) {
    suspend fun send(request: Nip17SendRequest): Result<Unit> {
        val wraps = payloadBuilder.buildGiftWraps(request.toNip17Request())
        if (wraps.isEmpty()) return Result.success(Unit)

        val signedWraps =
            wraps.mapNotNull { wrap ->
                val signedSeal =
                    signer.sign(
                        event = wrap.seal,
                        privateKeyHex = wrap.sealSignerPrivateKeyHex,
                    ).getOrElse { return Result.failure(it) }

                val signedGift =
                    signer.sign(
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
}
