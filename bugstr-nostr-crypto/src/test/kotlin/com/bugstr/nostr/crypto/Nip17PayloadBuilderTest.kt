package com.bugstr.nostr.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private class FakeEncryptor : Nip44Encryptor {
    override fun encrypt(senderPrivateKeyHex: String, receiverPubKeyHex: String, plaintext: String): String {
        return "enc:${senderPrivateKeyHex.take(6)}:${receiverPubKeyHex.take(6)}:$plaintext"
    }
}

private class FakePubKeyDeriver : PubKeyDeriver {
    override fun derivePubKeyHex(privateKeyHex: String): String = "pub${privateKeyHex.takeLast(6)}"
}

class Nip17PayloadBuilderTest {
    private val encryptor = FakeEncryptor()
    private val pubKeyDeriver = FakePubKeyDeriver()
    private val giftWrapper = Nip59GiftWrapper(
        nip44Encryptor = encryptor,
        pubKeyDeriver = pubKeyDeriver,
        randomSource = DeterministicRandom(),
        timestampRandomizer = TimestampRandomizer(randomSource = DeterministicRandom()),
    )

    @Test
    fun buildGiftWraps_includesExpirationAndRelayHints() {
        val builder = Nip17PayloadBuilder(giftWrapper = giftWrapper, timestampRandomizer = TimestampRandomizer(DeterministicRandom()))
        val request =
            Nip17Request(
                senderPubKey = "sender-pub",
                senderPrivateKeyHex = "sender-priv-key",
                recipients = listOf(Nip17Recipient(pubKeyHex = "receiver-pub", relayHint = "wss://example.com")),
                plaintext = "hello",
                expirationSeconds = 60,
                replyToEventId = "parent-id",
                replyRelayHint = "wss://reply.com",
                subject = "Crash Report",
            )

        val wraps = builder.buildGiftWraps(request)
        val wrap = wraps.single()

        assertEquals(13, wrap.seal.kind)
        assertEquals(1059, wrap.giftWrap.kind)

        val expirationTags = wrap.giftWrap.tags.filter { it.firstOrNull() == "expiration" }
        assertEquals("60", expirationTags.single().getOrNull(1))

        val pTag = wrap.giftWrap.tags.first { it.firstOrNull() == "p" }
        assertEquals("receiver-pub", pTag.getOrNull(1))
        assertEquals("wss://example.com", pTag.getOrNull(2))

        assertTrue(wrap.seal.content.startsWith("enc:"))
        assertTrue(wrap.giftWrap.content.startsWith("enc:"))
    }
}

private class DeterministicRandom : RandomSource() {
    private var counter = 0L

    override fun randomSeconds(maxSeconds: Long): Long {
        counter += 1
        return counter
    }

    override fun randomPrivateKeyHex(): String {
        counter += 1
        return "deadbeef${counter}"
    }
}
