package com.bugstr.nostr.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Nip17PayloadBuilderTest {
    private val encryptor = TestFakeEncryptor()
    private val pubKeyDeriver = TestFakePubKeyDeriver()
    private val giftWrapper = Nip59GiftWrapper(
        nip44Encryptor = encryptor,
        pubKeyDeriver = pubKeyDeriver,
        randomSource = TestDeterministicRandom(),
        timestampRandomizer = TimestampRandomizer(randomSource = TestDeterministicRandom()),
    )

    @Test
    fun buildGiftWraps_includesExpirationAndRelayHints() {
        val builder = Nip17PayloadBuilder(giftWrapper = giftWrapper, timestampRandomizer = TimestampRandomizer(TestDeterministicRandom()))
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

        assertEquals("sender-priv-key", wrap.sealSignerPrivateKeyHex)
        assertTrue(wrap.giftWrapPrivateKeyHex.startsWith("deadbeef"))

        val expirationTags = wrap.giftWrap.tags.filter { it.firstOrNull() == "expiration" }
        assertEquals("60", expirationTags.single().getOrNull(1))

        val pTag = wrap.giftWrap.tags.first { it.firstOrNull() == "p" }
        assertEquals("receiver-pub", pTag.getOrNull(1))
        assertEquals("wss://example.com", pTag.getOrNull(2))

        assertTrue(wrap.seal.content.startsWith("enc:"))
        assertTrue(wrap.giftWrap.content.startsWith("enc:"))
    }
}
