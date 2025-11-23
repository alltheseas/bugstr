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

private class FakeSigner : NostrEventSigner {
    override fun sign(event: UnsignedNostrEvent, privateKeyHex: String): Result<SignedNostrEvent> =
        Result.success(
            SignedNostrEvent(
                id = "id-${event.kind}",
                pubKey = event.pubKey,
                createdAt = event.createdAt,
                kind = event.kind,
                tags = event.tags,
                content = event.content,
                sig = "sig-${privateKeyHex.take(6)}",
            ),
        )
}

private class RecordingPublisher : NostrEventPublisher {
    val published = mutableListOf<SignedGiftWrap>()

    override suspend fun publishGiftWraps(wraps: List<SignedGiftWrap>): Result<Unit> {
        published.addAll(wraps)
        return Result.success(Unit)
    }
}

class Nip17CrashSenderTest {
    private val publisher = RecordingPublisher()
    private val sender =
        Nip17CrashSender(
            payloadBuilder =
                Nip17PayloadBuilder(
                    giftWrapper =
                        Nip59GiftWrapper(
                            nip44Encryptor = FakeEncryptor(),
                            pubKeyDeriver = FakePubKeyDeriver(),
                            randomSource = DeterministicRandom(),
                            timestampRandomizer = TimestampRandomizer(randomSource = DeterministicRandom()),
                        ),
                    timestampRandomizer = TimestampRandomizer(randomSource = DeterministicRandom()),
                ),
            signer = FakeSigner(),
            publisher = publisher,
        )

    @Test
    fun send_buildsSignsAndPublishesGiftWraps() {
        val request =
            Nip17SendRequest(
                senderPubKey = "sender-pub",
                senderPrivateKeyHex = "sender-priv",
                recipients = listOf(Nip17Recipient(pubKeyHex = "receiver")),
                plaintext = "hi",
            )

        val result = sender.send(request)
        assertTrue(result.isSuccess)

        assertEquals(1, publisher.published.size)
        val sent = publisher.published.single()

        assertEquals(13, sent.seal.kind)
        assertEquals("sig-sender", sent.seal.sig.take(10))
        assertEquals(1059, sent.giftWrap.kind)
        assertTrue(sent.giftWrap.sig.startsWith("sig-dead"))
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
