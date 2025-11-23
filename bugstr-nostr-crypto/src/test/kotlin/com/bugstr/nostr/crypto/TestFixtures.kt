package com.bugstr.nostr.crypto

internal class TestFakeEncryptor : Nip44Encryptor {
    override fun encrypt(senderPrivateKeyHex: String, receiverPubKeyHex: String, plaintext: String): String {
        return "enc:${senderPrivateKeyHex.take(6)}:${receiverPubKeyHex.take(6)}:$plaintext"
    }
}

internal class TestFakePubKeyDeriver : PubKeyDeriver {
    override fun derivePubKeyHex(privateKeyHex: String): String = "pub${privateKeyHex.takeLast(6)}"
}

internal class TestDeterministicRandom : RandomSource() {
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
