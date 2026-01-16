package com.bugstr.nostr.crypto

import com.vitorpamplona.quartz.nip01Core.core.toHexKey
import com.vitorpamplona.quartz.nip01Core.crypto.Nip01
import com.vitorpamplona.quartz.nip44Encryption.Nip44v2
import com.vitorpamplona.quartz.utils.Hex

/**
 * Thin Quartz-based Nip44 encryptor so hosts can avoid wiring their own crypto.
 */
class QuartzNip44Encryptor(
    private val nip44: Nip44v2 = Nip44v2(),
) : Nip44Encryptor {
    override fun encrypt(
        senderPrivateKeyHex: String,
        receiverPubKeyHex: String,
        plaintext: String,
    ): String {
        val senderPrivKey = Hex.decode(senderPrivateKeyHex)
        val receiverPubKey = Hex.decode(receiverPubKeyHex)
        return nip44.encrypt(
            msg = plaintext,
            privateKey = senderPrivKey,
            pubKey = receiverPubKey,
        ).encodePayload()
    }
}

/**
 * Derives compressed public keys (hex) via Quartz NIP-01 helpers.
 */
class QuartzPubKeyDeriver : PubKeyDeriver {
    override fun derivePubKeyHex(privateKeyHex: String): String {
        val privKey = Hex.decode(privateKeyHex)
        return Nip01.pubKeyCreate(privKey).toHexKey()
    }
}
