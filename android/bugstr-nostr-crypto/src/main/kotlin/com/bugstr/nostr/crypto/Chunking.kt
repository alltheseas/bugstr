package com.bugstr.nostr.crypto

import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * CHK (Content Hash Key) chunking for large crash reports.
 *
 * Implements hashtree-core compatible encryption where:
 * - Data is split into fixed-size chunks
 * - Each chunk's content hash is derived via HKDF to get the encryption key
 * - AES-256-GCM with zero nonce encrypts each chunk
 * - A root hash is computed from all chunk hashes
 * - Only the manifest (with root hash) needs to be encrypted via NIP-17
 * - Chunks are public but opaque without the root hash
 *
 * **CRITICAL**: Must match hashtree-core crypto exactly:
 * - Key derivation: HKDF-SHA256(content_hash, salt="hashtree-chk", info="encryption-key")
 * - Cipher: AES-256-GCM with 12-byte zero nonce
 * - Format: [ciphertext][16-byte auth tag]
 */
object Chunking {
    private const val AES_GCM_ALGORITHM = "AES/GCM/NoPadding"
    private const val KEY_ALGORITHM = "AES"
    private const val HMAC_ALGORITHM = "HmacSHA256"

    /** HKDF salt for CHK derivation (must match hashtree-core) */
    private val CHK_SALT = "hashtree-chk".toByteArray(Charsets.UTF_8)

    /** HKDF info for key derivation (must match hashtree-core) */
    private val CHK_INFO = "encryption-key".toByteArray(Charsets.UTF_8)

    /** Nonce size for AES-GCM (96 bits) */
    private const val NONCE_SIZE = 12

    /** Auth tag size for AES-GCM (128 bits) */
    private const val TAG_SIZE_BITS = 128

    /**
     * Result of chunking a payload.
     */
    data class ChunkingResult(
        val rootHash: String,
        val totalSize: Int,
        val chunks: List<ChunkData>,
    )

    /**
     * Encrypted chunk data before publishing.
     */
    data class ChunkData(
        val index: Int,
        val hash: ByteArray,
        val encrypted: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ChunkData) return false
            return index == other.index && hash.contentEquals(other.hash)
        }

        override fun hashCode(): Int = 31 * index + hash.contentHashCode()
    }

    /**
     * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
     */
    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(salt, HMAC_ALGORITHM))
        return mac.doFinal(ikm)
    }

    /**
     * HKDF-Expand: OKM = HMAC-based expansion
     */
    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(prk, HMAC_ALGORITHM))

        val hashLen = 32 // SHA-256 output length
        val n = (length + hashLen - 1) / hashLen
        val okm = ByteArray(length)
        var t = ByteArray(0)
        var okmOffset = 0

        for (i in 1..n) {
            mac.reset()
            mac.update(t)
            mac.update(info)
            mac.update(i.toByte())
            t = mac.doFinal()

            val copyLen = minOf(hashLen, length - okmOffset)
            System.arraycopy(t, 0, okm, okmOffset, copyLen)
            okmOffset += copyLen
        }

        return okm
    }

    /**
     * Derives encryption key from content hash using HKDF-SHA256.
     * Must match hashtree-core: HKDF(content_hash, salt="hashtree-chk", info="encryption-key")
     */
    private fun deriveKey(contentHash: ByteArray): ByteArray {
        val prk = hkdfExtract(CHK_SALT, contentHash)
        return hkdfExpand(prk, CHK_INFO, 32)
    }

    /**
     * Encrypts data using AES-256-GCM with zero nonce (CHK-safe).
     * Returns: [ciphertext][16-byte auth tag]
     *
     * Zero nonce is safe for CHK because same key = same content (convergent encryption).
     */
    private fun chkEncrypt(data: ByteArray, contentHash: ByteArray): ByteArray {
        val key = deriveKey(contentHash)
        val zeroNonce = ByteArray(NONCE_SIZE) // All zeros

        val cipher = Cipher.getInstance(AES_GCM_ALGORITHM)
        val keySpec = SecretKeySpec(key, KEY_ALGORITHM)
        val gcmSpec = GCMParameterSpec(TAG_SIZE_BITS, zeroNonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        // GCM automatically appends auth tag to ciphertext
        return cipher.doFinal(data)
    }

    /**
     * Decrypts data using AES-256-GCM with zero nonce.
     * Expects: [ciphertext][16-byte auth tag]
     */
    fun chkDecrypt(data: ByteArray, contentHash: ByteArray): ByteArray {
        val key = deriveKey(contentHash)
        val zeroNonce = ByteArray(NONCE_SIZE)

        val cipher = Cipher.getInstance(AES_GCM_ALGORITHM)
        val keySpec = SecretKeySpec(key, KEY_ALGORITHM)
        val gcmSpec = GCMParameterSpec(TAG_SIZE_BITS, zeroNonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        return cipher.doFinal(data)
    }

    /**
     * Computes SHA-256 hash of data.
     */
    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * Converts bytes to lowercase hex string.
     */
    private fun ByteArray.toHex(): String =
        joinToString(separator = "") { byte -> "%02x".format(byte) }

    /**
     * Splits payload into chunks and encrypts each using CHK.
     *
     * Each chunk is encrypted with a key derived from its content hash via HKDF.
     * The root hash is computed by hashing all chunk hashes concatenated.
     *
     * **CRITICAL**: Uses hashtree-core compatible encryption:
     * - HKDF-SHA256 key derivation with salt="hashtree-chk"
     * - AES-256-GCM with zero nonce
     *
     * @param data The data to chunk and encrypt
     * @param chunkSize Maximum size of each chunk (default 48KB)
     * @return Chunking result with root hash and encrypted chunks
     */
    fun chunkPayload(
        data: ByteArray,
        chunkSize: Int = Transport.MAX_CHUNK_SIZE,
    ): ChunkingResult {
        val chunks = mutableListOf<ChunkData>()
        val chunkHashes = mutableListOf<ByteArray>()

        var offset = 0
        var index = 0
        while (offset < data.size) {
            val end = minOf(offset + chunkSize, data.size)
            val chunkData = data.sliceArray(offset until end)

            // Compute hash of plaintext chunk (used for key derivation)
            val hash = sha256(chunkData)
            chunkHashes.add(hash)

            // Encrypt chunk using HKDF-derived key from hash
            val encrypted = chkEncrypt(chunkData, hash)

            chunks.add(
                ChunkData(
                    index = index,
                    hash = hash,
                    encrypted = encrypted,
                ),
            )

            offset = end
            index++
        }

        // Compute root hash from all chunk hashes
        val rootHashInput = chunkHashes.fold(ByteArray(0)) { acc, h -> acc + h }
        val rootHash = sha256(rootHashInput).toHex()

        return ChunkingResult(
            rootHash = rootHash,
            totalSize = data.size,
            chunks = chunks,
        )
    }

    /**
     * Converts chunk data to base64 for transport.
     */
    fun encodeChunkData(chunk: ChunkData): String =
        Base64.encodeToString(chunk.encrypted, Base64.NO_WRAP)

    /**
     * Converts chunk hash to hex string.
     */
    fun encodeChunkHash(chunk: ChunkData): String = chunk.hash.toHex()
}
