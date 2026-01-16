package com.bugstr.nostr.crypto

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * CHK (Content Hash Key) chunking for large crash reports.
 *
 * Implements hashtree-style encryption where:
 * - Data is split into fixed-size chunks
 * - Each chunk is encrypted using its content hash as the key
 * - A root hash is computed from all chunk hashes
 * - Only the manifest (with root hash) needs to be encrypted via NIP-17
 * - Chunks are public but opaque without the root hash
 */
object Chunking {
    private const val AES_ALGORITHM = "AES/CBC/PKCS5Padding"
    private const val KEY_ALGORITHM = "AES"
    private const val IV_SIZE = 16

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
     * Encrypts data using AES-256-CBC with the given key.
     * IV is prepended to the ciphertext.
     */
    private fun chkEncrypt(data: ByteArray, key: ByteArray): ByteArray {
        val secureRandom = SecureRandom()
        val iv = ByteArray(IV_SIZE)
        secureRandom.nextBytes(iv)

        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val keySpec = SecretKeySpec(key, KEY_ALGORITHM)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

        val encrypted = cipher.doFinal(data)
        return iv + encrypted
    }

    /**
     * Decrypts data using AES-256-CBC with the given key.
     * Expects IV prepended to the ciphertext.
     */
    fun chkDecrypt(data: ByteArray, key: ByteArray): ByteArray {
        val iv = data.sliceArray(0 until IV_SIZE)
        val ciphertext = data.sliceArray(IV_SIZE until data.size)

        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val keySpec = SecretKeySpec(key, KEY_ALGORITHM)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)

        return cipher.doFinal(ciphertext)
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

            // Compute hash of plaintext chunk (becomes encryption key)
            val hash = sha256(chunkData)
            chunkHashes.add(hash)

            // Encrypt chunk using its hash as key
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
