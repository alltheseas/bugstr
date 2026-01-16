package com.bugstr.nostr.crypto

import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

private const val COMPRESSION_VERSION = 1
private const val COMPRESSION_TYPE = "gzip"

/**
 * Compresses a plaintext string using gzip and wraps it in a versioned envelope.
 *
 * Output format: {"v":1,"compression":"gzip","payload":"<base64>"}
 *
 * @param plaintext The string to compress
 * @return JSON envelope containing compressed payload
 */
fun compressPayload(plaintext: String): String {
    val compressed = ByteArrayOutputStream().use { baos ->
        GZIPOutputStream(baos).use { gzip ->
            gzip.write(plaintext.toByteArray(Charsets.UTF_8))
        }
        baos.toByteArray()
    }
    val base64 = Base64.encodeToString(compressed, Base64.NO_WRAP)
    return buildString {
        append("{\"v\":")
        append(COMPRESSION_VERSION)
        append(",\"compression\":\"")
        append(COMPRESSION_TYPE)
        append("\",\"payload\":\"")
        append(base64)
        append("\"}")
    }
}

/**
 * Decompresses a payload envelope back to plaintext.
 *
 * Handles both compressed envelopes and raw plaintext (for backwards compatibility).
 *
 * @param envelope The JSON envelope or raw plaintext
 * @return Decompressed plaintext string
 */
fun decompressPayload(envelope: String): String {
    val trimmed = envelope.trim()
    if (!trimmed.startsWith("{") || !trimmed.contains("\"compression\"")) {
        return envelope // raw plaintext, no compression
    }

    // Simple JSON parsing without dependencies
    val payloadStart = trimmed.indexOf("\"payload\":\"") + 11
    if (payloadStart < 11) return envelope
    val payloadEnd = trimmed.indexOf("\"", payloadStart)
    if (payloadEnd < 0) return envelope

    val base64 = trimmed.substring(payloadStart, payloadEnd)
    val compressed = Base64.decode(base64, Base64.NO_WRAP)

    return ByteArrayInputStream(compressed).use { bais ->
        GZIPInputStream(bais).use { gzip ->
            gzip.bufferedReader(Charsets.UTF_8).readText()
        }
    }
}

/**
 * Checks if a payload should be compressed based on size.
 *
 * Small payloads may not benefit from compression overhead.
 *
 * @param plaintext The string to check
 * @param threshold Minimum size in bytes to trigger compression (default 1KB)
 * @return true if the payload should be compressed
 */
fun shouldCompress(plaintext: String, threshold: Int = 1024): Boolean {
    return plaintext.toByteArray(Charsets.UTF_8).size >= threshold
}

/**
 * Compresses payload only if it exceeds the size threshold.
 *
 * @param plaintext The string to potentially compress
 * @param threshold Minimum size in bytes to trigger compression (default 1KB)
 * @return Compressed envelope if above threshold, otherwise raw plaintext
 */
fun maybeCompressPayload(plaintext: String, threshold: Int = 1024): String {
    return if (shouldCompress(plaintext, threshold)) {
        compressPayload(plaintext)
    } else {
        plaintext
    }
}
