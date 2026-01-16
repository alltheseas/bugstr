package com.bugstr.nostr.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CompressionTest {

    @Test
    fun `compressPayload produces valid envelope`() {
        val plaintext = "Hello, World!"
        val envelope = compressPayload(plaintext)

        assertTrue(envelope.startsWith("{\"v\":1,"))
        assertTrue(envelope.contains("\"compression\":\"gzip\""))
        assertTrue(envelope.contains("\"payload\":\""))
    }

    @Test
    fun `decompressPayload round-trips correctly`() {
        val plaintext = "Test crash report with stack trace\n" +
            "java.lang.NullPointerException\n" +
            "\tat com.example.MyClass.method(MyClass.kt:42)"

        val compressed = compressPayload(plaintext)
        val decompressed = decompressPayload(compressed)

        assertEquals(plaintext, decompressed)
    }

    @Test
    fun `decompressPayload handles raw plaintext`() {
        val plaintext = "This is not compressed"
        val result = decompressPayload(plaintext)

        assertEquals(plaintext, result)
    }

    @Test
    fun `shouldCompress returns false for small payloads`() {
        val small = "tiny"
        assertFalse(shouldCompress(small, threshold = 1024))
    }

    @Test
    fun `shouldCompress returns true for large payloads`() {
        val large = "x".repeat(2000)
        assertTrue(shouldCompress(large, threshold = 1024))
    }

    @Test
    fun `maybeCompressPayload skips small payloads`() {
        val small = "tiny"
        val result = maybeCompressPayload(small, threshold = 1024)

        assertEquals(small, result)
    }

    @Test
    fun `maybeCompressPayload compresses large payloads`() {
        val large = "x".repeat(2000)
        val result = maybeCompressPayload(large, threshold = 1024)

        assertTrue(result.contains("\"compression\":\"gzip\""))
        assertEquals(large, decompressPayload(result))
    }

    @Test
    fun `compression achieves significant size reduction for text`() {
        val stackTrace = buildString {
            repeat(100) {
                appendLine("java.lang.RuntimeException: Error $it")
                appendLine("\tat com.example.Class$it.method(Class$it.kt:$it)")
            }
        }

        val compressed = compressPayload(stackTrace)
        val originalSize = stackTrace.toByteArray().size
        val compressedSize = compressed.toByteArray().size

        // Text should compress to less than 50% of original
        assertTrue(
            "Expected compression ratio < 0.5, got ${compressedSize.toDouble() / originalSize}",
            compressedSize < originalSize / 2
        )
    }
}
