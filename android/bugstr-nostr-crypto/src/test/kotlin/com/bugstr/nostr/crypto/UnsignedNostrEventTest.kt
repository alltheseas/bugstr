package com.bugstr.nostr.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests for [UnsignedNostrEvent] serialization and ID computation.
 *
 * These tests verify NIP-17/59 compliance, particularly:
 * - Event ID is correctly computed per NIP-01
 * - JSON output includes all required fields (id, sig)
 * - Rumors have sig: "" (empty string, not omitted)
 */
class UnsignedNostrEventTest {

    @Test
    fun toJson_includesIdAndSig() {
        val event = UnsignedNostrEvent(
            pubKey = "a".repeat(64),
            createdAt = 1234567890,
            kind = 14,
            tags = listOf(listOf("p", "b".repeat(64))),
            content = "hello world",
        )

        val json = event.toJson()

        // Verify all required fields are present
        assertTrue(json.contains("\"id\":\""), "JSON should contain id field")
        assertTrue(json.contains("\"pubkey\":\""), "JSON should contain pubkey field")
        assertTrue(json.contains("\"created_at\":"), "JSON should contain created_at field")
        assertTrue(json.contains("\"kind\":"), "JSON should contain kind field")
        assertTrue(json.contains("\"tags\":"), "JSON should contain tags field")
        assertTrue(json.contains("\"content\":\""), "JSON should contain content field")
        assertTrue(json.contains("\"sig\":\"\""), "JSON should contain sig field with empty string")
    }

    @Test
    fun computeId_returnsValidHex() {
        val event = UnsignedNostrEvent(
            pubKey = "a".repeat(64),
            createdAt = 1234567890,
            kind = 14,
            tags = emptyList(),
            content = "test",
        )

        val id = event.computeId()

        assertEquals(64, id.length, "Event ID should be 64 hex characters")
        assertTrue(id.all { it in '0'..'9' || it in 'a'..'f' }, "Event ID should be lowercase hex")
    }

    @Test
    fun computeId_isDeterministic() {
        val event = UnsignedNostrEvent(
            pubKey = "a".repeat(64),
            createdAt = 1234567890,
            kind = 14,
            tags = listOf(listOf("p", "b".repeat(64))),
            content = "hello",
        )

        val id1 = event.computeId()
        val id2 = event.computeId()

        assertEquals(id1, id2, "Event ID should be deterministic")
    }

    @Test
    fun computeId_changesWithContent() {
        val event1 = UnsignedNostrEvent(
            pubKey = "a".repeat(64),
            createdAt = 1234567890,
            kind = 14,
            tags = emptyList(),
            content = "hello",
        )

        val event2 = event1.copy(content = "world")

        assertTrue(
            event1.computeId() != event2.computeId(),
            "Different content should produce different IDs"
        )
    }

    @Test
    fun toJson_escapsSpecialCharacters() {
        val event = UnsignedNostrEvent(
            pubKey = "a".repeat(64),
            createdAt = 1234567890,
            kind = 14,
            tags = emptyList(),
            content = "line1\nline2\ttab\"quote\\backslash",
        )

        val json = event.toJson()

        assertTrue(json.contains("\\n"), "Newlines should be escaped")
        assertTrue(json.contains("\\t"), "Tabs should be escaped")
        assertTrue(json.contains("\\\""), "Quotes should be escaped")
        assertTrue(json.contains("\\\\"), "Backslashes should be escaped")
    }

    @Test
    fun toJson_pubkeyIsLowercase() {
        val event = UnsignedNostrEvent(
            pubKey = "ABCDEF".repeat(10) + "ABCD",
            createdAt = 1234567890,
            kind = 14,
            tags = emptyList(),
            content = "test",
        )

        val json = event.toJson()

        assertTrue(
            json.contains("\"pubkey\":\"abcdef"),
            "Pubkey should be lowercase in JSON output"
        )
    }

    @Test
    fun rumorSig_defaultsToEmptyString() {
        val rumor = UnsignedNostrEvent(
            pubKey = "a".repeat(64),
            createdAt = 1234567890,
            kind = 14,
            tags = emptyList(),
            content = "crash report",
        )

        assertEquals("", rumor.sig, "Rumor sig should default to empty string")
        assertTrue(
            rumor.toJson().contains("\"sig\":\"\""),
            "JSON should contain sig with empty string value"
        )
    }
}
