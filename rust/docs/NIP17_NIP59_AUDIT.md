# NIP-17 / NIP-59 Compliance Audit

**Date:** 2026-01-16
**Scope:** All bugstr SDKs (Android, Go, Python, React Native, Dart, Electron) and Rust receiver

## Executive Summary

The bugstr implementation is **largely compliant** with NIP-17 and NIP-59, with several gaps identified in the Rust receiver and optional feature support across sender SDKs.

### Critical Gaps
1. **Rust receiver doesn't verify signatures** - relies on implicit nostr crate behavior (which doesn't auto-verify)
2. **Rust receiver doesn't validate seal kind == 13**

### Medium Gaps
3. **All SDKs randomize rumor timestamp** - NIP-59 says rumor should have canonical timestamp; only seal/gift-wrap should be randomized
4. **No sender gift-wrap** - NIP-17 requires messages be gift-wrapped to BOTH sender and recipients; SDKs only wrap to recipient
5. **Android seal has tags** - NIP-59 says seal tags MUST be empty; Android adds expiration tags to seal
6. Non-Android SDKs don't support reply threading (e-tag), subject tags, expiration tags

### Low Gaps
7. **No kind:10050 relay lookup** - NIP-17 SHOULD consult recipient's relay list; SDKs use configured/default relays

---

## NIP-59 Gift Wrap Structure

### Rumor (Unsigned Inner Event)

| SDK | Kind Used | ID Computed | sig="" | Timestamp Randomized |
|-----|-----------|-------------|--------|----------------------|
| Android | 14 (chat) | ✅ SHA256 | ✅ | ⚠️ ±2 days (VIOLATION) |
| Go | 10420/10421 | ✅ SHA256 | ✅ | ⚠️ ±2 days (VIOLATION) |
| Python | 10420/10421 | ✅ SHA256 | ✅ | ⚠️ ±2 days (VIOLATION) |
| React Native | 10420/10421 | ✅ getEventHash | ✅ | ⚠️ ±2 days (VIOLATION) |
| Dart | 10420/10421 | ✅ SHA256 | ✅ | ⚠️ ±2 days (VIOLATION) |
| Electron | 10420/10421 | ✅ getEventHash | ✅ | ⚠️ ±2 days (VIOLATION) |

**⚠️ SPEC VIOLATION:** All SDKs randomize the rumor's `created_at`. NIP-59 specifies that the rumor should contain the canonical message timestamp, while only the seal and gift-wrap timestamps should be randomized for privacy. This breaks timing semantics.

**Locations:**
- `android/.../Nip17PayloadBuilder.kt:32-37` - `rumor.copy(createdAt = createdAt)` where `createdAt` is randomized
- `go/bugstr.go:491-494` - rumor created_at = randomPastTimestamp()
- `python/bugstr/__init__.py:456-458` - rumor created_at = _random_past_timestamp()
- `react-native/src/index.ts:177-179` - rumor created_at = randomPastTimestamp()
- `dart/lib/src/bugstr_client.dart:199` - rumorCreatedAt = _randomPastTimestamp()
- `electron/src/sdk.ts:170-172` - rumor created_at = randomPastTimestamp()

**Note:** Android wraps DirectPayload inside a kind 14 rumor (per NIP-17), while other SDKs use kind 10420/10421 directly. The Rust receiver accepts both (`is_crash_report_kind` matches 14, 10420, 10421).

### Seal (Kind 13)

| SDK | Kind | Signed By | Encryption | Timestamp | Tags Empty |
|-----|------|-----------|------------|-----------|------------|
| Android | 13 ✅ | Sender privkey ✅ | NIP-44 ✅ | Randomized ✅ | ⚠️ NO (VIOLATION) |
| Go | 13 ✅ | Sender privkey ✅ | NIP-44 ✅ | Randomized ✅ | ✅ |
| Python | 13 ✅ | Sender keys ✅ | NIP-44 ✅ | Randomized ✅ | ✅ |
| React Native | 13 ✅ | Sender privkey ✅ | NIP-44 ✅ | Randomized ✅ | ✅ |
| Dart | 13 ✅ | Sender privkey ✅ | NIP-44 ✅ | Randomized ✅ | ✅ |
| Electron | 13 ✅ | Sender privkey ✅ | NIP-44 ✅ | Randomized ✅ | ✅ |

**⚠️ SPEC VIOLATION (Android):** NIP-59 says seal "tags MUST be empty". Android adds expiration tags to the seal when `expirationSeconds` is set.

**Location:** `android/.../Nip17PayloadBuilder.kt:173-175`
```kotlin
val sealTags = buildList {
    expirationSeconds?.let { add(listOf("expiration", it.toString())) }
}
```

Expiration tags should only be on the gift wrap, not the seal.

### Gift Wrap (Kind 1059)

| SDK | Kind | Random Keypair | p-tag Recipient | Timestamp |
|-----|------|----------------|-----------------|-----------|
| Android | 1059 ✅ | ✅ randomPrivateKeyHex | ✅ | Randomized ✅ |
| Go | 1059 ✅ | ✅ GeneratePrivateKey | ✅ | Randomized ✅ |
| Python | 1059 ✅ | ✅ Keys.generate() | ✅ | Randomized ✅ |
| React Native | 1059 ✅ | ✅ generateSecretKey | ✅ | Randomized ✅ |
| Dart | 1059 ✅ | ✅ KeyPair.generate | ✅ | Randomized ✅ |
| Electron | 1059 ✅ | ✅ generateSecretKey | ✅ | Randomized ✅ |

---

## NIP-17 Private Direct Messages

### Sender Gift-Wrap Requirement

**⚠️ SPEC VIOLATION (All SDKs):** NIP-17 states: "Messages MUST be gift-wrapped to each receiver **and the sender individually**, so the sender can read and process their own sent messages from relays."

All bugstr SDKs only gift-wrap to recipients, not to the sender:

| SDK | Gift-wraps to Sender | Location |
|-----|---------------------|----------|
| Android | ❌ | `Nip17PayloadBuilder.kt:35` - only maps over `recipients` |
| Go | ❌ | `bugstr.go:487-550` - single gift wrap to developer |
| Python | ❌ | `__init__.py:454-494` - single gift wrap to developer |
| React Native | ❌ | `index.ts:171-218` - single gift wrap to recipient |
| Dart | ❌ | `bugstr_client.dart:197-260` - single gift wrap to developer |
| Electron | ❌ | `sdk.ts:164-211` - single gift wrap to recipient |

**Rationale for bugstr:** For crash reporting, the sender (crashing app) typically doesn't need to read back its own crash reports. However, this is technically a protocol violation.

### Relay Discovery (kind:10050)

**⚠️ SPEC RECOMMENDATION NOT FOLLOWED:** NIP-17 states: "Clients SHOULD read kind:10050 relay lists of the recipients to deliver messages."

All SDKs use configured or default relays instead of consulting the recipient's relay list:

| SDK | Consults 10050 | Location |
|-----|---------------|----------|
| Android | ❌ | Uses relays from `Nip17SendRequest` |
| Go | ❌ | `bugstr.go:720` - uses `config.Relays` |
| Python | ❌ | `__init__.py:512` - uses `_config.relays` |
| React Native | ❌ | `index.ts:382` - uses `config.relays` |
| Dart | ❌ | `bugstr_client.dart:282` - uses `effectiveRelays` |
| Electron | ❌ | `sdk.ts:240` - uses `config.relays` |

**Impact:** Crash reports may not reach developers who only monitor their preferred relays listed in kind:10050.

### Tag Handling

| SDK | Recipient p-tag | Sender NOT in p-tag | Reply e-tag | Subject tag | Expiration tag |
|-----|-----------------|---------------------|-------------|-------------|----------------|
| Android | ✅ | ✅ | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | ❌ | ❌ | ❌ |
| Python | ✅ | ✅ | ❌ | ❌ | ❌ |
| React Native | ✅ | ✅ | ❌ | ❌ | ❌ |
| Dart | ✅ | ✅ | ❌ | ❌ | ❌ |
| Electron | ✅ | ✅ | ❌ | ❌ | ❌ |

**NIP-17 Spec:** "Senders must include p tags for all recipients in the rumor but SHOULD NOT include a p tag for themselves."

All SDKs correctly exclude the sender from rumor p-tags. ✅

---

## Rust Receiver Analysis

### Current Implementation (main.rs:1143-1152)

```rust
fn unwrap_gift_wrap(keys: &Keys, gift_wrap: &Event) -> Result<Rumor, Box<dyn std::error::Error>> {
    // Decrypt gift wrap to get seal
    let seal_json = nip44::decrypt(keys.secret_key(), &gift_wrap.pubkey, &gift_wrap.content)?;
    let seal: Event = serde_json::from_str(&seal_json)?;

    // Decrypt seal to get rumor
    let rumor_json = nip44::decrypt(keys.secret_key(), &seal.pubkey, &seal.content)?;
    let rumor: Rumor = serde_json::from_str(&rumor_json)?;

    Ok(rumor)
}
```

### Gaps Identified

1. **No Gift Wrap Signature Verification**
   - The gift wrap arrives from relay as `Event` parsed by nostr crate
   - `serde_json::from_str` does NOT verify signatures (confirmed in nostr-0.43 source)
   - Should call `gift_wrap.verify()` before processing
   - **Risk:** Malformed events could be processed

2. **No Seal Signature Verification**
   - Seal parsed via `serde_json::from_str` - no auto-verification
   - Should call `seal.verify()` after parsing
   - **Risk:** Tampered seals could be accepted

3. **No Seal Kind Validation**
   - Code doesn't check `seal.kind == 13`
   - **Risk:** Any event kind inside gift wrap would be processed

4. **Seal Sender Identity Not Logged/Displayed**
   - NIP-59: "if the receiver can verify the seal signature, it can be sure the sender created the gift wrap"
   - `seal.pubkey` is the actual sender identity - should be prominently logged

### Recommended Fix

```rust
fn unwrap_gift_wrap(keys: &Keys, gift_wrap: &Event) -> Result<Rumor, Box<dyn std::error::Error>> {
    // Verify gift wrap signature (from random keypair)
    gift_wrap.verify()?;

    // Decrypt gift wrap to get seal
    let seal_json = nip44::decrypt(keys.secret_key(), &gift_wrap.pubkey, &gift_wrap.content)?;
    let seal: Event = serde_json::from_str(&seal_json)?;

    // Verify seal kind
    if seal.kind != Kind::Seal {
        return Err("Invalid seal kind".into());
    }

    // Verify seal signature (from actual sender)
    seal.verify()?;

    // Log verified sender identity
    tracing::info!("Verified sender: {}", seal.pubkey.to_hex());

    // Decrypt seal to get rumor
    let rumor_json = nip44::decrypt(keys.secret_key(), &seal.pubkey, &seal.content)?;
    let rumor: Rumor = serde_json::from_str(&rumor_json)?;

    Ok(rumor)
}
```

---

## NIP-44 Encryption

All SDKs correctly use NIP-44 versioned encryption for both seal and gift wrap content. ✅

| SDK | Library |
|-----|---------|
| Android | quartz.crypto (Nip44Encryptor) |
| Go | github.com/nbd-wtf/go-nostr/nip44 |
| Python | nostr_sdk.nip44 |
| React Native | nostr-tools.nip44 |
| Dart | ndk (Nip44) |
| Electron | nostr-tools.nip44 |

---

## Timestamp Randomization

All SDKs implement ±2 days randomization per NIP-59:

| SDK | Implementation |
|-----|----------------|
| Android | `TimestampRandomizer` - random 0 to 2 days in past |
| Go | `randomPastTimestamp()` - random 0 to 2 days in past |
| Python | `_random_past_timestamp()` - random 0 to 2 days in past |
| React Native | `randomPastTimestamp()` - random 0 to 2 days in past |
| Dart | `_randomPastTimestamp()` - random 0 to 2 days in past |
| Electron | `randomPastTimestamp()` - random 0 to 2 days in past |

**NIP-59 Spec:** "created_at SHOULD be tweaked to thwart time-analysis attacks. All inner event timestamps SHOULD be set to a date in the past within 2-day window."

All implementations randomize into the past (not future), which is correct. ✅

---

## Custom Kinds (Bugstr Extension)

Bugstr extends NIP-17 with custom kinds for crash report transport:

| Kind | Purpose | Transport |
|------|---------|-----------|
| 10420 | Direct crash payload (≤50KB) | Gift-wrapped |
| 10421 | Manifest for chunked payload (>50KB) | Gift-wrapped |
| 10422 | CHK-encrypted chunk data | Public (decryptable only with manifest) |

These are application-specific kinds and don't conflict with NIP-17/NIP-59. The receiver correctly filters for kind 1059 (gift wrap) and then examines the rumor kind to determine processing path.

---

## Recommendations

### Priority 1 (Critical) - FIXED 2026-01-16
- [x] Add `gift_wrap.verify()` call in Rust receiver
- [x] Add `seal.verify()` call in Rust receiver
- [x] Add `seal.kind == 13` validation in Rust receiver

### Priority 2 (Medium) - Spec Violations - FIXED 2026-01-16
- [x] **Fix rumor timestamp**: All SDKs now use actual message time for rumor `created_at`, only randomize seal/gift-wrap
- [x] **Fix Android seal tags**: Removed expiration tag from seal (kept on gift-wrap only)
- [ ] **Consider sender gift-wrap**: Intentionally skipped for crash reporting (sender doesn't need to read back crash reports)

### Priority 3 (Feature Gaps)
- [ ] ~~Add reply threading support (e-tag) to Go, Python, RN, Dart, Electron SDKs~~ - Not needed for crash reporting
- [ ] ~~Add subject tag support to Go, Python, RN, Dart, Electron SDKs~~ - Not needed for crash reporting
- [x] Expiration tag support already present in Android SDK

### Priority 4 (Low)
- [ ] Log verified sender pubkey prominently in receiver
- [ ] ~~Consider kind:10050 relay discovery for better deliverability~~ - Using hardcoded relay list
- [ ] Add protocol version field to allow future evolution
- [ ] Document the protocol inconsistency between Android (kind 14 wrapper) and other SDKs (direct kind 10420/10421)

---

## Specification References

- **NIP-17:** https://github.com/nostr-protocol/nips/blob/master/17.md
- **NIP-59:** https://github.com/nostr-protocol/nips/blob/master/59.md
- **NIP-44:** https://github.com/nostr-protocol/nips/blob/master/44.md
