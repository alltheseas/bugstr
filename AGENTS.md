# BugStr Agent Guidelines

This document provides guidelines for AI agents and human contributors working on BugStr.

## Before Committing Checklist

Every commit touching code must pass:

- [ ] `cargo test` (Rust) or equivalent per platform
- [ ] `cargo build --release` compiles without errors
- [ ] CHANGELOG.md updated for user-facing changes
- [ ] Public functions have docstrings
- [ ] No PII in test fixtures (no real emails, IPs, pubkeys)

## Project Overview

BugStr is a privacy-focused crash reporting library for Nostr applications. It uses NIP-17 gift-wrapped encrypted messages to deliver crash reports with user consent.

### Supported Platforms

| Platform | Directory |
|----------|-----------|
| Android/Kotlin | `android/` |
| Electron | `electron/` |
| Flutter/Dart | `dart/` |
| Rust | `rust/` |
| Go | `go/` |
| Python | `python/` |
| React Native | `react-native/` |

### Key NIPs

- **NIP-17** - Private Direct Messages
- **NIP-44** - Versioned Encryption (v2)
- **NIP-59** - Gift Wrap (rumor → seal → gift wrap)
- **NIP-40** - Expiration Timestamp

## Privacy Requirements

Privacy is bugstr's core differentiator. All code must uphold these rules:

### PII Collection Defaults

- SDKs MUST NOT collect user-identifiable data by default
- No IP addresses, email addresses, usernames, or device IDs unless explicitly opted in
- Crash report content (stack traces, messages) must not contain PII from the user's app — this is the SDK integrator's responsibility, but SDKs should document the risk
- Test fixtures and examples must use synthetic data only

### User Consent

- Crash reporting MUST be opt-in, not opt-out
- SDKs must provide `setEnabled(bool)` or equivalent to control collection
- No data leaves the device before user consent
- Crashes occurring before consent can be cached locally and sent after consent is granted

### Data Handling

- All crash data is encrypted end-to-end via NIP-17 (gift wrap)
- The relay never sees plaintext crash data
- Receiver (developer) is the only party that can decrypt reports
- Local crash caches should be stored in app-private directories

## Crash Report Payload Schema

All SDKs must produce crash reports conforming to this JSON schema:

```json
{
  "message": "Error description (string, required)",
  "stack": "Full stack trace (string, optional)",
  "environment": "production|staging|development|test (string, optional)",
  "release": "1.0.0+42 (string, optional)",
  "app_id": "com.example.myapp (string, optional)",
  "platform": "android|flutter|electron|javascript|rust|go|python|react-native (string, optional)"
}
```

- `message`: The exception message or error description
- `stack`: Full stack trace as a single string with newlines
- Stack traces must use the platform's native format (Java `at` frames, Dart `#N` frames, JS `at` frames, etc.)
- Do NOT strip or truncate stack traces at the SDK level — the receiver handles grouping

### Transport Kinds

| Kind | Purpose | Payload |
|------|---------|---------|
| 10420 | Direct crash report | `DirectPayload` wrapping the JSON above |
| 10421 | Chunked manifest | `ManifestPayload` with chunk IDs |
| 10422 | Chunk | `ChunkPayload` with index + data |

Use kind 10420 for payloads under 40KB. Above that, chunk via kind 10421/10422.

## Crash Grouping (Fingerprint Algorithm)

The Rust receiver groups crashes using a Rollbar-style fingerprint. SDKs do not need to compute fingerprints — this is server-side. But understanding the algorithm helps when debugging grouping issues.

### Algorithm

```text
input = exception_type + "\n"
for each line in stack_trace:
    if is_stack_frame(line) and is_in_app(frame):
        input += normalized_filename + ":" + method_name + "\n"
if no in-app frames found:
    input += normalize_message(message)    # strip hex, IPs, timestamps, large numbers
fingerprint = "v1:" + hex(sha256(input))[..32]
```

### What makes frames "in-app"

Excluded (framework/runtime) frames:
- `dart:async/*`, `dart:core/*`, `dart:io/*`
- `flutter/*`, `packages/flutter/*`
- `java.lang.*`, `java.util.*`, `android.*`, `androidx.*`, `dalvik.*`, `kotlin.*`
- `node:*`, `internal/*`
- `<anonymous>`, `native`, `Unknown Source`

### What gets stripped

- **Line numbers** — they change with unrelated edits
- **Frame indices** — `#0`, `#1`, etc.
- **Memory addresses** — `0x7fff...`
- In message fallback: hex values, IPs, timestamps, numbers > 5 digits

### Group titles

Human-readable titles are computed as: `"ExceptionType in method (file)"` using the first in-app frame. Falls back to `"ExceptionType: first line of message"`.

## SDK Design Contract

Every platform SDK must implement these capabilities:

### Required

1. **Opt-in consent** — No data sent without explicit `enable()` call
2. **Uncaught exception handler** — Hook into the platform's crash mechanism
3. **Offline caching** — Cache reports locally when network is unavailable; send on next launch
4. **Background sending** — Never block the main/UI thread for crash transmission
5. **NIP-17 gift wrap** — Encrypt via NIP-44, wrap per NIP-59, send to configured relay(s)
6. **Payload compression** — Gzip payloads > 1KB before wrapping (see `compression.rs`)
7. **Chunking** — Payloads > 40KB must be chunked (kinds 10421/10422)

### Recommended

8. **`beforeSend` callback** — Let integrators inspect/modify/drop reports before transmission
9. **Breadcrumbs** — Record a trail of events (navigation, HTTP, UI) leading up to the crash (max 100)
10. **Context/tags** — Allow setting key-value metadata (app version, OS version, device model)
11. **Rate limiting** — Max 10 reports per minute per SDK instance to prevent flood
12. **Non-fatal reporting** — `reportError(exception)` for caught exceptions

### Payload Limits

- Maximum crash content: **500KB** before compression
- Maximum compressed payload for direct send: **40KB**
- Above 40KB: chunk into 32KB pieces via kind 10421/10422
- Maximum breadcrumbs per report: **100 entries**

## Symbolication

The Rust receiver supports server-side symbolication. SDKs must tag reports for symbol lookup:

### Required metadata for symbolication

- `platform`: Identifies which symbolicator to use
- `app_id`: Package name / bundle ID (e.g., `com.example.myapp`)
- `release`: Version string (e.g., `1.0.0+42`)

### Mapping file upload

Mapping files are stored in: `<mappings_dir>/<platform>/<app_id>/<version>/<file>`

| Platform | File Type | Upload Tool |
|----------|-----------|-------------|
| Android | `mapping.txt` (ProGuard/R8) | CI upload or manual |
| Flutter/Dart | `.symbols` | CI upload |
| JavaScript/Electron | `.map` (source maps) | CI upload |
| React Native | `.map` (Hermes + source maps) | CI upload |

## Coding Requirements

### 1. Documentation

All public functions must have docstrings in the platform's standard format:

- **Kotlin**: KDoc (`/** ... */`)
- **Dart**: dartdoc (`/// ...`)
- **TypeScript/Electron**: JSDoc (`/** ... */`)
- **Rust**: rustdoc (`/// ...` or `//!`)
- **Go**: godoc (comment before declaration)
- **Python**: docstrings (`"""..."""`)

Document: purpose, parameters, return values, thrown exceptions.

### 2. Commit Guidelines

#### Logically Distinct Commits

Each commit should represent a single logical change:
- One feature, fix, or refactor per commit
- Avoid mixing unrelated changes
- Keep commits focused and reviewable

#### Standalone Commits

Commits must be independently removable:
- No forward references to uncommitted code
- Each commit should compile and pass tests
- Avoid tight coupling between commits in a PR

#### Cherry-Pick for Attribution

When incorporating work from other branches or contributors:
- Use `git cherry-pick` to preserve original authorship
- Do not copy code manually and re-commit under different author
- Reference original commits in PR descriptions

### 3. Changelog

All user-facing changes require a CHANGELOG.md entry:

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Modified behavior description

### Fixed
- Bug fix description
```

### 4. Commit Message Format

```
<type>: <short description>

<optional body explaining what and why>

<optional footer>
Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## NIP-17/59 Implementation Notes

### Critical Implementation Requirements

Based on integration testing with 0xchat and other clients:

1. **Rumor must include `sig: ""`** - Empty string, not omitted
2. **Rumor must include computed `id`** - SHA256 of serialized event
3. **Event serialization order**: `[0, pubkey, created_at, kind, tags, content]`
4. **Seal is signed** by the sender's key
5. **Gift wrap is signed** by an ephemeral key

### Event ID Computation

```text
id = sha256(json([0, pubkey, created_at, kind, tags, content]))
```

Returns lowercase hex string (64 characters).

## Lessons Learned

### CHK Encryption Compatibility (Critical)

**Problem**: All SDKs implemented CHK (Content Hash Key) encryption differently from the Rust reference implementation, causing complete decryption failure.

**Root Cause**: Each SDK used its own interpretation of "encrypt with content hash":
- Some used AES-256-CBC with random IV
- Others omitted HKDF key derivation
- Ciphertext format varied (IV position, tag handling)

**The Correct Algorithm** (must match `hashtree-core` exactly):

```text
1. content_hash = SHA256(plaintext)
2. key = HKDF-SHA256(
     ikm: content_hash,
     salt: "hashtree-chk",
     info: "encryption-key",
     length: 32
   )
3. ciphertext = AES-256-GCM(
     key: key,
     nonce: 12 zero bytes,
     plaintext: data
   )
4. output = [ciphertext][16-byte auth tag]
```

**Why each component matters**:

| Component | Purpose | If Wrong |
|-----------|---------|----------|
| HKDF | Derives encryption key from content hash | Key mismatch → decryption fails |
| Salt `"hashtree-chk"` | Domain separation | Different key → decryption fails |
| Info `"encryption-key"` | Key purpose binding | Different key → decryption fails |
| Zero nonce | Safe for CHK (same key = same content) | Different ciphertext → verification fails |
| AES-GCM | Authenticated encryption | Different algorithm → decryption fails |

**Why zero nonce is safe**: CHK is convergent encryption - the same plaintext always produces the same key. Since the key is deterministic, using a random nonce would make ciphertext non-deterministic, breaking content-addressable storage. Zero nonce is safe because the key is never reused with different content.

**Verification checklist for new implementations**:
1. Generate test vector in Rust: `cargo test chunking -- --nocapture`
2. Encrypt same plaintext in your SDK
3. Compare: content hash, derived key, ciphertext must be byte-identical
4. Decrypt Rust ciphertext in your SDK (and vice versa)

**Platform-specific libraries**:

| Platform | HKDF | AES-GCM |
|----------|------|---------|
| Rust | `hashtree-core` | (built-in) |
| Dart | `pointycastle` HKDFKeyDerivator | `pointycastle` GCMBlockCipher |
| Kotlin | Manual HMAC-SHA256 | `javax.crypto` AES/GCM/NoPadding |
| Go | `golang.org/x/crypto/hkdf` | `crypto/cipher` NewGCM |
| Python | `cryptography` HKDF | `cryptography` AESGCM |
| TypeScript (Node) | `crypto` hkdfSync | `crypto` aes-256-gcm |
| TypeScript (RN) | `@noble/hashes/hkdf` | `@noble/ciphers/aes` gcm |

## Testing

### Unit Tests

- All new code must have corresponding unit tests
- Test edge cases: empty strings, null fields, malformed input
- Test interop: Rust receiver must handle all SDK payload formats
- Mock external dependencies (relays, network)

### Critical Test Scenarios

- Same exception + different stack = different fingerprints
- Same stack + different line numbers = same fingerprint
- URL-only content → `is_crash = false`, excluded from groups
- Dart, Java, JS frame parsing produces correct (method, file) pairs
- Gift wrap round-trip: encrypt in SDK → decrypt in Rust receiver
- Chunking round-trip: chunk → reassemble → decompress → original payload
- Compression: payloads > 1KB are compressed, < 1KB are sent raw

### Interoperability Testing

NIP-17 messages should be tested against multiple clients:
- 0xchat
- Amethyst
- Other NIP-17 compatible clients

## Project Structure

```
bugstr/
├── android/                      # Android/Kotlin implementation
│   ├── src/main/java/com/bugstr/
│   ├── bugstr-nostr-crypto/      # NIP-17/44/59 (Kotlin)
│   ├── CHANGELOG.md
│   └── README.md
├── electron/                     # Electron desktop app implementation
│   ├── src/
│   ├── CHANGELOG.md
│   └── README.md
├── dart/                         # Flutter/Dart implementation
│   ├── lib/src/
│   ├── CHANGELOG.md
│   └── README.md
├── rust/                         # Rust CLI + receiver + web dashboard
│   ├── src/
│   │   ├── storage.rs            # SQLite storage, fingerprinting, grouping
│   │   ├── web.rs                # REST API + embedded dashboard
│   │   ├── symbolication/        # Server-side symbolication
│   │   ├── chunking.rs           # Payload chunking (CHK)
│   │   └── compression.rs        # Gzip compression
│   ├── static/index.html         # Dashboard frontend
│   ├── CHANGELOG.md
│   └── README.md
├── go/                           # Go library
│   ├── bugstr.go
│   └── README.md
├── python/                       # Python library
│   ├── bugstr/
│   └── README.md
├── react-native/                 # React Native library
│   ├── src/
│   └── README.md
├── test-vectors/                 # Shared NIP-17 test vectors
│   └── nip17-gift-wrap.json
├── AGENTS.md                     # This file (shared guidelines)
├── LICENSE
└── README.md                     # Monorepo overview
```

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
