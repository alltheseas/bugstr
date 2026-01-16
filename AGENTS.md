# BugStr Agent Guidelines

This document provides guidelines for AI agents and human contributors working on BugStr.

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

## Coding Requirements

### 1. Documentation

Ensure docstring coverage for any code added or modified:

- **Kotlin**: Use KDoc format (`/** ... */`)
- **Dart**: Use dartdoc format (`/// ...`)
- **TypeScript/Electron**: Use JSDoc format (`/** ... */`)
- **Rust**: Use rustdoc format (`/// ...` or `//!`)
- **Go**: Use godoc format (comment before declaration)
- **Python**: Use docstrings (`"""..."""`)

All public classes, methods, and non-trivial functions must have documentation explaining:
- Purpose and behavior
- Parameters and return values
- Exceptions that may be thrown
- Usage examples for complex APIs

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

#### Human Readable Code

All code must be reviewable by human developers:
- Clear, descriptive variable and function names
- Appropriate comments for non-obvious logic
- Consistent formatting per language conventions

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
Signed-off-by: name <email>
Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
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

```
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

```
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

- All new code should have corresponding unit tests
- Test edge cases and error conditions
- Mock external dependencies

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
├── rust/                         # Rust CLI + library
│   ├── src/
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
