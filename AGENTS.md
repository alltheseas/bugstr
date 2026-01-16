# BugStr Agent Guidelines

This document provides guidelines for AI agents and human contributors working on BugStr.

## Project Overview

BugStr is a privacy-focused crash reporting library for Nostr applications. It uses NIP-17 gift-wrapped encrypted messages to deliver crash reports with user consent.

### Supported Platforms

| Platform | Directory | Status |
|----------|-----------|--------|
| Android/Kotlin | `android/` | Production |
| TypeScript | `typescript/` | Production |
| Flutter/Dart | `dart/` | Planned |

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
- **TypeScript**: Use JSDoc format (`/** ... */`)

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

### Critical Compliance Requirements

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
│   │   ├── BugstrCrashHandler.kt
│   │   ├── BugstrCrashReportCache.kt
│   │   ├── BugstrReportAssembler.kt
│   │   ├── BugstrAnrWatcher.kt
│   │   └── ui/BugstrCrashPrompt.kt
│   ├── bugstr-nostr-crypto/      # NIP-17/44/59 (Kotlin)
│   ├── CHANGELOG.md
│   └── README.md
├── typescript/                   # TypeScript implementation
│   ├── src/
│   ├── CHANGELOG.md
│   └── README.md
├── dart/                         # Flutter/Dart (planned)
├── test-vectors/                 # Shared NIP-17 compliance tests
│   └── nip17-gift-wrap.json
├── AGENTS.md                     # This file (shared guidelines)
├── LICENSE
└── README.md                     # Monorepo overview
```
