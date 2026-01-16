# Changelog

All notable changes to the TypeScript implementation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Moved to bugstr monorepo from standalone bugstr-ts repository

### Fixed
- `clearPendingReports()` no longer throws when called before `init()`

## [0.1.0] - 2025-01-15

### Added
- Initial release
- `init()` for configuration (developer npub, relays, env/release, redaction, confirm hook)
- `captureException()` for manual error capture
- Automatic window hooks (error/unhandledrejection)
- NIP-17 gift wrap delivery via nostr-tools
- Default redaction patterns (cashu tokens, LN invoices, npub/nsec, mint URLs)
- Confirm prompt before sending (customizable via `confirmSend`)
