# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- AGENTS.md with contributor guidelines and NIP-17/59 compliance notes
- CHANGELOG.md for tracking version history
- `UnsignedNostrEvent.computeId()` method for NIP-01 compliant event ID computation
- Unit tests for `UnsignedNostrEvent` serialization and ID computation
- NIP-17 crypto module documentation in README
- Flutter/Dart listed as planned platform

### Changed
- README now correctly states "four building blocks" instead of "three"

### Fixed
- `UnsignedNostrEvent.toJson()` now includes `id` and `sig` fields for NIP-17 compliance
- Some clients (e.g., 0xchat) rejected messages without these fields

## [0.1.0] - 2025-01-15

### Added
- Initial release extracted from Amethyst
- BugstrCrashHandler for capturing uncaught exceptions
- BugstrCrashReportCache for local crash storage with rotation
- BugstrReportAssembler for formatting crash reports
- BugstrAnrWatcher for ANR detection
- BugstrCrashPrompt Compose dialog for user consent
- NIP-17 gift wrap support via bugstr-nostr-crypto module
- NIP-44 encryption with Quartz adapters
