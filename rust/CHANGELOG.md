# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Symbolication module with support for 7 platforms:
  - Android (ProGuard/R8 mapping.txt parsing)
  - JavaScript/Electron (source map support)
  - Flutter/Dart (flutter symbolize integration)
  - Rust (backtrace parsing)
  - Go (goroutine stack parsing)
  - Python (traceback parsing)
  - React Native (Hermes bytecode + JS source maps)
- `bugstr symbolicate` CLI command for symbolicating stack traces
- `POST /api/symbolicate` web API endpoint for dashboard integration
- `--mappings` option for `bugstr serve` to enable symbolication
- `MappingStore` for organizing mapping files by platform/app/version
- Fingerprint-based crash grouping (Rollbar-style algorithm):
  - `compute_fingerprint()` — SHA256 of exception type + all in-app file:method pairs, line numbers stripped
  - `compute_group_title()` — human-readable titles like "StateError in build (profile_screen.dart)"
  - Dart, Java, and JavaScript stack frame parsing with in-app detection
  - Message normalization fallback (strips hex, IPs, timestamps, large numbers)
- Non-crash data filtering: URL-only content (blossom URLs) marked `is_crash = false` and excluded from groups
- Database migration: automatic `ALTER TABLE` for existing databases, fingerprint backfill at startup
- `GET /api/groups/:fingerprint` endpoint for drill-down by fingerprint
- Dashboard groups view shows human-readable titles and sample messages

### Changed
- Crash groups now aggregate by fingerprint instead of exception type only
- Groups API returns `fingerprint`, `title`, `sample_message` fields
- Dashboard fetches group drill-down by fingerprint instead of exception type
- `count()` now returns only actual crash count (excludes non-crash data)

### Fixed
- ProGuard/R8 parsing now supports `:origStart:origEnd` line range format
- Overloaded/inlined methods with same obfuscated name now correctly differentiated by line range
- Original line numbers preserved when method mapping is missing or line range doesn't match
- Path validation in `MappingStore.save_mapping` prevents directory traversal attacks

## [0.1.0] - 2025-01-15

### Added
- Initial release
- Crash report receiver with NIP-17 gift wrap decryption
- Web dashboard for viewing and grouping crash reports
- SQLite storage with deduplication
- Gzip compression support for large payloads
- `bugstr listen` command for terminal-only crash monitoring
- `bugstr serve` command for web dashboard with crash collection
- `bugstr pubkey` command to display receiver public key
