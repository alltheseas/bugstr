# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Transport module for crash report delivery with new event kinds:
  - Kind 10420: Direct crash report transport (≤50KB payloads)
  - Kind 10421: Hashtree manifest for large crash reports
  - Kind 10422: CHK-encrypted chunk data
- CHK (Content Hash Key) chunking module for large payload support:
  - `chunk_payload()` splits and encrypts payloads using CHK encryption
  - `reassemble_payload()` decrypts and reconstructs original data
  - Root hash computed from chunk keys ensures integrity
  - Secure when manifest delivered via NIP-17 gift wrap
- Receiver now supports kind 10420 in addition to legacy kind 14
- Receiver fetches and reassembles chunked crash reports from kind 10421 manifests
- `DirectPayload`, `ManifestPayload`, `ChunkPayload` types for transport layer
- `TransportKind` enum for automatic transport selection based on payload size
- `hashtree-core` dependency for CHK encryption primitives
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

### Changed
- None

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
