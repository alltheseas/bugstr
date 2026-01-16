# Changelog

All notable changes to the Dart implementation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Full Bugstr client with `init()` and `captureException()` API
- NIP-17 gift-wrapped crash reports using `ndk` package
- `BugstrConfig` with default relays (damus, primal, nos.lol)
- `CrashPayload` with auto-redaction for sensitive data (nsec, cashu tokens, etc.)
- Auto-install of Flutter error handlers on initialization
- `beforeSend` hook to modify/filter payloads before sending
- `confirmSend` hook for user consent dialogs
- Gzip compression for payloads over 1 KB
- Random timestamps (±2 days) for timing analysis protection
- Platform and device info in crash reports

### Removed
- Placeholder skeleton files (bugstr_crash_handler.dart, etc.)

### Notes
- Uses `ndk` package for NIP-44 encryption and NIP-59 gift wrap
- Tested relay compatibility: damus (1MB), primal (1MB), nos.lol (128KB)
