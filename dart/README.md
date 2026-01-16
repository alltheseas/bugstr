# Bugstr for Flutter/Dart

Privacy-focused crash reporting for Flutter/Dart apps using NIP-17 gift-wrapped DMs.

> **Status: Skeleton** - This package provides the API structure but is not yet implemented. Contributions welcome!

## Planned Features

- `BugstrCrashHandler` - Captures uncaught Flutter/Dart exceptions
- `BugstrCrashReportCache` - Local file-based crash storage with rotation
- `BugstrReportAssembler` - Formats crash reports with metadata
- `Nip17PayloadBuilder` - NIP-17/44/59 gift wrap building

## Planned Usage

```dart
import 'package:bugstr/bugstr.dart';

void main() {
  BugstrCrashHandler.install(
    cache: BugstrCrashReportCache(maxReports: 3),
    assembler: BugstrReportAssembler(
      appName: 'My App',
      appVersion: '1.0.0',
    ),
  );
  runApp(MyApp());
}
```

## NIP Compliance

The implementation will follow:
- **NIP-17** - Private Direct Messages (kind 14 rumors)
- **NIP-44** - Versioned Encryption (v2)
- **NIP-59** - Gift Wrap (rumor → seal → gift wrap)
- **NIP-40** - Expiration Timestamp

**Important**: Rumors must include `id` (computed) and `sig: ""` (empty string) per spec.

## Contributing

See the [monorepo AGENTS.md](../AGENTS.md) for contributor guidelines.

## Other Platforms

- [Android/Kotlin](../android/)
- [TypeScript](../typescript/)
