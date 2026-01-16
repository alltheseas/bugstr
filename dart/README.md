# Bugstr for Flutter/Dart

Zero-infrastructure crash reporting — no server to run, no SaaS to pay for.

## Installation

```yaml
dependencies:
  bugstr: ^0.1.0
```

## Quick Start

```dart
import 'package:bugstr/bugstr.dart';

void main() {
  Bugstr.init(
    developerPubkey: 'npub1...',
    environment: 'production',
    release: '1.0.0',
  );

  runApp(MyApp());
}
```

## Manual Capture

```dart
try {
  riskyOperation();
} catch (e, stack) {
  Bugstr.captureException(e, stack);
}
```

## Configuration Options

```dart
Bugstr.init(
  // Required: Your npub or hex pubkey
  developerPubkey: 'npub1...',

  // Optional: Custom relays (defaults to damus, primal, nos.lol)
  relays: ['wss://relay.damus.io', 'wss://relay.primal.net'],

  // Optional: Environment tag
  environment: 'production',

  // Optional: Release version
  release: '1.0.0',

  // Optional: Custom redaction patterns
  redactPatterns: [
    RegExp(r'api_key=[^&]+'),
  ],

  // Optional: Modify payload before sending
  beforeSend: (payload) {
    // Return null to drop, or modify and return
    return payload;
  },

  // Optional: Confirm with user before sending
  confirmSend: (message, stackPreview) async {
    return await showConfirmDialog(message);
  },
);
```

## Default Relays

| Relay | Max Event Size | Notes |
|-------|----------------|-------|
| `wss://relay.damus.io` | 64 KB | strfry defaults |
| `wss://relay.primal.net` | 64 KB | strfry defaults |
| `wss://nos.lol` | 128 KB | Fallback |

## Compression

Payloads over 1 KB are automatically gzip compressed:

```json
{
  "v": 1,
  "compression": "gzip",
  "payload": "<base64-encoded-gzip>"
}
```

## Privacy Features

- **NIP-17 Gift Wrap**: Crash reports are encrypted with NIP-44 and wrapped per NIP-59
- **Random Timestamps**: Created_at randomized within ±2 days to prevent timing analysis
- **Ephemeral Keys**: Each gift wrap uses a fresh random key
- **Auto-expiration**: Reports expire after 30 days (NIP-40)
- **Redaction**: Sensitive patterns (tokens, keys, invoices) are auto-redacted

## How It Works

1. **Crash occurs** → Flutter/Dart error handler captures it
2. **Payload built** → Stack trace redacted and truncated
3. **User consent** → Optional confirmation dialog
4. **Gift wrapped** → Encrypted with NIP-44, wrapped per NIP-59
5. **Published** → Sent to relays as kind 1059 event

## NIP Compliance

- **NIP-01**: Event structure and ID computation
- **NIP-17**: Private Direct Messages (kind 14 rumors)
- **NIP-44**: Versioned Encryption (v2)
- **NIP-59**: Gift Wrap (rumor → seal → gift wrap)
- **NIP-40**: Expiration Timestamp

## Other Platforms

- [Android/Kotlin](../android/)
- [TypeScript](../typescript/)
- [Rust](../rust/)
- [Go](../go/)
- [Python](../python/)
- [React Native](../react-native/)

## License

[MIT](../LICENSE)
