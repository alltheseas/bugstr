# Bugstr for Electron

Zero-infrastructure crash reporting for Electron desktop apps.

<img width="256" height="256" alt="Bugstr logo" src="https://github.com/user-attachments/assets/1c3c17dc-6a6d-4881-9ac7-32217bd4e1ad" />

## Installation

```bash
npm install bugstr-electron
```

**Peer dependency:** Electron >= 20.0.0

## Quick Start

```ts
// main.ts (main process)
import { init, processPendingReports } from 'bugstr-electron';
import { app } from 'electron';

// Initialize early, before app.whenReady()
init({
  developerPubkey: 'npub1...',
  environment: 'production',
  release: app.getVersion(),
});

app.whenReady().then(async () => {
  // Process any crashes from previous session
  await processPendingReports();

  // ... create windows
});
```

## How It Works

```
Crash → Cache locally → App exits → App restarts → Show consent dialog → User approves → Send encrypted DM
```

1. **Crash occurs** - Exception handler captures error and stack trace
2. **Local cache** - Report saved to disk via `electron-store` (no network)
3. **App restarts** - On next launch, `processPendingReports()` checks for cached crashes
4. **User consent** - Native Electron dialog asks permission to send
5. **NIP-17 DM** - Encrypted, gift-wrapped message sent to developer's npub

## Configuration

```ts
init({
  // Required: Your npub or hex pubkey
  developerPubkey: 'npub1...',

  // Optional: Custom relays (defaults: damus, primal, nos.lol)
  relays: ['wss://relay.damus.io', 'wss://relay.primal.net'],

  // Optional: Environment tag
  environment: 'production',

  // Optional: Release version
  release: '1.0.0',

  // Optional: Custom redaction patterns
  redactPatterns: [
    /api_key=[^&]+/g,
  ],

  // Optional: Modify payload before sending (return null to drop)
  beforeSend: (payload) => {
    return payload;
  },

  // Optional: Custom confirmation dialog
  confirmSend: async (summary) => {
    // Return true to send, false to cancel
    return await myCustomDialog(summary);
  },
});
```

## API

### `init(config)`

Initialize Bugstr. Call early in your main process.

### `processPendingReports()`

Process any cached crash reports from previous sessions. Call after `app.whenReady()`.

### `captureException(error)`

Manually capture an exception. The report is cached and will be sent on next app launch.

```ts
try {
  riskyOperation();
} catch (err) {
  captureException(err);
}
```

### `captureMessage(message)`

Capture a message as a crash report.

```ts
captureMessage('Something unexpected happened');
```

### `clearPendingReports()`

Clear all cached crash reports without sending.

## Default Relays

| Relay | Max Event Size | Notes |
|-------|----------------|-------|
| `wss://relay.damus.io` | 64 KB | strfry defaults |
| `wss://relay.primal.net` | 64 KB | strfry defaults |
| `wss://nos.lol` | 128 KB | Fallback |

## Privacy Features

- **NIP-17 Gift Wrap**: Crash reports are encrypted with NIP-44 and wrapped per NIP-59
- **Random Timestamps**: Created_at randomized within ±2 days to prevent timing analysis
- **Ephemeral Keys**: Each gift wrap uses a fresh random key
- **Auto-expiration**: Reports expire after 30 days (NIP-40)
- **Redaction**: Sensitive patterns (tokens, keys, invoices) are auto-redacted

## Default Redaction

These patterns are automatically redacted from crash reports:
- Cashu tokens (`cashuA...`)
- Lightning invoices (`lnbc...`)
- Nostr public keys (`npub1...`)
- Nostr private keys (`nsec1...`)
- Mint URLs

## Scripts

- `npm run build` – Build ESM + CJS + types
- `npm run test` – Run tests
- `npm run lint` – Lint code

## Other Platforms

See the [monorepo root](../) for other platform implementations:
- [Android/Kotlin](../android/)
- [Flutter/Dart](../dart/)
- [React Native](../react-native/)
- [Rust](../rust/)
- [Go](../go/)
- [Python](../python/)

## License

[MIT](../LICENSE)
