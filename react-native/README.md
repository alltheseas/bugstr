# Bugstr React Native SDK

Zero-infrastructure crash reporting for React Native via NIP-17 encrypted DMs.

## Installation

```bash
npm install @bugstr/react-native nostr-tools
# or
yarn add @bugstr/react-native nostr-tools
```

## Usage

### Basic Setup

```tsx
import * as Bugstr from '@bugstr/react-native';

// Initialize early in your app (e.g., index.js or App.tsx)
Bugstr.init({
  developerPubkey: 'npub1...', // Your receiver pubkey
  environment: 'production',
  release: '1.0.0',
});
```

### Error Boundary

Wrap your app to catch React component errors:

```tsx
import * as Bugstr from '@bugstr/react-native';

export default function App() {
  return (
    <Bugstr.ErrorBoundary
      fallback={<Text>Something went wrong</Text>}
      onError={(error) => console.log('Error captured:', error)}
    >
      <YourApp />
    </Bugstr.ErrorBoundary>
  );
}
```

### Manual Capture

```tsx
try {
  await riskyOperation();
} catch (error) {
  Bugstr.captureException(error);
}

// Or capture a message
Bugstr.captureMessage('Something unexpected happened');
```

### Custom Confirmation

```tsx
Bugstr.init({
  developerPubkey: 'npub1...',
  confirmSend: async (summary) => {
    // Show your own UI
    return await showCustomDialog(summary.message);
  },
});
```

### Auto-send (no confirmation)

For apps where you don't want user confirmation:

```tsx
Bugstr.init({
  developerPubkey: 'npub1...',
  useNativeAlert: false, // Disable native Alert
  confirmSend: () => true, // Always send
});
```

## Features

- **Error Boundary** component for React errors
- **Global error handler** for uncaught JS exceptions
- **Native Alert** for user confirmation (configurable)
- **Platform info** included in reports (iOS/Android)
- **Automatic redaction** of sensitive data
- **NIP-17 encryption** - end-to-end encrypted
- **30-day expiration** on relays

## Configuration

| Property | Type | Description |
|----------|------|-------------|
| `developerPubkey` | `string` | Required. Recipient's npub or hex pubkey |
| `relays` | `string[]` | Relay URLs (default: damus.io, nos.lol) |
| `environment` | `string` | Environment tag |
| `release` | `string` | Version tag |
| `redactPatterns` | `RegExp[]` | Custom redaction patterns |
| `beforeSend` | `function` | Modify/filter payloads |
| `confirmSend` | `function` | Custom confirmation logic |
| `useNativeAlert` | `boolean` | Use native Alert for confirmation (default: true) |

## Payload

Reports include:

```json
{
  "message": "Error message",
  "stack": "Stack trace...",
  "timestamp": 1234567890,
  "environment": "production",
  "release": "1.0.0",
  "platform": "ios",
  "deviceInfo": {
    "os": "ios",
    "version": "17.0"
  }
}
```

## License

MIT
