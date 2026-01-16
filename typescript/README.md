# Bugstr-TS (POC)

🚧 ```Proceed with caution: Bugstr-TS is proof of concept stage, and has not been reviewed by a professional developer``` 🚧

Minimal browser SDK for sending crash reports as [NIP-17 giftwrapped DMs](https://github.com/nostr-protocol/nips/blob/master/17.md) using [nostr-tools](https://github.com/nbd-wtf/nostr-tools). Ships:
- `init` – configure Bugstr (developer npub, relays, env/release, redaction, confirm hook)
- `captureException` – build payload, redact, confirm with user, and send via NIP-17
- Window hooks (error/unhandledrejection) wired automatically after `init`

  <img width="256" height="256" alt="image" src="https://github.com/user-attachments/assets/1c3c17dc-6a6d-4881-9ac7-32217bd4e1ad" />

## Install
```bash
npm install bugstr-ts
```

## Usage
```ts
import { init, captureException } from "bugstr-ts";

init({
  developerPubkey: "npub1...", // target npub for NIP-17 DM
  relays: ["wss://relay.damus.io", "wss://nos.lol"],
  environment: "development",
  release: "dev",
  // Optional: beforeSend, confirmSend, redactPatterns
});

// Manual capture
captureException(new Error("bugstr test crash"));
```

### Defaults
- Redaction: cashu tokens, LN invoices, npub/nsec, mint URLs.
- Confirm prompt: `window.confirm` if no `confirmSend` provided.
- NIP-17 delivery: nip44 seal and giftwrap, publishes to relays in order, stops after first OK.

### Manual testing in the browser
After calling `init`, run in devtools:
```js
window.dispatchEvent(new ErrorEvent("error", { error: new Error("bugstr test crash") }));
```
Expect a confirm dialog. On OK, console logs:
- `Bugstr: user confirmed send`
- `Bugstr: send completed (received OK from 1 relay, last=<relay>)`
And the target npub should receive a NIP-17 DM containing the JSON payload (minified stack).

Redaction check:
```js
window.dispatchEvent(new ErrorEvent("error", { error: new Error("cashuA123 npub1abc lnbc1xyz") }));
```
Payload should show `[redacted]` in place of secrets.

## Scripts
- `npm run build` – tsup ESM+CJS + types
- `npm run test` – vitest (unit tests TBD)
- `npm run lint`

## Notes
- Browser-first; relies on `nostr-tools` nip44 and `Relay.connect`.
- Early return/guard clauses used to avoid deep nesting.

## Other Platforms

See the [monorepo root](../) for other platform implementations:
- [Android/Kotlin](../android/)
- Flutter/Dart (planned)
