# Bugstr

Private crash reporting for apps that respect their users.

End-to-end encrypted. User-consented. Self-hostable as a single binary. No third party ever sees your crash data — not the relay, not a SaaS vendor, not Google.

<img width="256" height="256" alt="Bugstr logo" src="https://github.com/user-attachments/assets/1c3c17dc-6a6d-4881-9ac7-32217bd4e1ad" />

## Why Bugstr?

|  | Bugstr | Sentry | Crashlytics |
|--|--------|--------|-------------|
| Who sees crash data? | **Only you** | Sentry servers | Google |
| E2E encrypted? | **Yes** (NIP-44) | No | No |
| User consent before sending? | **Yes** (opt-in) | No | No |
| Data retention | **Auto-expires** (30 days) | Indefinite | 90 days |
| Vendor lock-in | **None** (open protocol) | Their infrastructure | Firebase |
| Self-hostable? | **Single binary** | 10+ Docker services | No |
| Cost to get started | **Free** | Free (limited) | Free (Google ToS) |

## How It Works

```text
Crash → Cache locally → App restart → User consents → Encrypted report sent → Auto-expires in 30 days
```

1. **Crash occurs** — Exception handler captures stack trace, saved to disk. No network call.
2. **User decides** — On next launch, a consent dialog lets the user choose whether to send. No data leaves the device without explicit approval.
3. **Encrypted delivery** — Report is encrypted end-to-end with [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) and gift-wrapped via [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md). The relay transporting it cannot read the content.
4. **You decrypt** — Only your Nostr private key can decrypt the report. No third party ever sees it.
5. **Auto-expiration** — Reports are deleted from relays after 30 days via [NIP-40](https://github.com/nostr-protocol/nips/blob/master/40.md).

## Privacy by Design

- **No PII collected by default** — No IP addresses, emails, device IDs, or usernames
- **Opt-in, not opt-out** — Users explicitly consent before any data leaves their device
- **End-to-end encrypted** — NIP-44 (ChaCha20, HMAC-SHA256, [Cure53 audited](https://cure53.de/audit-report_nip44-implementations.pdf))
- **Zero-knowledge relay** — The relay transports ciphertext. It never sees plaintext crash data.
- **Ephemeral sender identity** — Each report uses a fresh keypair. Reports cannot be correlated to a user.
- **Auto-expiring** — Reports self-delete from relays after 30 days
- **Open source** — Every line of code is auditable
- **No vendor lock-in** — Built on the open Nostr protocol. If bugstr disappears, the protocol still works.

## Platforms

| Platform | Directory | Tested |
|----------|-----------|--------|
| Android/Kotlin | [`android/`](android/) | ✅ [Zapstore](https://github.com/zapstore/zapstore/pull/272) |
| Electron | [`electron/`](electron/) | Community testing |
| Flutter/Dart | [`dart/`](dart/) | Community testing |
| Rust | [`rust/`](rust/) | Community testing |
| Go | [`go/`](go/) | Community testing |
| Python | [`python/`](python/) | Community testing |
| React Native | [`react-native/`](react-native/) | Community testing |

## Receiver Dashboard

The Rust receiver includes a web dashboard with:

- **Fingerprint-based crash grouping** — Crashes grouped by stack trace similarity (Rollbar-style algorithm), not just exception type
- **Server-side symbolication** — Supports Android (ProGuard/R8), Flutter, Electron/JS, React Native, Rust, Go, Python
- **Human-readable group titles** — e.g. "StateError in _AboutSection.build (profile_screen.dart)"
- **Single binary** — No Docker, no Kafka, no Redis. Just `bugstr serve`.

```bash
# Start the receiver
bugstr serve --mappings ./mappings

# With symbolication for Android
bugstr symbolicate --platform android --input crash.txt \
  --app-id com.example.app --version 1.0.0
```

## Default Relays

| Relay | Notes |
|-------|-------|
| `wss://relay.damus.io` | strfry defaults |
| `wss://relay.primal.net` | strfry defaults |
| `wss://nos.lol` | Fallback relay |

Override via the `relays` configuration option in each SDK.

## Nostr Protocol

All implementations use these NIPs:

- [**NIP-17**](https://github.com/nostr-protocol/nips/blob/master/17.md) — Private Direct Messages (kind 14 rumors)
- [**NIP-44**](https://github.com/nostr-protocol/nips/blob/master/44.md) — Versioned Encryption (v2, ChaCha20 + HMAC-SHA256)
- [**NIP-59**](https://github.com/nostr-protocol/nips/blob/master/59.md) — Gift Wrap (rumor → seal → gift wrap)
- [**NIP-40**](https://github.com/nostr-protocol/nips/blob/master/40.md) — Expiration Timestamp

### Implementation Notes

Per NIP-17, rumors (kind 14) must include:
- `id` — SHA256 hash of `[0, pubkey, created_at, kind, tags, content]`
- `sig: ""` — Empty string (not omitted)

## Size Limits & Compression

Most relays enforce a **64 KB** event size limit. Bugstr handles this automatically:

| Payload Size | Behavior |
|--------------|----------|
| < 1 KB | Sent as plain JSON |
| >= 1 KB | Compressed with gzip, base64-encoded |

Gzip achieves **70-90% reduction** on stack traces. With compression, most crash reports fit well within relay limits.

<details>
<summary>Compression format details</summary>

Large payloads are wrapped in a versioned envelope:

```json
{
  "v": 1,
  "compression": "gzip",
  "payload": "<base64-encoded-gzip-data>"
}
```

Stack traces are automatically truncated to fit within limits (default: 200 KB before compression). The receiver automatically detects and decompresses payloads.

| Original Size | Compressed | Reduction |
|---------------|------------|-----------|
| 10 KB | ~1-2 KB | ~80-90% |
| 50 KB | ~5-10 KB | ~80-90% |
| 200 KB | ~20-40 KB | ~80-85% |

</details>

## Symbolication

The Rust receiver includes built-in symbolication for 7 platforms:

| Platform | Mapping File | Notes |
|----------|--------------|-------|
| Android | `mapping.txt` | ProGuard/R8 with full line-range support |
| Electron/JS | `*.js.map` | Source map v3 |
| Flutter | `*.symbols` | Via `flutter symbolize` or direct parsing |
| Rust | Backtrace | Debug builds include source locations |
| Go | Goroutine stacks | Symbol tables usually embedded |
| Python | Tracebacks | Source file mapping |
| React Native | `*.bundle.map` | Hermes bytecode + JS source maps |

<details>
<summary>Mapping file organization</summary>

```text
mappings/
  android/
    com.example.app/
      1.0.0/mapping.txt
      1.1.0/mapping.txt
  electron/
    my-app/
      1.0.0/main.js.map
  flutter/
    com.example.app/
      1.0.0/app.android-arm64.symbols
```

The receiver automatically falls back to the newest available version if an exact version match isn't found.

</details>

## Shared Test Vectors

The [`test-vectors/`](test-vectors/) directory contains JSON test cases for NIP-17 and crash payload conformance. All platform implementations should validate against these vectors.

## Contributing

See [AGENTS.md](AGENTS.md) for contributor guidelines covering:
- Privacy requirements and PII rules
- Crash report payload schema
- Fingerprint algorithm specification
- Documentation and commit conventions

## License

[MIT](LICENSE)
