# Bugstr

Zero-infrastructure crash reporting — no server to run, no SaaS to pay for.

Bugstr delivers crash reports via [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) encrypted direct messages with user consent. Reports auto-expire after 30 days.

<img width="256" height="256" alt="Bugstr logo" src="https://github.com/user-attachments/assets/1c3c17dc-6a6d-4881-9ac7-32217bd4e1ad" />

## Platforms

| Platform | Directory | Tested |
|----------|-----------|--------|
| Android/Kotlin | [`android/`](android/) | ✅ [Zapstore](https://github.com/zapstore/zapstore/pull/272) |
| Electron | [`electron/`](electron/) | 🐹 Guinea pigs needed |
| Flutter/Dart | [`dart/`](dart/) | 🐹 Guinea pigs needed |
| Rust | [`rust/`](rust/) | 🐹 Guinea pigs needed |
| Go | [`go/`](go/) | 🐹 Guinea pigs needed |
| Python | [`python/`](python/) | 🐹 Guinea pigs needed |
| React Native | [`react-native/`](react-native/) | 🐹 Guinea pigs needed |

## How It Works

```
Crash → Cache locally → App restart → Show consent dialog → User approves → Send encrypted DM (expires in 30 days)
```

1. **Crash occurs** - Exception handler captures stack trace
2. **Local cache** - Report saved to disk (no network)
3. **User consent** - Dialog shows on next app launch
4. **NIP-17 DM** - Encrypted, gift-wrapped message sent to developer
5. **Auto-expiration** - Report deleted from relays after 30 days

## Default Relays

All SDKs use the same default relay list, chosen for reliability:

| Relay | Max Event Size | Max WebSocket | Notes |
|-------|----------------|---------------|-------|
| `wss://relay.damus.io` | 64 KB | 128 KB | strfry defaults |
| `wss://relay.primal.net` | 64 KB | 128 KB | strfry defaults |
| `wss://nos.lol` | 128 KB | 128 KB | Fallback relay |

**Note:** Most relays use strfry defaults (64 KB event size, 128 KB websocket payload). The practical limit for crash reports is ~60 KB to allow for gift-wrap envelope overhead.

You can override these defaults via the `relays` configuration option in each SDK.

## Size Limits & Compression

Crash reports are subject to relay message size limits (see [NIP-11](https://github.com/nostr-protocol/nips/blob/master/11.md) `max_message_length`).

| Relay Limit | Compatibility |
|-------------|---------------|
| 64 KB | ~99% of relays |
| 128 KB | ~90% of relays |
| 512 KB+ | Major relays only |

**Practical limit:** Keep compressed payloads under **60 KB** for universal delivery (allows ~500 bytes for gift-wrap envelope overhead).

| Payload Size | Behavior |
|--------------|----------|
| < 1 KB | Sent as plain JSON |
| ≥ 1 KB | Compressed with gzip, base64-encoded |

### Compression Format

Large payloads are wrapped in a versioned envelope:

```json
{
  "v": 1,
  "compression": "gzip",
  "payload": "<base64-encoded-gzip-data>"
}
```

Stack traces are automatically truncated to fit within limits (default: 200 KB before compression). The receiver CLI/WebUI automatically detects and decompresses payloads.

### Compression Efficiency

Gzip typically achieves **70-90% reduction** on stack traces due to their repetitive text patterns:

| Original Size | Compressed | Reduction |
|---------------|------------|-----------|
| 10 KB | ~1-2 KB | ~80-90% |
| 50 KB | ~5-10 KB | ~80-90% |
| 200 KB | ~20-40 KB | ~80-85% |

With gzip compression (70-90% reduction), most crash reports fit well within the 64 KB strfry default limit. For maximum compatibility, keep compressed payloads under 60 KB.

## Nostr Protocol

All implementations use these NIPs:

- [**NIP-17**](https://github.com/nostr-protocol/nips/blob/master/17.md) - Private Direct Messages (kind 14 rumors)
- [**NIP-44**](https://github.com/nostr-protocol/nips/blob/master/44.md) - Versioned Encryption (v2, XChaCha20-Poly1305)
- [**NIP-59**](https://github.com/nostr-protocol/nips/blob/master/59.md) - Gift Wrap (rumor → seal → gift wrap)
- [**NIP-40**](https://github.com/nostr-protocol/nips/blob/master/40.md) - Expiration Timestamp

### Implementation Notes

Per NIP-17, rumors (kind 14) must include:
- `id` - SHA256 hash of `[0, pubkey, created_at, kind, tags, content]`
- `sig: ""` - Empty string (not omitted)

Some clients (e.g., 0xchat) reject messages missing these fields.

## Shared Test Vectors

The [`test-vectors/`](test-vectors/) directory contains JSON test cases for NIP-17. All platform implementations should validate against these vectors.

## Symbolication

The Rust receiver includes built-in symbolication for 7 platforms:

| Platform | Mapping File | Notes |
|----------|--------------|-------|
| Android | `mapping.txt` | ProGuard/R8 with full line range support |
| Electron/JS | `*.js.map` | Source map v3 |
| Flutter | `*.symbols` | Via `flutter symbolize` or direct parsing |
| Rust | Backtrace | Debug builds include source locations |
| Go | Goroutine stacks | Symbol tables usually embedded |
| Python | Tracebacks | Source file mapping |
| React Native | `*.bundle.map` | Hermes bytecode + JS source maps |

### CLI Usage

```bash
# Symbolicate a stack trace
bugstr symbolicate --platform android --input crash.txt --mappings ./mappings \
  --app-id com.example.app --version 1.0.0

# Output formats: pretty (default) or json
bugstr symbolicate --platform android --input crash.txt --format json
```

### Web API

```bash
# Start server with symbolication enabled
bugstr serve --mappings ./mappings

# POST to symbolicate endpoint
curl -X POST http://localhost:3000/api/symbolicate \
  -H "Content-Type: application/json" \
  -d '{"platform":"android","stack_trace":"...","app_id":"com.example","version":"1.0.0"}'
```

### Mapping File Organization

```
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

## Contributing

See [AGENTS.md](AGENTS.md) for contributor guidelines covering:
- Documentation requirements
- Commit conventions
- NIP implementation notes

## License

[MIT](LICENSE)
