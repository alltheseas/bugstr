# Bugstr

Zero-infrastructure crash reporting — no server to run, no SaaS to pay for.

Bugstr delivers crash reports via [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) encrypted direct messages with user consent. Reports auto-expire after 30 days.

<img width="256" height="256" alt="Bugstr logo" src="https://github.com/user-attachments/assets/1c3c17dc-6a6d-4881-9ac7-32217bd4e1ad" />

## Platforms

| Platform | Status | Directory | Tested |
|----------|--------|-----------|--------|
| Android/Kotlin | Production | [`android/`](android/) | ✅ [Zapstore](https://github.com/zapstore/zapstore/pull/272) |
| TypeScript | Production | [`typescript/`](typescript/) | 🐹 Guinea pigs needed |
| Flutter/Dart | Library | [`dart/`](dart/) | 🐹 Guinea pigs needed |
| Rust | CLI + Library | [`rust/`](rust/) | 🐹 Guinea pigs needed |
| Go | Library | [`go/`](go/) | 🐹 Guinea pigs needed |
| Python | Library | [`python/`](python/) | 🐹 Guinea pigs needed |
| React Native | Library | [`react-native/`](react-native/) | 🐹 Guinea pigs needed |

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

All SDKs use the same default relay list, chosen for reliability and generous size limits:

| Relay | Max Message Size | Notes |
|-------|------------------|-------|
| `wss://relay.damus.io` | 1 MB | Primary relay |
| `wss://relay.primal.net` | 1 MB | Secondary relay |
| `wss://nos.lol` | 128 KB | Fallback relay |

You can override these defaults via the `relays` configuration option in each SDK.

## Size Limits & Compression

Crash reports are subject to relay message size limits (see [NIP-11](https://nips.nostr.com/11) `max_message_length`).

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

With the default relays (1 MB limit), even uncompressed 200 KB stack traces transmit without issue. For maximum compatibility across all relays, the 60 KB practical limit allows ~300 KB of uncompressed stack trace data.

## NIP Compliance

All implementations follow the same Nostr standards:

- **NIP-17** - Private Direct Messages (kind 14 rumors)
- **NIP-44** - Versioned Encryption (v2, XChaCha20-Poly1305)
- **NIP-59** - Gift Wrap (rumor → seal → gift wrap)
- **NIP-40** - Expiration Timestamp

### Critical Requirements

Per NIP-17, rumors (kind 14) must include:
- `id` - SHA256 hash of `[0, pubkey, created_at, kind, tags, content]`
- `sig: ""` - Empty string (not omitted)

Some clients (e.g., 0xchat) reject messages missing these fields.

## Shared Test Vectors

The [`test-vectors/`](test-vectors/) directory contains JSON test cases for NIP-17 compliance. All platform implementations should validate against these vectors.

## Contributing

See [AGENTS.md](AGENTS.md) for contributor guidelines covering:
- Documentation requirements
- Commit conventions
- NIP compliance notes

## License

[MIT](LICENSE)
