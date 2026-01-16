# Bugstr

Zero-infrastructure crash reporting — no server to run, no SaaS to pay for.

Bugstr delivers crash reports via [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) encrypted direct messages with user consent. Reports auto-expire after 30 days.

<img width="256" height="256" alt="Bugstr logo" src="https://github.com/user-attachments/assets/1c3c17dc-6a6d-4881-9ac7-32217bd4e1ad" />

## Platforms

| Platform | Status | Directory |
|----------|--------|-----------|
| Android/Kotlin | Production | [`android/`](android/) |
| TypeScript | Production | [`typescript/`](typescript/) |
| Flutter/Dart | Skeleton | [`dart/`](dart/) |
| Rust | CLI + Library | [`rust/`](rust/) |
| Go | Library | [`go/`](go/) |
| Python | Library | [`python/`](python/) |
| React Native | Library | [`react-native/`](react-native/) |

## How It Works

```
Crash → Cache locally → App restart → Show consent dialog → User approves → Send encrypted DM (expires in 30 days)
```

1. **Crash occurs** - Exception handler captures stack trace
2. **Local cache** - Report saved to disk (no network)
3. **User consent** - Dialog shows on next app launch
4. **NIP-17 DM** - Encrypted, gift-wrapped message sent to developer
5. **Auto-expiration** - Report deleted from relays after 30 days

## Size Limits & Compression

Crash reports are subject to relay message size limits (typically 64KB-512KB depending on relay).

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

Stack traces are automatically truncated to fit within limits (default: 200KB before compression). The receiver CLI/WebUI automatically detects and decompresses payloads.

### Compression Efficiency

Gzip typically achieves **70-90% reduction** on stack traces due to their repetitive text patterns:

| Original Size | Compressed | Reduction |
|---------------|------------|-----------|
| 10 KB | ~1-2 KB | ~80-90% |
| 50 KB | ~5-10 KB | ~80-90% |
| 200 KB | ~20-40 KB | ~80-85% |

This allows most crash reports to fit comfortably within relay limits even with large stack traces.

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
