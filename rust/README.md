# Bugstr for Rust

Zero-infrastructure crash reporting — no server to run, no SaaS to pay for.

## Installation

```bash
cargo install --path .
```

## CLI Usage

### Get your receiver pubkey

```bash
bugstr pubkey --privkey <your-hex-or-nsec>
# Output: npub1... (add this to your app's bugstr config)
```

### Listen for crash reports

```bash
# Basic usage
bugstr listen --privkey <your-hex-or-nsec>

# Custom relays
bugstr listen --privkey $BUGSTR_PRIVKEY --relays wss://relay.damus.io wss://nos.lol

# JSON output (for piping to jq, etc.)
bugstr listen --privkey $BUGSTR_PRIVKEY --format json

# Raw output (just the crash content)
bugstr listen --privkey $BUGSTR_PRIVKEY --format raw
```

### Environment variable

```bash
export BUGSTR_PRIVKEY=<your-hex-or-nsec>
bugstr listen  # uses $BUGSTR_PRIVKEY
```

## Library Usage

```rust
use bugstr::{compress_payload, decompress_payload, UnsignedNostrEvent};

// Compression
let envelope = compress_payload("crash report...").unwrap();
let plaintext = decompress_payload(&envelope).unwrap();

// Event creation
let event = UnsignedNostrEvent::new(
    "pubkey_hex",
    1234567890,
    14, // kind 14 = chat message
    vec![vec!["p".into(), "recipient_pubkey".into()]],
    "crash report content",
);
let id = event.compute_id();
let json = event.to_json();
```

## Features

- **CLI receiver** — `bugstr listen` subscribes to relays, decrypts NIP-17 DMs, prints crash reports
- **Compression** — gzip with versioned envelope format
- **NIP-17 decryption** — unwraps gift wrap → seal → rumor
- **Pretty/JSON/Raw output** — flexible output formats

## NIP Compliance

- **NIP-17** — Private Direct Messages (kind 14 rumors)
- **NIP-44** — Versioned Encryption (v2)
- **NIP-59** — Gift Wrap (rumor → seal → gift wrap)

Rumors include `id` (computed) and `sig: ""` (empty string) per spec.

## Other Platforms

- [Android/Kotlin](../android/)
- [TypeScript](../typescript/)
- [Flutter/Dart](../dart/)
