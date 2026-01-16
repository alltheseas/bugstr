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

### Listen for crash reports (CLI)

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

### Web Dashboard

Start the web server with an embedded dashboard to view and manage crash reports:

```bash
# Start on default port 3000
bugstr serve --privkey <your-hex-or-nsec>

# Custom port and relays
bugstr serve --privkey $BUGSTR_PRIVKEY --port 8080 --relays wss://relay.damus.io

# Open http://localhost:3000 in your browser
```

The dashboard provides:
- Real-time crash report collection
- SQLite storage for persistence
- Grouping by exception type
- Auto-refresh every 30 seconds

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
- **Web dashboard** — `bugstr serve` provides a browser-based UI with SQLite storage
- **Compression** — gzip with versioned envelope format
- **NIP-17 decryption** — unwraps gift wrap → seal → rumor
- **Pretty/JSON/Raw output** — flexible output formats

## NIP Compliance

- **NIP-17** — Private Direct Messages (kind 14 rumors)
- **NIP-44** — Versioned Encryption (v2)
- **NIP-59** — Gift Wrap (rumor → seal → gift wrap)

Rumors include `id` (computed) and `sig: ""` (empty string) per spec.

## Symbolication

Bugstr supports server-side symbolication of stack traces using mapping files (ProGuard, source maps, etc.).

### Enable Symbolication

```bash
# Start server with mappings directory
bugstr serve --privkey $BUGSTR_PRIVKEY --mappings ./mappings

# Or via CLI
bugstr symbolicate --mappings ./mappings --platform android --app com.example.app --version 1.0.0 < stacktrace.txt
```

### Directory Structure

Mapping files are organized by platform, app ID, and version:

```text
mappings/
  android/
    com.example.app/
      1.0.0/
        mapping.txt          # ProGuard/R8 mapping
      1.1.0/
        mapping.txt
  electron/
    my-desktop-app/
      1.0.0/
        main.js.map          # Source map
        renderer.js.map
  flutter/
    com.example.app/
      1.0.0/
        app.android-arm64.symbols
  react-native/
    com.example.app/
      1.0.0/
        index.android.bundle.map
```

### Supported Platforms

| Platform | Mapping File | Notes |
|----------|-------------|-------|
| Android | `mapping.txt` | ProGuard/R8 obfuscation mapping |
| Electron/JS | `*.js.map` | Source maps |
| Flutter | `*.symbols` | Flutter symbolize format |
| React Native | `*.bundle.map` | Hermes bytecode + JS source maps |
| Rust | — | Parses native backtraces |
| Go | — | Parses goroutine stacks |
| Python | — | Parses tracebacks |

### API Endpoint

```bash
curl -X POST http://localhost:3000/api/symbolicate \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "android",
    "app_id": "com.example.app",
    "version": "1.0.0",
    "stack_trace": "..."
  }'
```

## Other Platforms

- [Android/Kotlin](../android/)
- [TypeScript](../typescript/)
- [Flutter/Dart](../dart/)
