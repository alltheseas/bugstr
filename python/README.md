# Bugstr Python SDK

Zero-infrastructure crash reporting for Python applications via NIP-17 encrypted DMs.

## Installation

```bash
pip install bugstr
```

## Usage

### Basic Setup

```python
import bugstr

bugstr.init(
    developer_pubkey="npub1...",  # Your receiver pubkey
    environment="production",
    release="1.0.0",
)

# Install global exception hook for uncaught exceptions
bugstr.install_exception_hook()
```

### Manual Capture

```python
try:
    risky_operation()
except Exception as e:
    bugstr.capture_exception(e)

# Or capture a message
bugstr.capture_message("Something unexpected happened")
```

### Server Mode (Auto-send)

For servers, omit `confirm_send` to send reports automatically:

```python
bugstr.init(
    developer_pubkey="npub1...",
    environment="production",
    # No confirm_send = auto-send
)
```

### With Confirmation

For CLI tools or interactive applications:

```python
def confirm(message: str, stack_preview: str) -> bool:
    print(f"Send crash report?\n{message}\n{stack_preview}")
    return input("Send? [y/N] ").lower() == "y"

bugstr.init(
    developer_pubkey="npub1...",
    confirm_send=confirm,
)
```

### Django Integration

```python
# settings.py
import bugstr

bugstr.init(
    developer_pubkey="npub1...",
    environment="production",
    release=os.environ.get("GIT_SHA", "unknown"),
)

# Add to LOGGING config or use Django signals
```

### Flask Integration

```python
from flask import Flask
import bugstr

app = Flask(__name__)

bugstr.init(developer_pubkey="npub1...")

@app.errorhandler(Exception)
def handle_exception(e):
    bugstr.capture_exception(e)
    raise e
```

## Features

- **Exception hook** for automatic capture of uncaught exceptions
- **Automatic redaction** of sensitive data (cashu tokens, lightning invoices, nostr keys)
- **Compression** for large stack traces (gzip, >1KB threshold)
- **NIP-17 encryption** - reports are end-to-end encrypted
- **30-day expiration** - reports auto-expire on relays
- **Async-safe** - sends in background thread

## Configuration

| Parameter | Type | Description |
|-----------|------|-------------|
| `developer_pubkey` | `str` | Required. Recipient's npub or hex pubkey |
| `relays` | `list[str]` | Relay URLs (default: damus.io, nos.lol) |
| `environment` | `str` | Environment tag (e.g., "production") |
| `release` | `str` | Version tag |
| `redact_patterns` | `list[Pattern]` | Custom redaction regex patterns |
| `before_send` | `Callable` | Hook to modify/filter payloads |
| `confirm_send` | `Callable` | Hook to confirm before sending |

## License

MIT
