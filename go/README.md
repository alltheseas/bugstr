# Bugstr Go SDK

Zero-infrastructure crash reporting for Go applications via NIP-17 encrypted DMs.

## Installation

```bash
go get github.com/alltheseas/bugstr/go
```

## Usage

### Basic Setup

```go
package main

import (
    "github.com/alltheseas/bugstr/go"
)

func main() {
    bugstr.Init(bugstr.Config{
        DeveloperPubkey: "npub1...", // Your receiver pubkey
        Environment:     "production",
        Release:         "1.0.0",
    })
    defer bugstr.Recover()

    // Your application code...
}
```

### Goroutine Recovery

```go
go func() {
    defer bugstr.RecoverAndContinue() // Captures panic without re-panicking
    // ...
}()
```

### Manual Capture

```go
if err != nil {
    bugstr.CaptureException(err)
}

bugstr.CaptureMessage("Something unexpected happened")
```

### Server Mode (Auto-send)

For servers, omit `ConfirmSend` to send reports automatically:

```go
bugstr.Init(bugstr.Config{
    DeveloperPubkey: "npub1...",
    Environment:     "production",
    // No ConfirmSend = auto-send
})
```

### With Confirmation

For CLI tools or interactive applications:

```go
bugstr.Init(bugstr.Config{
    DeveloperPubkey: "npub1...",
    ConfirmSend: func(summary bugstr.Summary) bool {
        fmt.Printf("Send crash report?\n%s\n", summary.Message)
        // Return true to send, false to skip
        return promptUser()
    },
})
```

## Features

- **Panic recovery** via `Recover()` and `RecoverAndContinue()`
- **Automatic redaction** of sensitive data (cashu tokens, lightning invoices, nostr keys)
- **Compression** for large stack traces (gzip, >1KB threshold)
- **NIP-17 encryption** - reports are end-to-end encrypted
- **30-day expiration** - reports auto-expire on relays

## Configuration

| Field | Type | Description |
|-------|------|-------------|
| `DeveloperPubkey` | `string` | Required. Recipient's npub or hex pubkey |
| `Relays` | `[]string` | Relay URLs (default: damus.io, nos.lol) |
| `Environment` | `string` | Environment tag (e.g., "production") |
| `Release` | `string` | Version tag |
| `RedactPatterns` | `[]*regexp.Regexp` | Custom redaction patterns |
| `BeforeSend` | `func(*Payload) *Payload` | Modify/filter before send |
| `ConfirmSend` | `func(Summary) bool` | Prompt before sending |

## License

MIT
