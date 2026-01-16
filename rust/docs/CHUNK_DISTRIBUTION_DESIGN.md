# Chunk Distribution & Rate Limiting Design

Bead: `rust-0qz` - Implement relay-specific rate limiting and progress UX for chunk uploads

## Problem

All three default relays use strfry with noteguard rate limiting:
- **relay.damus.io**: strfry + noteguard
- **nos.lol**: strfry + noteguard
- **relay.primal.net**: strfry + noteguard

**Default rate limit: 8 posts/minute per IP** (from noteguard.toml)

### Current Implementation Issues

1. Current 100ms delay is **way too fast** (would allow 600/min vs limit of 8/min)
2. Publishing to ALL relays for each chunk means hitting rate limits on ALL relays
3. No progress feedback to users
4. No relay hints for receiver optimization

### UX Impact (Current: Single Relay @ 8/min)

| Payload | Chunks | Events | Time | UX |
|---------|--------|--------|------|-----|
| 50KB | 0 | 1 | instant | ✅ |
| 100KB | 3 | 4 | **30 sec** | 😐 |
| 500KB | 11 | 12 | **90 sec** | 😬 |
| 1MB | 22 | 23 | **~3 min** | ❌ |

## Proposed Solution: Round-Robin Distribution with Relay Hints

### Strategy

Distribute chunks across relays in round-robin fashion:
```
Chunk 0 → relay.damus.io
Chunk 1 → nos.lol
Chunk 2 → relay.primal.net
Chunk 3 → relay.damus.io (cycle)
...
```

### Extended Manifest with Relay Hints

```json
{
  "v": 1,
  "root_hash": "abc123...",
  "total_size": 100000,
  "chunk_count": 3,
  "chunk_ids": ["id0", "id1", "id2"],
  "chunk_relays": {
    "id0": ["wss://relay.damus.io"],
    "id1": ["wss://nos.lol"],
    "id2": ["wss://relay.primal.net"]
  }
}
```

### UX Impact (3-Relay Distribution @ 8/min each = 24/min effective)

| Payload | Chunks | Time (old) | Time (new) | Improvement |
|---------|--------|------------|------------|-------------|
| 100KB | 3 | 30 sec | **7.5 sec** | 4x faster |
| 500KB | 11 | 90 sec | **27 sec** | 3.3x faster |
| 1MB | 22 | 3 min | **55 sec** | 3.3x faster |

### Rate Limit Configuration

```typescript
const RELAY_RATE_LIMITS: Record<string, number> = {
  // Known strfry + noteguard relays: 8 posts/min = 7500ms between posts
  'wss://relay.damus.io': 7500,
  'wss://nos.lol': 7500,
  'wss://relay.primal.net': 7500,
  // Default for unknown relays (conservative)
  'default': 7500,
};
```

### Progress Callback API (Apple HIG Compliant)

Per [Apple Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/progress-indicators):

1. **Use determinate progress** - Since chunk count is known, show exact progress (not spinner)
2. **Show estimated time remaining** - Help users gauge duration
3. **Avoid vague terms** - "Uploading chunk 3 of 22" not just "Loading..."
4. **Show progress immediately** - Don't leave screen blank/frozen

```typescript
/**
 * Progress state for crash report upload.
 * Designed for HIG-compliant determinate progress indicators.
 */
export type BugstrProgress = {
  /** Current phase: 'preparing' | 'uploading' | 'finalizing' */
  phase: 'preparing' | 'uploading' | 'finalizing';

  /** Current chunk being uploaded (1-indexed for display) */
  currentChunk: number;

  /** Total number of chunks */
  totalChunks: number;

  /** Progress as fraction 0.0 to 1.0 (for UIProgressView/ProgressView) */
  fractionCompleted: number;

  /** Estimated seconds remaining (for display) */
  estimatedSecondsRemaining: number;

  /** Human-readable status for accessibility/display */
  localizedDescription: string;
};

// Callback type
export type BugstrProgressCallback = (progress: BugstrProgress) => void;

// Usage - Flutter example with HIG-compliant UI
Bugstr.init(
  developerPubkey: 'npub1...',
  onProgress: (progress) {
    setState(() {
      _uploadProgress = progress.fractionCompleted;
      _statusText = progress.localizedDescription;
      _timeRemaining = progress.estimatedSecondsRemaining;
    });
  },
);

// Example progress states:
// { phase: 'preparing', currentChunk: 0, totalChunks: 22, fractionCompleted: 0.0,
//   estimatedSecondsRemaining: 55, localizedDescription: 'Preparing crash report...' }
//
// { phase: 'uploading', currentChunk: 5, totalChunks: 22, fractionCompleted: 0.23,
//   estimatedSecondsRemaining: 42, localizedDescription: 'Uploading chunk 5 of 22' }
//
// { phase: 'finalizing', currentChunk: 22, totalChunks: 22, fractionCompleted: 0.95,
//   estimatedSecondsRemaining: 2, localizedDescription: 'Finalizing...' }
```

### Recommended UI Implementation

```dart
// Flutter - HIG-compliant progress indicator
Widget buildProgressIndicator(BugstrProgress progress) {
  return Column(
    children: [
      // Determinate progress bar (not CircularProgressIndicator)
      LinearProgressIndicator(
        value: progress.fractionCompleted,
        semanticsLabel: progress.localizedDescription,
      ),
      SizedBox(height: 8),
      // Status text
      Text(progress.localizedDescription),
      // Time remaining (if > 5 seconds)
      if (progress.estimatedSecondsRemaining > 5)
        Text('About ${progress.estimatedSecondsRemaining} seconds remaining'),
    ],
  );
}
```

```swift
// SwiftUI - HIG-compliant progress indicator
struct UploadProgressView: View {
    let progress: BugstrProgress

    var body: some View {
        VStack {
            ProgressView(value: progress.fractionCompleted)
                .progressViewStyle(.linear)

            Text(progress.localizedDescription)
                .font(.caption)

            if progress.estimatedSecondsRemaining > 5 {
                Text("About \(progress.estimatedSecondsRemaining) seconds remaining")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
    }
}
```

## Implementation Changes

### 1. Transport Layer Updates

Add to `transport.ts` / `Transport.kt` / etc:
```typescript
// Per-relay rate limiting (ms between posts)
export const RELAY_RATE_LIMITS: Record<string, number> = {
  'wss://relay.damus.io': 7500,
  'wss://nos.lol': 7500,
  'wss://relay.primal.net': 7500,
  'default': 7500,
};

// Get rate limit for a relay
export function getRelayRateLimit(relayUrl: string): number {
  return RELAY_RATE_LIMITS[relayUrl] ?? RELAY_RATE_LIMITS['default'];
}
```

### 2. Manifest Payload Extension

```typescript
export type ManifestPayload = {
  v: number;
  root_hash: string;
  total_size: number;
  chunk_count: number;
  chunk_ids: string[];
  chunk_relays?: Record<string, string[]>;  // NEW: relay hints per chunk
};
```

### 3. Sender: Round-Robin with Rate Tracking

```typescript
async function sendChunked(payload: CrashPayload, onProgress?: ChunkProgressCallback) {
  const relays = config.relays;
  const lastPostTime: Map<string, number> = new Map();
  const chunkRelays: Record<string, string[]> = {};

  for (let i = 0; i < chunks.length; i++) {
    const relayUrl = relays[i % relays.length];  // Round-robin

    // Wait for rate limit
    const lastTime = lastPostTime.get(relayUrl) ?? 0;
    const rateLimit = getRelayRateLimit(relayUrl);
    const elapsed = Date.now() - lastTime;
    if (elapsed < rateLimit) {
      await sleep(rateLimit - elapsed);
    }

    // Publish chunk
    await publishToRelay(relayUrl, chunkEvent);
    lastPostTime.set(relayUrl, Date.now());

    // Track relay hint
    chunkRelays[chunkEvent.id] = [relayUrl];

    // Report progress
    onProgress?.({
      phase: 'chunks',
      current: i + 1,
      total: chunks.length,
      percent: Math.round((i + 1) / chunks.length * 100),
      estimatedSecondsRemaining: (chunks.length - i - 1) * (rateLimit / relays.length) / 1000,
    });
  }

  // Include relay hints in manifest
  const manifest = { ..., chunk_relays: chunkRelays };
}
```

### 4. Receiver: Use Relay Hints

```rust
async fn fetch_chunks(manifest: &Manifest, default_relays: &[String]) -> Result<Vec<Chunk>> {
    for chunk_id in &manifest.chunk_ids {
        // Prefer relay hints if available
        let relays = manifest.chunk_relays
            .as_ref()
            .and_then(|hints| hints.get(chunk_id))
            .unwrap_or(default_relays);

        // Try hinted relays first, then fall back to all relays
        let chunk = fetch_from_relays(chunk_id, relays).await?;
    }
}
```

## Redundancy Considerations

**Option A: Single relay per chunk (fastest, less redundant)**
- Each chunk goes to 1 relay
- Risk: If relay goes down, chunk is lost
- Mitigation: Receiver queries all relays anyway (cross-relay aggregation)

**Option B: Two relays per chunk (balanced)**
- Each chunk goes to 2 relays (staggered round-robin)
- Better redundancy, slightly slower
- Example: chunk 0 → [damus, nos.lol], chunk 1 → [nos.lol, primal]

**Recommendation: Option A** - Cross-relay aggregation already provides resilience. The receiver will query all relays for missing chunks.

## Files to Modify

### SDKs (Senders)
- `dart/lib/src/bugstr_client.dart`
- `dart/lib/src/transport.dart`
- `android/.../Nip17CrashSender.kt`
- `android/.../Transport.kt`
- `electron/src/sdk.ts`
- `electron/src/transport.ts`
- `react-native/src/index.ts`
- `react-native/src/transport.ts`
- `go/bugstr.go`
- `python/bugstr/__init__.py`

### Receiver
- `rust/src/bin/main.rs` - Use relay hints when fetching

### Types
- All `ManifestPayload` types need `chunk_relays` field

## Testing Plan

1. Unit test: Round-robin distribution logic
2. Unit test: Rate limit waiting logic
3. Integration test: Send 100KB payload, verify timing
4. Integration test: Send 500KB payload, verify progress callbacks
5. Integration test: Receiver can fetch with/without relay hints
