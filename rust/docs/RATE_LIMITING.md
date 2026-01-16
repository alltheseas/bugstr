# Relay Rate Limiting Analysis

Investigation for bead `rust-x1v`: Relay rate limiting behavior when sending many chunks.

## Background

When sending large crash reports via CHK chunking, multiple chunk events (kind 10422) are published to relays in quick succession. This could trigger relay rate limiting.

## Damus/strfry Rate Limiting

The damus.io relay uses [noteguard](https://github.com/damus-io/noteguard), a plugin for strfry that implements rate limiting:

### Configuration
- **Rate limit**: Configurable `posts_per_minute` (example: 8)
- **Scope**: Per IP address
- **Whitelist**: Specific IPs can bypass rate limiting
- **No burst allowance**: Simple per-minute threshold, no spike handling

### Rejection Behavior
When rate limit is exceeded:
- Event is rejected
- Error message: "rate-limited: you are noting too much"
- Pipeline stops, event is not stored

## Impact on Bugstr Chunking

### Scenario: 100KB Crash Report
- Chunk size: 48KB
- Chunks needed: 3
- Events to publish: 3 chunks + 1 manifest = 4 events

### Scenario: 1MB Crash Report
- Chunk size: 48KB
- Chunks needed: 22
- Events to publish: 22 chunks + 1 manifest = 23 events

### Risk Assessment

| Relay Type | Rate Limit | Risk for 3 chunks | Risk for 22 chunks |
|------------|-----------|-------------------|-------------------|
| strfry + noteguard (8/min) | 8 posts/min | Low | **High** |
| Paid relays | Usually higher | Low | Medium |
| Personal relays | Often unlimited | Low | Low |

## Mitigation Strategies

### 1. Staggered Publishing (Recommended)
Add delay between chunk publications:
```
delay_ms = 60_000 / posts_per_minute_limit
# For 8/min limit: 7.5 seconds between chunks
```

**Pros**: Simple, predictable
**Cons**: Slow for many chunks

### 2. Multi-Relay Distribution
Publish different chunks to different relays:
```
chunk[0] -> relay A
chunk[1] -> relay B
chunk[2] -> relay C
```

**Pros**: Parallelism, faster
**Cons**: Requires cross-relay aggregation (already implemented)

### 3. Batch with Backoff
Send initial batch, then exponential backoff on rate limit:
```rust
for chunk in chunks {
    match publish(chunk).await {
        Ok(_) => continue,
        Err(RateLimited) => {
            delay(backoff_ms).await;
            backoff_ms *= 2;
        }
    }
}
```

**Pros**: Adapts to relay limits
**Cons**: Complex error detection

### 4. Relay Hint Tags
Include relay hints in manifest for chunk locations:
```json
{
  "chunk_ids": ["abc123", "def456"],
  "chunk_relays": {
    "abc123": ["wss://relay1.example"],
    "def456": ["wss://relay2.example"]
  }
}
```

**Pros**: Enables targeted fetching
**Cons**: Protocol extension needed

## Recommendations

### For SDK Senders

1. **Default behavior**: Publish chunks to all relays with 100ms delay between chunks
2. **Configuration option**: Allow customizing `chunk_publish_delay_ms`
3. **Parallel relay publishing**: Continue publishing same chunk to multiple relays simultaneously
4. **Sequential chunk publishing**: Publish chunks one at a time (with delay) to avoid bursts

### For Receiver

1. **Already implemented**: Cross-relay aggregation handles chunks distributed across relays
2. **Timeout handling**: Current 30-second timeout per relay is adequate
3. **Retry logic**: Consider adding retry for individual missing chunks

### Suggested Default Values

```rust
const DEFAULT_CHUNK_PUBLISH_DELAY_MS: u64 = 100; // Between chunks
const DEFAULT_RELAY_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_CHUNK_FETCH_TIMEOUT_MS: u64 = 30_000;
```

## Testing Plan

1. Create test with 5 chunks (250KB payload)
2. Publish to damus.io relay
3. Measure success rate with different delays:
   - 0ms (burst)
   - 100ms
   - 500ms
   - 1000ms
4. Document minimum safe delay for common relays

## Sources

- [noteguard - damus strfry plugin](https://github.com/damus-io/noteguard)
- [strfry relay](https://github.com/hoytech/strfry)
