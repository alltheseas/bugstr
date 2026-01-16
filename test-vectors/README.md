# Bugstr Test Vectors

Shared NIP-17 compliance test vectors for all Bugstr implementations.

## Schema Validation

Uses JSON Schema draft-07 for validation, based on the [nostrability/schemata](https://github.com/nostrability/schemata) specifications.

## Running Tests

```bash
cd test-vectors
npm install
npm test
```

## Test Coverage

### Event ID Computation
Validates that implementations correctly compute event IDs per NIP-01:
```
id = sha256([0, pubkey, created_at, kind, tags, content])
```

### Kind 14 Schema Validation
Validates rumor events against the official NIP-17 kind 14 schema from nostrability/schemata.

## Adding Platform-Specific Tests

Each platform implementation can import and validate against these test vectors:

### TypeScript
```typescript
import vectors from '../test-vectors/nip17-gift-wrap.json';
// Validate your implementation against vectors.test_vectors
```

### Kotlin
```kotlin
val vectors = Json.decodeFromString<TestVectors>(
    File("../test-vectors/nip17-gift-wrap.json").readText()
)
```

## CI Integration

The GitHub workflow `.github/workflows/schema-validation.yml` runs these tests on every push and PR.
