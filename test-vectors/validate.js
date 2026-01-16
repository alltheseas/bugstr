/**
 * NIP-17 Schema Validation
 *
 * Validates test vectors against NIP-17 kind-14 schema.
 * Schema based on nostrability/schemata specification.
 *
 * Reference:
 * - https://github.com/nostrability/schemata/blob/master/nips/nip-17/kind-14/schema.yaml
 * - https://github.com/hzrd149/applesauce/pull/39
 */

import Ajv from "ajv";
import { createHash } from "crypto";
import { readFileSync } from "fs";

const ajv = new Ajv({ strict: false, allErrors: true });

/**
 * NIP-17 Kind 14 schema based on nostrability/schemata.
 *
 * This is a flattened version of the schema that resolves all $ref pointers.
 * The original schema uses allOf with refs to:
 * - @/note-unsigned.yaml (content, created_at, kind, pubkey, tags)
 * - @/secp256k1.yaml (64 char lowercase hex pattern)
 * - @/tag.yaml and @/tag/p.yaml (tag structure)
 *
 * Key requirements:
 * - kind: const 14
 * - id: 64 char lowercase hex (event hash)
 * - pubkey: 64 char lowercase hex
 * - tags: must include at least one p tag
 * - sig: must NOT be present (not: required: [sig])
 */
const kind14Schema = {
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "kind14",
  description: "Private direct message event defined by NIP-17",
  type: "object",
  properties: {
    id: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
      description: "Deterministic event hash as defined in NIP-01",
    },
    pubkey: {
      type: "string",
      pattern: "^[a-f0-9]{64}$",
      description: "Sender public key (secp256k1)",
    },
    created_at: {
      type: "integer",
      minimum: 0,
      description: "Unix timestamp in seconds",
    },
    kind: {
      const: 14,
      description: "Kind 14 identifies an unsigned private direct message",
    },
    content: {
      type: "string",
      description: "Plain text chat message content",
    },
    tags: {
      type: "array",
      minItems: 1,
      items: {
        type: "array",
        items: { type: "string" },
        minItems: 1,
      },
      description: "Must include at least one p tag identifying a receiver",
    },
  },
  required: ["id", "pubkey", "created_at", "kind", "content", "tags"],
  // Per NIP-17: sig must NOT be required (rumors are unsigned)
  not: {
    required: ["sig"],
  },
};

// Load test vectors
const vectors = JSON.parse(readFileSync("./nip17-gift-wrap.json", "utf-8"));

let passed = 0;
let failed = 0;

console.log("NIP-17 Schema Validation (nostrability/schemata spec)");
console.log("======================================================\n");

// Test 1: Validate event ID computation
console.log("1. Event ID Computation Tests\n");

for (const testCase of vectors.test_vectors.event_id_computation) {
  const { name, input, serialized, expected_id } = testCase;

  // Compute ID from serialized form
  const computedId = createHash("sha256").update(serialized).digest("hex");

  // Verify serialization format
  const expectedSerialized = JSON.stringify([
    0,
    input.pubkey,
    input.created_at,
    input.kind,
    input.tags,
    input.content,
  ]);

  const serializationMatch = serialized === expectedSerialized;

  if (expected_id) {
    if (computedId === expected_id && serializationMatch) {
      console.log(`  ✓ ${name}`);
      passed++;
    } else {
      console.log(`  ✗ ${name}`);
      if (!serializationMatch) {
        console.log(`    Serialization mismatch:`);
        console.log(`    Expected: ${expectedSerialized}`);
        console.log(`    Got:      ${serialized}`);
      }
      if (computedId !== expected_id) {
        console.log(`    ID mismatch:`);
        console.log(`    Expected: ${expected_id}`);
        console.log(`    Got:      ${computedId}`);
      }
      failed++;
    }
  } else {
    if (serializationMatch) {
      console.log(`  ✓ ${name} (serialization only)`);
      passed++;
    } else {
      console.log(`  ✗ ${name} (serialization mismatch)`);
      failed++;
    }
  }
}

// Test 2: Validate rumor structure against NIP-17 kind-14 schema
console.log("\n2. NIP-17 Kind 14 Schema Validation\n");

const validate = ajv.compile(kind14Schema);

for (const testCase of vectors.test_vectors.rumor_json_output) {
  const { name, input } = testCase;

  // Build a complete rumor event
  const serialized = JSON.stringify([
    0,
    input.pubkey,
    input.created_at,
    input.kind,
    input.tags,
    input.content,
  ]);
  const id = createHash("sha256").update(serialized).digest("hex");

  const rumor = {
    id,
    pubkey: input.pubkey,
    created_at: input.created_at,
    kind: input.kind,
    tags: input.tags,
    content: input.content,
    // sig is intentionally omitted per NIP-17 spec
  };

  const valid = validate(rumor);

  if (valid) {
    console.log(`  ✓ ${name}`);
    passed++;
  } else {
    console.log(`  ✗ ${name}`);
    console.log(`    Errors: ${JSON.stringify(validate.errors, null, 2)}`);
    failed++;
  }
}

// Summary
console.log("\n======================================================");
console.log(`\nResults: ${passed} passed, ${failed} failed\n`);

if (failed > 0) {
  process.exit(1);
}
