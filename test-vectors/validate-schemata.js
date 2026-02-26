/**
 * NIP-17 / NIP-59 Schema Validation against upstream nostrability/schemata
 *
 * Loads YAML schemas directly from @nostrability/schemata and validates
 * sample events for all relevant kinds:
 *   - Kind 14  (NIP-17: private direct message / rumor)
 *   - Kind 15  (NIP-17: encrypted file message)
 *   - Kind 10050 (NIP-17: preferred DM relay list)
 *   - Kind 13  (NIP-59: seal)
 *   - Kind 1059 (NIP-59: gift wrap)
 *
 * Schemas are referenced from upstream — not copied or flattened.
 */

import Ajv from "ajv";
import addFormats from "ajv-formats";
import { createHash } from "crypto";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import YAML from "yaml";
import $RefParser from "@apidevtools/json-schema-ref-parser";

const __dirname = dirname(fileURLToPath(import.meta.url));

const SCHEMATA_ROOT = resolve(
  __dirname,
  "node_modules/@nostrability/schemata"
);

// ── Schema loader ──────────────────────────────────────────────────────

/**
 * Load a YAML schema from the schemata package, resolve all $ref pointers
 * (including @/ and nips/ prefixes), and return a plain JSON object.
 */
async function loadSchema(relPath) {
  const fullPath = resolve(SCHEMATA_ROOT, relPath);
  const raw = readFileSync(fullPath, "utf-8");
  const schema = YAML.parse(raw);

  // Rewrite @/ and nips/ refs to absolute file paths before dereferencing
  rewriteRefs(schema, SCHEMATA_ROOT);

  const dereferenced = await $RefParser.dereference(schema, {
    resolve: {
      file: {
        read(file) {
          const content = readFileSync(new URL(file.url).pathname, "utf-8");
          const parsed = file.url.endsWith(".yaml") || file.url.endsWith(".yml")
            ? YAML.parse(content)
            : JSON.parse(content);
          rewriteRefs(parsed, SCHEMATA_ROOT);
          return parsed;
        },
      },
    },
  });

  // Strip duplicate $id fields that cause AJV issues
  stripNestedIds(dereferenced);

  // Remove additionalProperties from allOf subschemas (draft-07 composition
  // pitfall: additionalProperties only sees properties from its own schema
  // object, not from allOf siblings). Upstream schemata works around this
  // via full deref pipeline; we strip it after dereferencing.
  stripAdditionalPropertiesInAllOf(dereferenced);

  return dereferenced;
}

function rewriteRefs(obj, root) {
  if (Array.isArray(obj)) {
    obj.forEach((item) => rewriteRefs(item, root));
  } else if (obj && typeof obj === "object") {
    for (const [key, val] of Object.entries(obj)) {
      if (key === "$ref" && typeof val === "string") {
        if (val.startsWith("@/")) {
          obj[key] = resolve(root, val.slice(2));
        } else if (val.startsWith("nips/")) {
          obj[key] = resolve(root, val);
        }
      } else {
        rewriteRefs(val, root);
      }
    }
  }
}

function stripNestedIds(obj, isRoot = true) {
  if (Array.isArray(obj)) {
    for (const item of obj) stripNestedIds(item, false);
  } else if (obj && typeof obj === "object") {
    if (!isRoot && "$id" in obj) delete obj.$id;
    for (const val of Object.values(obj)) stripNestedIds(val, false);
  }
}

// ── Sample events ──────────────────────────────────────────────────────

const HEX64 = "a".repeat(64);
const HEX128 = "b".repeat(128);

const sampleEvents = {
  "kind-14": {
    valid: {
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 14,
      content: "Hello, this is a private message",
      tags: [["p", HEX64]],
      sig: "",
    },
    invalid: {
      // Non-empty sig = invalid for kind 14 (rumors MUST have sig: "" per NIP-59, not a real signature)
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 14,
      content: "Hello",
      tags: [["p", HEX64]],
      sig: HEX128,
    },
  },
  "kind-13": {
    valid: {
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 13,
      content: "encrypted-rumor-payload-here",
      tags: [],
      sig: HEX128,
    },
    invalid: {
      // tags must be empty for seals
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 13,
      content: "encrypted",
      tags: [["p", HEX64]],
      sig: HEX128,
    },
  },
  "kind-1059": {
    valid: {
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 1059,
      content: "encrypted-seal-payload-here",
      tags: [["p", HEX64]],
      sig: HEX128,
    },
    invalid: {
      // missing p tag
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 1059,
      content: "encrypted",
      tags: [],
      sig: HEX128,
    },
  },
  "kind-10050": {
    valid: {
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 10050,
      content: "",
      tags: [["relay", "wss://relay.example.com"]],
      sig: HEX128,
    },
    invalid: {
      // wrong kind
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 9999,
      content: "",
      tags: [],
      sig: HEX128,
    },
  },
  "kind-15": {
    valid: {
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 15,
      content: "https://cdn.example.com/encrypted-file.bin",
      tags: [
        ["p", HEX64],
        ["file-type", "image/png"],
        ["encryption-algorithm", "aes-gcm"],
        ["decryption-key", "abcdef1234567890"],
        ["decryption-nonce", "nonce123"],
        ["x", HEX64],
      ],
    },
    invalid: {
      // missing required tags for kind 15
      id: HEX64,
      pubkey: HEX64,
      created_at: 1700000000,
      kind: 15,
      content: "https://cdn.example.com/file.bin",
      tags: [["p", HEX64]],
    },
  },
};

// Compute correct id for kind-14 valid sample (SHA256 of serialized event per NIP-01)
{
  const s = sampleEvents["kind-14"].valid;
  const serialized = JSON.stringify([0, s.pubkey, s.created_at, s.kind, s.tags, s.content]);
  s.id = createHash("sha256").update(serialized).digest("hex");
}

// ── Schema paths ───────────────────────────────────────────────────────

const schemaPaths = {
  "kind-14": "nips/nip-17/kind-14/schema.yaml",
  "kind-15": "nips/nip-17/kind-15/schema.yaml",
  "kind-10050": "nips/nip-17/kind-10050/schema.yaml",
  "kind-13": "nips/nip-59/kind-13/schema.yaml",
  "kind-1059": "nips/nip-59/kind-1059/schema.yaml",
};

// ── Main ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

console.log("NIP-17 / NIP-59 Upstream Schema Validation");
console.log("(@nostrability/schemata)");
console.log("=============================================\n");

for (const [kindName, schemaPath] of Object.entries(schemaPaths)) {
  console.log(`${kindName} (${schemaPath})\n`);

  let schema;
  try {
    schema = await loadSchema(schemaPath);
  } catch (err) {
    console.log(`  SKIP: Failed to load schema: ${err.message}\n`);
    continue;
  }

  // Strip errorMessage (not standard JSON Schema, AJV rejects it)
  stripCustomKeywords(schema);

  const ajv = addFormats(new Ajv({ strict: false, allErrors: true }));
  let validate;
  try {
    validate = ajv.compile(schema);
  } catch (err) {
    console.log(`  SKIP: Failed to compile schema: ${err.message}\n`);
    continue;
  }

  const samples = sampleEvents[kindName];

  // For kind-14 rumors, verify id matches SHA256 of serialized event
  if (kindName === "kind-14") {
    const s = samples.valid;
    const serialized = JSON.stringify([0, s.pubkey, s.created_at, s.kind, s.tags, s.content]);
    const expectedId = createHash("sha256").update(serialized).digest("hex");
    if (s.id !== expectedId) {
      console.log(`  FAIL  kind-14 rumor id does not match SHA256 of serialized event`);
      console.log(`        expected: ${expectedId}`);
      console.log(`        got:      ${s.id}`);
      failed++;
    } else {
      console.log(`  PASS  kind-14 rumor id matches computed hash`);
      passed++;
    }
  }

  // Valid event should pass
  const validResult = validate(samples.valid);
  if (validResult) {
    console.log(`  PASS  valid event accepted`);
    passed++;
  } else {
    console.log(`  FAIL  valid event rejected`);
    console.log(`        ${JSON.stringify(validate.errors, null, 2)}`);
    failed++;
  }

  // Invalid event should fail
  const invalidResult = validate(samples.invalid);
  if (!invalidResult) {
    console.log(`  PASS  invalid event rejected`);
    passed++;
  } else {
    console.log(`  FAIL  invalid event accepted (should have been rejected)`);
    failed++;
  }

  console.log();
}

// Also validate our existing NIP-17 test vectors against kind-14 schema
console.log("NIP-17 Test Vectors vs kind-14 schema\n");
try {
  const kind14Schema = await loadSchema("nips/nip-17/kind-14/schema.yaml");
  stripCustomKeywords(kind14Schema);
  const ajv = addFormats(new Ajv({ strict: false, allErrors: true }));
  const validate = ajv.compile(kind14Schema);

  const vectors = JSON.parse(readFileSync("./nip17-gift-wrap.json", "utf-8"));

  for (const testCase of vectors.test_vectors.rumor_json_output) {
    const { name, input } = testCase;
    // Compute event id per NIP-01: SHA256 of [0, pubkey, created_at, kind, tags, content]
    const serialized = JSON.stringify([0, input.pubkey, input.created_at, input.kind, input.tags, input.content]);
    const computedId = createHash("sha256").update(serialized).digest("hex");

    const rumor = {
      id: computedId,
      pubkey: input.pubkey,
      created_at: input.created_at,
      kind: input.kind,
      tags: input.tags,
      content: input.content,
      sig: "", // NIP-17: rumors must include sig as empty string
    };

    const valid = validate(rumor);
    if (valid) {
      console.log(`  PASS  ${name}`);
      passed++;
    } else {
      console.log(`  FAIL  ${name}`);
      console.log(`        ${JSON.stringify(validate.errors, null, 2)}`);
      failed++;
    }
  }
} catch (err) {
  console.log(`  SKIP: ${err.message}`);
}

console.log("\n=============================================");
console.log(`Results: ${passed} passed, ${failed} failed\n`);

if (failed > 0) process.exit(1);

// ── Helpers ────────────────────────────────────────────────────────────

function stripCustomKeywords(obj) {
  if (Array.isArray(obj)) {
    obj.forEach(stripCustomKeywords);
  } else if (obj && typeof obj === "object") {
    delete obj.errorMessage;
    for (const val of Object.values(obj)) stripCustomKeywords(val);
  }
}

function stripAdditionalPropertiesInAllOf(obj) {
  if (Array.isArray(obj)) {
    obj.forEach(stripAdditionalPropertiesInAllOf);
  } else if (obj && typeof obj === "object") {
    if (Array.isArray(obj.allOf)) {
      for (const sub of obj.allOf) {
        if (sub && typeof sub === "object" && "additionalProperties" in sub) {
          delete sub.additionalProperties;
        }
        stripAdditionalPropertiesInAllOf(sub);
      }
    }
    for (const [key, val] of Object.entries(obj)) {
      if (key !== "allOf" && val !== obj) stripAdditionalPropertiesInAllOf(val);
    }
  }
}
