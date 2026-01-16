/**
 * Bugstr crash reporting SDK for Electron desktop apps.
 *
 * Captures crashes, caches them locally, and sends via NIP-17 gift-wrapped
 * encrypted DMs on next app launch with user consent.
 *
 * For large crash reports (>50KB), uses CHK chunking:
 * - Chunks are published as public events (kind 10422)
 * - Manifest with root hash is gift-wrapped (kind 10421)
 * - Only the recipient can decrypt chunks using the root hash
 */
import { nip19, nip44, finalizeEvent, generateSecretKey, getPublicKey, getEventHash, Relay } from "nostr-tools";
import { maybeCompressPayload } from "./compression.js";
import {
  KIND_DIRECT,
  KIND_MANIFEST,
  KIND_CHUNK,
  DIRECT_SIZE_THRESHOLD,
  getTransportKind,
  createDirectPayload,
  type ManifestPayload,
  type ChunkPayload,
} from "./transport.js";
import { chunkPayload, type ChunkData } from "./chunking.js";
import Store from "electron-store";

export type BugstrConfig = {
  /** Developer's npub or hex pubkey to receive crash reports */
  developerPubkey: string;
  /** Relay URLs to publish to (defaults: damus, primal, nos.lol) */
  relays?: string[];
  /** Environment tag (e.g., 'production') */
  environment?: string;
  /** Release version tag */
  release?: string;
  /** Custom redaction patterns */
  redactPatterns?: RegExp[];
  /** Hook to modify/filter payload before sending. Return null to drop. */
  beforeSend?: (payload: BugstrPayload) => BugstrPayload | null;
  /** Custom confirmation dialog. If not provided, uses Electron dialog. */
  confirmSend?: (summary: BugstrSummary) => Promise<boolean> | boolean;
};

export type BugstrPayload = {
  message: string;
  stack?: string;
  timestamp: number;
  environment?: string;
  release?: string;
  platform?: string;
};

export type BugstrSummary = {
  message: string;
  stackPreview?: string;
};

type CachedReport = {
  id: string;
  payload: BugstrPayload;
  createdAt: number;
};

// Default redaction patterns for wallet/nostr secrets
const DEFAULT_REDACTIONS: RegExp[] = [
  /cashuA[a-zA-Z0-9]+/g,
  /lnbc[a-z0-9]+/gi,
  /npub1[a-z0-9]+/gi,
  /nsec1[a-z0-9]+/gi,
  /https?:\/\/[^\s"]*mint[^\s"]*/gi,
];

const DEFAULT_RELAYS = [
  "wss://relay.damus.io",
  "wss://relay.primal.net",
  "wss://nos.lol",
];

let initialized = false;
let senderPrivkey: Uint8Array | undefined;
let developerPubkeyHex = "";
let config: BugstrConfig = { developerPubkey: "" };
let store: Store<{ pendingReports: CachedReport[] }>;

function decodePubkey(pubkey: string): string {
  if (!pubkey) return "";
  if (pubkey.startsWith("npub")) {
    const decoded = nip19.decode(pubkey);
    if (decoded.type === "npub") {
      return decoded.data;
    }
  }
  return pubkey;
}

function redact(input: string | undefined, patterns: RegExp[]): string | undefined {
  if (!input) return input;
  return patterns.reduce((acc, pattern) => acc.replace(pattern, "[redacted]"), input);
}

function randomPastTimestamp(): number {
  const now = Math.floor(Date.now() / 1000);
  const maxOffset = 60 * 60 * 24 * 2; // up to 2 days
  return now - Math.floor(Math.random() * maxOffset);
}

function generateReportId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function buildPayload(err: unknown): BugstrPayload {
  let message = "Unknown error";
  if (err instanceof Error) {
    message = err.message || "Unknown error";
  } else if (typeof err === "string") {
    message = err;
  }

  const stack = err instanceof Error && typeof err.stack === "string" ? err.stack : "";
  const patterns = config.redactPatterns?.length ? config.redactPatterns : DEFAULT_REDACTIONS;

  return {
    message: redact(message, patterns) || "Unknown error",
    stack: redact(stack, patterns),
    timestamp: Date.now(),
    environment: config.environment,
    release: config.release,
    platform: process.platform,
  };
}

/** Cache a crash report locally for later sending */
function cacheReport(payload: BugstrPayload): void {
  const reports = store.get("pendingReports", []);
  reports.push({
    id: generateReportId(),
    payload,
    createdAt: Date.now(),
  });
  store.set("pendingReports", reports);
  console.info("Bugstr: crash report cached locally");
}

/** Get all pending reports from cache */
function getPendingReports(): CachedReport[] {
  return store.get("pendingReports", []);
}

/** Remove a report from cache after successful send or user decline */
function removeReport(id: string): void {
  const reports = store.get("pendingReports", []);
  store.set("pendingReports", reports.filter((r) => r.id !== id));
}

/** Clear all pending reports. No-op if not initialized. */
export function clearPendingReports(): void {
  if (!initialized) return;
  store.set("pendingReports", []);
}

/**
 * Build a NIP-17 gift-wrapped event for a rumor.
 */
function buildGiftWrap(
  rumorKind: number,
  content: string,
  senderPrivkey: Uint8Array,
  recipientPubkey: string
): ReturnType<typeof finalizeEvent> {
  // NIP-59: rumor uses actual timestamp, only seal/gift-wrap are randomized
  const rumorEvent = {
    kind: rumorKind,
    created_at: Math.floor(Date.now() / 1000),
    tags: [["p", recipientPubkey]],
    content,
    pubkey: getPublicKey(senderPrivkey),
  };

  const rumorId = getEventHash(rumorEvent);
  const unsignedRumor = {
    ...rumorEvent,
    id: rumorId,
    sig: "", // Empty signature for rumors per NIP-17
  };

  // Seal (kind 13)
  const conversationKey = nip44.getConversationKey(senderPrivkey, recipientPubkey);
  const sealContent = nip44.encrypt(JSON.stringify(unsignedRumor), conversationKey);
  const seal = finalizeEvent(
    {
      kind: 13,
      created_at: randomPastTimestamp(),
      tags: [],
      content: sealContent,
    },
    senderPrivkey
  );

  // Gift wrap (kind 1059)
  const wrapperPrivBytes = generateSecretKey();
  const wrapKey = nip44.getConversationKey(wrapperPrivBytes, recipientPubkey);
  const giftWrapContent = nip44.encrypt(JSON.stringify(seal), wrapKey);
  return finalizeEvent(
    {
      kind: 1059,
      created_at: randomPastTimestamp(),
      tags: [["p", recipientPubkey]],
      content: giftWrapContent,
    },
    wrapperPrivBytes
  );
}

/**
 * Build a public chunk event (kind 10422).
 */
function buildChunkEvent(chunk: ChunkData): ReturnType<typeof finalizeEvent> {
  const chunkPrivkey = generateSecretKey();
  const chunkPayload: ChunkPayload = {
    v: 1,
    index: chunk.index,
    hash: chunk.hash,
    data: chunk.encrypted.toString("base64"),
  };
  return finalizeEvent(
    {
      kind: KIND_CHUNK,
      created_at: randomPastTimestamp(),
      tags: [],
      content: JSON.stringify(chunkPayload),
    },
    chunkPrivkey
  );
}

async function sendToNostr(payload: BugstrPayload): Promise<void> {
  if (!developerPubkeyHex || !senderPrivkey) {
    throw new Error("Bugstr Nostr keys not configured");
  }

  const relays = config.relays?.length ? config.relays : DEFAULT_RELAYS;

  // Compress and check size
  const rawJson = JSON.stringify(payload);
  const compressed = maybeCompressPayload(rawJson);
  const payloadBytes = Buffer.from(compressed, "utf-8");
  const transportKind = getTransportKind(payloadBytes.length);

  if (transportKind === "direct") {
    // Small payload: direct gift-wrapped delivery
    const directPayload = createDirectPayload(payload as Record<string, unknown>);
    const giftWrap = buildGiftWrap(
      KIND_DIRECT,
      JSON.stringify(directPayload),
      senderPrivkey,
      developerPubkeyHex
    );

    await publishToRelays(relays, giftWrap);
    console.info("Bugstr: sent direct crash report");
  } else {
    // Large payload: chunked delivery
    console.info(`Bugstr: payload ${payloadBytes.length} bytes, using chunked transport`);

    const { rootHash, totalSize, chunks } = chunkPayload(payloadBytes);
    console.info(`Bugstr: split into ${chunks.length} chunks`);

    // Build chunk events
    const chunkEvents = chunks.map(buildChunkEvent);

    // Publish chunks to all relays with delay to avoid rate limiting
    const chunkIds: string[] = [];
    const CHUNK_PUBLISH_DELAY_MS = 100; // Delay between chunks to avoid relay rate limits
    for (let i = 0; i < chunkEvents.length; i++) {
      const chunkEvent = chunkEvents[i];
      chunkIds.push(chunkEvent.id);
      await publishToAllRelays(relays, chunkEvent);
      // Add delay between chunks (not after last chunk)
      if (i < chunkEvents.length - 1) {
        await new Promise((resolve) => setTimeout(resolve, CHUNK_PUBLISH_DELAY_MS));
      }
    }
    console.info(`Bugstr: published ${chunks.length} chunks`);

    // Build and publish manifest
    const manifest: ManifestPayload = {
      v: 1,
      root_hash: rootHash,
      total_size: totalSize,
      chunk_count: chunks.length,
      chunk_ids: chunkIds,
    };

    const manifestGiftWrap = buildGiftWrap(
      KIND_MANIFEST,
      JSON.stringify(manifest),
      senderPrivkey,
      developerPubkeyHex
    );

    await publishToRelays(relays, manifestGiftWrap);
    console.info("Bugstr: sent chunked crash report manifest");
  }
}

/**
 * Publish an event to the first successful relay.
 */
async function publishToRelays(
  relays: string[],
  event: ReturnType<typeof finalizeEvent>
): Promise<void> {
  let lastError: Error | undefined;
  for (const relayUrl of relays) {
    try {
      const relay = await Relay.connect(relayUrl);
      await relay.publish(event);
      relay.close();
      return;
    } catch (err) {
      lastError = err as Error;
    }
  }
  throw lastError || new Error("Unable to publish Bugstr event");
}

/**
 * Publish an event to all relays (for chunk redundancy).
 */
async function publishToAllRelays(
  relays: string[],
  event: ReturnType<typeof finalizeEvent>
): Promise<void> {
  const results = await Promise.allSettled(
    relays.map(async (relayUrl) => {
      const relay = await Relay.connect(relayUrl);
      await relay.publish(event);
      relay.close();
    })
  );

  const successful = results.filter((r) => r.status === "fulfilled").length;
  if (successful === 0) {
    throw new Error("Unable to publish chunk to any relay");
  }
}

async function showElectronDialog(summary: BugstrSummary): Promise<boolean> {
  // Dynamic import to avoid issues when bundling
  const { dialog } = await import("electron");

  const result = await dialog.showMessageBox({
    type: "question",
    buttons: ["Send Report", "Don't Send"],
    defaultId: 0,
    cancelId: 1,
    title: "Send Crash Report?",
    message: "The app encountered an error. Send a crash report to help improve the app?",
    detail: `${summary.message}${summary.stackPreview ? `\n\n${summary.stackPreview}` : ""}`,
  });

  return result.response === 0;
}

async function processPendingReport(report: CachedReport): Promise<void> {
  // Apply beforeSend hook first
  let payload = report.payload;
  if (config.beforeSend !== undefined) {
    const modified = config.beforeSend(payload);
    if (modified === null) {
      removeReport(report.id);
      return;
    }
    payload = modified;
  }

  const summary: BugstrSummary = {
    message: payload.message,
    stackPreview: payload.stack?.split("\n").slice(0, 3).join("\n"),
  };

  // Get user consent
  const shouldSend = config.confirmSend
    ? await config.confirmSend(summary)
    : await showElectronDialog(summary);

  if (!shouldSend) {
    removeReport(report.id);
    console.info("Bugstr: user declined to send report");
    return;
  }

  try {
    await sendToNostr(payload);
    removeReport(report.id);
    console.info("Bugstr: crash report sent successfully");
  } catch (err) {
    console.warn("Bugstr: failed to send report, keeping in cache", err);
  }
}

/** Process all pending crash reports (call on app ready) */
export async function processPendingReports(): Promise<void> {
  if (!initialized) {
    console.warn("Bugstr not initialized");
    return;
  }

  const reports = getPendingReports();
  if (reports.length === 0) return;

  console.info(`Bugstr: processing ${reports.length} pending crash report(s)`);

  for (const report of reports) {
    await processPendingReport(report);
  }
}

function handleMainProcessError(err: Error): void {
  if (!initialized) return;
  const payload = buildPayload(err);
  cacheReport(payload);
}

/**
 * Initialize Bugstr for Electron.
 *
 * Call this early in your main process, then call processPendingReports()
 * after the app is ready to show consent dialogs for any cached crashes.
 *
 * @example
 * ```ts
 * import { init, processPendingReports } from 'bugstr-electron';
 * import { app } from 'electron';
 *
 * init({
 *   developerPubkey: 'npub1...',
 *   environment: 'production',
 *   release: app.getVersion(),
 * });
 *
 * app.whenReady().then(() => {
 *   processPendingReports();
 *   // ... create windows
 * });
 * ```
 */
export function init(configOverrides: BugstrConfig): void {
  if (initialized) return;

  config = configOverrides;
  developerPubkeyHex = decodePubkey(config.developerPubkey);
  if (!developerPubkeyHex) {
    throw new Error("Bugstr: invalid developerPubkey");
  }

  senderPrivkey = generateSecretKey();

  // Initialize persistent store
  store = new Store<{ pendingReports: CachedReport[] }>({
    name: "bugstr-crash-reports",
    defaults: { pendingReports: [] },
  });

  // Install main process error handlers
  process.on("uncaughtException", handleMainProcessError);
  process.on("unhandledRejection", (reason) => {
    handleMainProcessError(
      reason instanceof Error ? reason : new Error(String(reason))
    );
  });

  initialized = true;
  console.info("Bugstr: initialized for Electron");
}

/**
 * Manually capture an exception.
 *
 * The report is cached locally and will be sent on next app launch
 * after user consent.
 */
export function captureException(err: unknown): void {
  if (!initialized) {
    console.warn("Bugstr not initialized; dropping error");
    return;
  }
  const payload = buildPayload(err);
  cacheReport(payload);
}

/**
 * Capture a message as a crash report.
 */
export function captureMessage(message: string): void {
  captureException(new Error(message));
}
