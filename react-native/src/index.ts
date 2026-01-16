/**
 * Bugstr React Native SDK
 *
 * Zero-infrastructure crash reporting for React Native via NIP-17 encrypted DMs.
 *
 * For large crash reports (>50KB), uses CHK chunking:
 * - Chunks are published as public events (kind 10422)
 * - Manifest with root hash is gift-wrapped (kind 10421)
 * - Only the recipient can decrypt chunks using the root hash
 *
 * @example
 * ```tsx
 * import * as Bugstr from '@bugstr/react-native';
 *
 * Bugstr.init({
 *   developerPubkey: 'npub1...',
 *   environment: 'production',
 *   release: '1.0.0',
 * });
 *
 * // Wrap your app with error boundary
 * export default function App() {
 *   return (
 *     <Bugstr.ErrorBoundary>
 *       <YourApp />
 *     </Bugstr.ErrorBoundary>
 *   );
 * }
 * ```
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { Alert, Platform } from 'react-native';
import { nip19, nip44, finalizeEvent, generateSecretKey, getPublicKey, Relay, getEventHash } from 'nostr-tools';
import type { UnsignedEvent } from 'nostr-tools';
import {
  KIND_DIRECT,
  KIND_MANIFEST,
  KIND_CHUNK,
  DIRECT_SIZE_THRESHOLD,
  getTransportKind,
  createDirectPayload,
  getRelayRateLimit,
  estimateUploadSeconds,
  progressPreparing,
  progressUploading,
  progressFinalizing,
  progressCompleted,
  type ManifestPayload,
  type ChunkPayload,
  type BugstrProgress,
  type BugstrProgressCallback,
} from './transport';
import { chunkPayload, encodeChunkData, type ChunkData } from './chunking';

// Re-export progress types
export type { BugstrProgress, BugstrProgressCallback } from './transport';

// Types
export type BugstrConfig = {
  developerPubkey: string;
  relays?: string[];
  environment?: string;
  release?: string;
  redactPatterns?: RegExp[];
  beforeSend?: (payload: BugstrPayload) => BugstrPayload | null;
  confirmSend?: (summary: BugstrSummary) => Promise<boolean> | boolean;
  /** If true, uses native Alert for confirmation. Default: true */
  useNativeAlert?: boolean;
  /**
   * Progress callback for large crash reports (>50KB).
   * Fires asynchronously during upload - does not block the UI.
   */
  onProgress?: BugstrProgressCallback;
};

export type BugstrPayload = {
  message: string;
  stack?: string;
  timestamp: number;
  environment?: string;
  release?: string;
  platform?: string;
  deviceInfo?: Record<string, unknown>;
};

export type BugstrSummary = {
  message: string;
  stackPreview?: string;
};

// Default configuration
const DEFAULT_REDACTIONS: RegExp[] = [
  /cashuA[a-zA-Z0-9]+/g,
  /lnbc[a-z0-9]+/gi,
  /npub1[a-z0-9]+/gi,
  /nsec1[a-z0-9]+/gi,
  /https?:\/\/[^\s"]*\/mint[^\s"]*/gi,
];

const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://relay.primal.net', 'wss://nos.lol'];

// Global state
let initialized = false;
let senderPrivkey: Uint8Array | undefined;
let developerPubkeyHex = '';
let config: BugstrConfig = {
  developerPubkey: '',
  useNativeAlert: true,
};

/** Track last post time per relay for rate limiting. */
const lastPostTime: Map<string, number> = new Map();

// Helpers
function decodePubkey(pubkey: string): string {
  if (!pubkey) return '';
  if (pubkey.startsWith('npub')) {
    const decoded = nip19.decode(pubkey);
    if (decoded.type === 'npub') {
      return decoded.data;
    }
  }
  return pubkey;
}

function redact(input: string | undefined, patterns: RegExp[]): string | undefined {
  if (!input) return input;
  return patterns.reduce((acc, pattern) => acc.replace(pattern, '[redacted]'), input);
}

function randomPastTimestamp(): number {
  const now = Math.floor(Date.now() / 1000);
  const maxOffset = 60 * 60 * 24 * 2;
  const offset = Math.floor(Math.random() * maxOffset);
  return now - offset;
}

function buildPayload(err: unknown, errorInfo?: ErrorInfo): BugstrPayload {
  let message = 'Unknown error';
  if (err instanceof Error) {
    message = err.message || 'Unknown error';
  } else if (typeof err === 'string') {
    message = err;
  }

  let stack = err instanceof Error && typeof err.stack === 'string' ? err.stack : '';
  if (errorInfo?.componentStack) {
    stack += '\n\nComponent Stack:' + errorInfo.componentStack;
  }

  const patterns = config.redactPatterns?.length ? config.redactPatterns : DEFAULT_REDACTIONS;

  return {
    message: redact(message, patterns) || 'Unknown error',
    stack: redact(stack, patterns),
    timestamp: Date.now(),
    environment: config.environment,
    release: config.release,
    platform: Platform.OS,
    deviceInfo: {
      os: Platform.OS,
      version: Platform.Version,
    },
  };
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
  const rumorEvent: UnsignedEvent = {
    kind: rumorKind,
    created_at: randomPastTimestamp(),
    tags: [['p', recipientPubkey]],
    content,
    pubkey: getPublicKey(senderPrivkey),
  };

  const rumorId = getEventHash(rumorEvent);
  const unsignedRumor = {
    ...rumorEvent,
    id: rumorId,
    sig: '', // Empty signature for rumors per NIP-17
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
      tags: [['p', recipientPubkey]],
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
  const chunkPayloadData: ChunkPayload = {
    v: 1,
    index: chunk.index,
    hash: chunk.hash,
    data: encodeChunkData(chunk),
  };
  return finalizeEvent(
    {
      kind: KIND_CHUNK,
      created_at: randomPastTimestamp(),
      tags: [],
      content: JSON.stringify(chunkPayloadData),
    },
    chunkPrivkey
  );
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
  throw lastError || new Error('Unable to publish Bugstr event');
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

  const successful = results.filter((r) => r.status === 'fulfilled').length;
  if (successful === 0) {
    throw new Error('Unable to publish chunk to any relay');
  }
}

/**
 * Wait for relay rate limit if needed.
 */
async function waitForRateLimit(relayUrl: string): Promise<void> {
  const rateLimit = getRelayRateLimit(relayUrl);
  const lastTime = lastPostTime.get(relayUrl) ?? 0;
  const now = Date.now();
  const elapsed = now - lastTime;

  if (elapsed < rateLimit) {
    const waitMs = rateLimit - elapsed;
    console.log(`Bugstr: rate limit wait ${waitMs}ms for ${relayUrl}`);
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  }
}

/**
 * Record post time for rate limiting.
 */
function recordPostTime(relayUrl: string): void {
  lastPostTime.set(relayUrl, Date.now());
}

/**
 * Publish chunk to a single relay with rate limiting.
 */
async function publishChunkToRelay(
  relayUrl: string,
  event: ReturnType<typeof finalizeEvent>
): Promise<void> {
  await waitForRateLimit(relayUrl);
  const relay = await Relay.connect(relayUrl);
  await relay.publish(event);
  relay.close();
  recordPostTime(relayUrl);
}

/**
 * Verify a chunk event exists on a relay.
 */
async function verifyChunkExists(relayUrl: string, eventId: string): Promise<boolean> {
  try {
    const relay = await Relay.connect(relayUrl);
    const events = await relay.list([{ ids: [eventId], kinds: [KIND_CHUNK], limit: 1 }]);
    relay.close();
    return events.length > 0;
  } catch (err) {
    console.log(`Bugstr: verify chunk failed on ${relayUrl}: ${err}`);
    return false;
  }
}

/**
 * Publish chunk with verification and retry on failure.
 * @returns The relay URL where the chunk was successfully published, or null if all failed.
 */
async function publishChunkWithVerify(
  event: ReturnType<typeof finalizeEvent>,
  relays: string[],
  startIndex: number
): Promise<string | null> {
  const numRelays = relays.length;

  // Try each relay starting from startIndex (round-robin)
  for (let attempt = 0; attempt < numRelays; attempt++) {
    const relayUrl = relays[(startIndex + attempt) % numRelays];

    try {
      // Publish with rate limiting
      await publishChunkToRelay(relayUrl, event);

      // Brief delay before verification
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Verify the chunk exists
      if (await verifyChunkExists(relayUrl, event.id)) {
        return relayUrl;
      }
      console.log(`Bugstr: chunk verification failed on ${relayUrl}, trying next`);
    } catch (err) {
      console.log(`Bugstr: chunk publish failed on ${relayUrl}: ${err}`);
    }
    // Try next relay
  }

  return null; // All relays failed
}

/**
 * Send payload via NIP-17 gift wrap, using chunking for large payloads.
 * Uses round-robin relay distribution to maximize throughput while
 * respecting per-relay rate limits (8 posts/min for strfry+noteguard).
 */
async function sendToNostr(payload: BugstrPayload): Promise<void> {
  if (!developerPubkeyHex || !senderPrivkey) {
    throw new Error('Bugstr Nostr keys not configured');
  }

  const relays = config.relays?.length ? config.relays : DEFAULT_RELAYS;
  const plaintext = JSON.stringify(payload);
  const payloadSize = new TextEncoder().encode(plaintext).length;
  const transportKind = getTransportKind(payloadSize);

  if (transportKind === 'direct') {
    // Small payload: direct gift-wrapped delivery (no progress needed)
    const directPayload = createDirectPayload(payload as Record<string, unknown>);
    const giftWrap = buildGiftWrap(
      KIND_DIRECT,
      JSON.stringify(directPayload),
      senderPrivkey,
      developerPubkeyHex
    );

    await publishToRelays(relays, giftWrap);
    console.log('Bugstr: sent direct crash report');
  } else {
    // Large payload: chunked delivery with round-robin distribution
    console.log(`Bugstr: payload ${payloadSize} bytes, using chunked transport`);

    const { rootHash, totalSize, chunks } = chunkPayload(plaintext);
    const totalChunks = chunks.length;
    console.log(`Bugstr: split into ${totalChunks} chunks across ${relays.length} relays`);

    // Report initial progress
    const estimatedSeconds = estimateUploadSeconds(totalChunks, relays.length);
    config.onProgress?.(progressPreparing(totalChunks, estimatedSeconds));

    // Build chunk events and track relay assignments with verification
    const chunkEvents = chunks.map(buildChunkEvent);
    const chunkIds: string[] = [];
    const chunkRelays: Record<string, string[]> = {};

    for (let i = 0; i < chunkEvents.length; i++) {
      const chunkEvent = chunkEvents[i];
      chunkIds.push(chunkEvent.id);

      // Publish with verification and retry (starts at round-robin relay)
      const successRelay = await publishChunkWithVerify(chunkEvent, relays, i % relays.length);
      if (successRelay) {
        chunkRelays[chunkEvent.id] = [successRelay];
      }
      // If all relays failed, chunk is lost - receiver will report missing chunk

      // Report progress
      const remainingChunks = totalChunks - i - 1;
      const remainingSeconds = estimateUploadSeconds(remainingChunks, relays.length);
      config.onProgress?.(progressUploading(i + 1, totalChunks, remainingSeconds));
    }
    console.log(`Bugstr: published ${totalChunks} chunks`);

    // Report finalizing
    config.onProgress?.(progressFinalizing(totalChunks));

    // Build and publish manifest with relay hints
    const manifest: ManifestPayload = {
      v: 1,
      root_hash: rootHash,
      total_size: totalSize,
      chunk_count: totalChunks,
      chunk_ids: chunkIds,
      chunk_relays: chunkRelays,
    };

    const manifestGiftWrap = buildGiftWrap(
      KIND_MANIFEST,
      JSON.stringify(manifest),
      senderPrivkey,
      developerPubkeyHex
    );

    await publishToRelays(relays, manifestGiftWrap);
    console.log('Bugstr: sent chunked crash report manifest');

    // Report complete
    config.onProgress?.(progressCompleted(totalChunks));
  }
}

async function nativeConfirm(summary: BugstrSummary): Promise<boolean> {
  return new Promise((resolve) => {
    Alert.alert(
      'Send Crash Report?',
      `${summary.message}${summary.stackPreview ? `\n\n${summary.stackPreview}` : ''}`,
      [
        { text: 'Cancel', style: 'cancel', onPress: () => resolve(false) },
        { text: 'Send', onPress: () => resolve(true) },
      ],
      { cancelable: true, onDismiss: () => resolve(false) }
    );
  });
}

async function maybeSend(payload: BugstrPayload): Promise<void> {
  // Apply beforeSend hook first (may modify or drop the payload)
  const finalPayload = config.beforeSend === undefined ? payload : config.beforeSend(payload);
  if (finalPayload === null) return;

  const payloadToSend = finalPayload || payload;

  // Build summary from the (potentially modified) payload
  const summary: BugstrSummary = {
    message: payloadToSend.message,
    stackPreview: payloadToSend.stack ? payloadToSend.stack.split('\n').slice(0, 3).join('\n') : undefined,
  };

  // Confirm with user
  let shouldSend: boolean;
  if (config.confirmSend) {
    shouldSend = await config.confirmSend(summary);
  } else if (config.useNativeAlert !== false) {
    shouldSend = await nativeConfirm(summary);
  } else {
    shouldSend = true;
  }

  if (!shouldSend) return;

  await sendToNostr(payloadToSend);
}

// Public API

/**
 * Initialize Bugstr.
 *
 * @param configOverrides - Configuration options
 */
export function init(configOverrides: BugstrConfig): void {
  if (initialized) return;

  config = { ...config, ...configOverrides };
  developerPubkeyHex = decodePubkey(config.developerPubkey);
  senderPrivkey = generateSecretKey();
  initialized = true;

  // Install global error handler
  const originalHandler = ErrorUtils.getGlobalHandler();
  ErrorUtils.setGlobalHandler((error: Error, isFatal?: boolean) => {
    captureException(error);
    if (originalHandler) {
      originalHandler(error, isFatal);
    }
  });
}

/**
 * Capture an exception and send as crash report.
 *
 * @param err - The error to capture
 * @param errorInfo - Optional React error info (from error boundaries)
 */
export function captureException(err: unknown, errorInfo?: ErrorInfo): void {
  if (!initialized) {
    console.warn('Bugstr not initialized; dropping error');
    return;
  }
  const payload = buildPayload(err, errorInfo);
  maybeSend(payload).catch((sendErr) => console.warn('Bugstr send failed', sendErr));
}

/**
 * Capture a message as crash report.
 *
 * @param message - The message to send
 */
export function captureMessage(message: string): void {
  captureException(new Error(message));
}

// Error Boundary Component

type ErrorBoundaryProps = {
  children: ReactNode;
  fallback?: ReactNode | ((error: Error) => ReactNode);
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
};

type ErrorBoundaryState = {
  hasError: boolean;
  error: Error | null;
};

/**
 * React Error Boundary that automatically captures errors.
 *
 * @example
 * ```tsx
 * <Bugstr.ErrorBoundary
 *   fallback={<Text>Something went wrong</Text>}
 *   onError={(error) => console.log('Captured:', error)}
 * >
 *   <YourApp />
 * </Bugstr.ErrorBoundary>
 * ```
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    captureException(error, errorInfo);
    this.props.onError?.(error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.hasError && this.state.error) {
      if (typeof this.props.fallback === 'function') {
        return this.props.fallback(this.state.error);
      }
      return this.props.fallback ?? null;
    }
    return this.props.children;
  }
}

// Re-export types
export type { ErrorInfo };
