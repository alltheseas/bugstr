/**
 * Transport layer constants and types for crash report delivery.
 *
 * Supports both direct delivery (<=50KB) and hashtree-based chunked
 * delivery (>50KB) for large crash reports.
 */

/** Event kind for direct crash report delivery (<=50KB). */
export const KIND_DIRECT = 10420;

/** Event kind for hashtree manifest (>50KB crash reports). */
export const KIND_MANIFEST = 10421;

/** Event kind for CHK-encrypted chunk data. */
export const KIND_CHUNK = 10422;

/** Size threshold for switching from direct to chunked transport (50KB). */
export const DIRECT_SIZE_THRESHOLD = 50 * 1024;

/** Maximum chunk size (48KB, accounts for base64 + relay overhead). */
export const MAX_CHUNK_SIZE = 48 * 1024;

// ---------------------------------------------------------------------------
// Relay Rate Limiting
// ---------------------------------------------------------------------------

/**
 * Known relay rate limits in milliseconds between posts.
 * Based on strfry + noteguard default: 8 posts/minute = 7500ms between posts.
 */
export const RELAY_RATE_LIMITS: Record<string, number> = {
  'wss://relay.damus.io': 7500,
  'wss://nos.lol': 7500,
  'wss://relay.primal.net': 7500,
};

/** Default rate limit for unknown relays (conservative: 8 posts/min). */
export const DEFAULT_RELAY_RATE_LIMIT = 7500;

/** Get rate limit for a relay URL. */
export function getRelayRateLimit(relayUrl: string): number {
  return RELAY_RATE_LIMITS[relayUrl] ?? DEFAULT_RELAY_RATE_LIMIT;
}

/** Estimate upload time in seconds for given chunks and relays. */
export function estimateUploadSeconds(totalChunks: number, numRelays: number): number {
  const msPerChunk = DEFAULT_RELAY_RATE_LIMIT / numRelays;
  return Math.ceil((totalChunks * msPerChunk) / 1000);
}

// ---------------------------------------------------------------------------
// Progress Reporting (Apple HIG Compliant)
// ---------------------------------------------------------------------------

/** Phase of crash report upload. */
export type BugstrProgressPhase = 'preparing' | 'uploading' | 'finalizing';

/**
 * Progress state for crash report upload.
 * Designed for HIG-compliant determinate progress indicators.
 */
export type BugstrProgress = {
  /** Current phase of upload. */
  phase: BugstrProgressPhase;
  /** Current chunk being uploaded (1-indexed for display). */
  currentChunk: number;
  /** Total number of chunks. */
  totalChunks: number;
  /** Progress as fraction 0.0 to 1.0 (for ProgressView). */
  fractionCompleted: number;
  /** Estimated seconds remaining. */
  estimatedSecondsRemaining: number;
  /** Human-readable status for accessibility/display. */
  localizedDescription: string;
};

/** Callback type for progress updates. */
export type BugstrProgressCallback = (progress: BugstrProgress) => void;

/** Create progress for preparing phase. */
export function progressPreparing(totalChunks: number, estimatedSeconds: number): BugstrProgress {
  return {
    phase: 'preparing',
    currentChunk: 0,
    totalChunks,
    fractionCompleted: 0,
    estimatedSecondsRemaining: estimatedSeconds,
    localizedDescription: 'Preparing crash report...',
  };
}

/** Create progress for uploading phase. */
export function progressUploading(current: number, total: number, estimatedSeconds: number): BugstrProgress {
  return {
    phase: 'uploading',
    currentChunk: current,
    totalChunks: total,
    fractionCompleted: (current / total) * 0.95,
    estimatedSecondsRemaining: estimatedSeconds,
    localizedDescription: `Uploading chunk ${current} of ${total}`,
  };
}

/** Create progress for finalizing phase. */
export function progressFinalizing(totalChunks: number): BugstrProgress {
  return {
    phase: 'finalizing',
    currentChunk: totalChunks,
    totalChunks,
    fractionCompleted: 0.95,
    estimatedSecondsRemaining: 2,
    localizedDescription: 'Finalizing...',
  };
}

/** Create progress for completion. */
export function progressCompleted(totalChunks: number): BugstrProgress {
  return {
    phase: 'finalizing',
    currentChunk: totalChunks,
    totalChunks,
    fractionCompleted: 1.0,
    estimatedSecondsRemaining: 0,
    localizedDescription: 'Complete',
  };
}

// ---------------------------------------------------------------------------
// Payload Types
// ---------------------------------------------------------------------------

/** Direct crash report payload (kind 10420). */
export type DirectPayload = {
  v: number;
  crash: Record<string, unknown>;
};

/** Hashtree manifest payload (kind 10421). */
export type ManifestPayload = {
  v: number;
  root_hash: string;
  total_size: number;
  chunk_count: number;
  chunk_ids: string[];
  /** Optional relay hints for each chunk (for optimized fetching). */
  chunk_relays?: Record<string, string[]>;
};

/** Chunk payload (kind 10422). */
export type ChunkPayload = {
  v: number;
  index: number;
  hash: string;
  data: string;
};

/** Determines transport kind based on payload size. */
export function getTransportKind(size: number): 'direct' | 'chunked' {
  return size <= DIRECT_SIZE_THRESHOLD ? 'direct' : 'chunked';
}

/** Creates a direct payload wrapper. */
export function createDirectPayload(crash: Record<string, unknown>): DirectPayload {
  return { v: 1, crash };
}
