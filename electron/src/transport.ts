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
};

/** Chunk payload (kind 10422). */
export type ChunkPayload = {
  v: number;
  index: number;
  hash: string;
  data: string;
};

/** Determines transport kind based on payload size. */
export function getTransportKind(size: number): "direct" | "chunked" {
  return size <= DIRECT_SIZE_THRESHOLD ? "direct" : "chunked";
}

/** Creates a direct payload wrapper. */
export function createDirectPayload(crash: Record<string, unknown>): DirectPayload {
  return { v: 1, crash };
}
