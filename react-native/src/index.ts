/**
 * Bugstr React Native SDK
 *
 * Zero-infrastructure crash reporting for React Native via NIP-17 encrypted DMs.
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

async function sendToNostr(payload: BugstrPayload): Promise<void> {
  if (!developerPubkeyHex || !senderPrivkey) {
    throw new Error('Bugstr Nostr keys not configured');
  }

  const relays = config.relays?.length ? config.relays : DEFAULT_RELAYS;
  const plaintext = JSON.stringify(payload);

  // Build unsigned kind 14 (rumor)
  const rumorEvent: UnsignedEvent = {
    kind: 14,
    created_at: randomPastTimestamp(),
    tags: [['p', developerPubkeyHex]],
    content: plaintext,
    pubkey: getPublicKey(senderPrivkey),
  };

  // Compute rumor ID per NIP-01 using nostr-tools getEventHash
  const rumorId = getEventHash(rumorEvent);

  const unsignedKind14 = {
    ...rumorEvent,
    id: rumorId,
    sig: '', // Empty signature for rumors per NIP-17
  };

  // Seal (kind 13)
  const conversationKey = nip44.getConversationKey(senderPrivkey, developerPubkeyHex);
  const sealContent = await nip44.encrypt(JSON.stringify(unsignedKind14), conversationKey);
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
  const wrapKey = nip44.getConversationKey(wrapperPrivBytes, developerPubkeyHex);
  const giftWrapContent = await nip44.encrypt(JSON.stringify(seal), wrapKey);
  const giftWrap = finalizeEvent(
    {
      kind: 1059,
      created_at: randomPastTimestamp(),
      tags: [['p', developerPubkeyHex]],
      content: giftWrapContent,
    },
    wrapperPrivBytes
  );

  // Publish
  let lastError: Error | undefined;
  for (const relayUrl of relays) {
    try {
      const relay = await Relay.connect(relayUrl);
      await relay.publish(giftWrap);
      relay.close();
      return;
    } catch (err) {
      lastError = err as Error;
    }
  }
  throw lastError || new Error('Unable to publish Bugstr event');
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
  const summary: BugstrSummary = {
    message: payload.message,
    stackPreview: payload.stack ? payload.stack.split('\n').slice(0, 3).join('\n') : undefined,
  };

  let shouldSend: boolean;
  if (config.confirmSend) {
    shouldSend = await config.confirmSend(summary);
  } else if (config.useNativeAlert !== false) {
    shouldSend = await nativeConfirm(summary);
  } else {
    shouldSend = true;
  }

  if (!shouldSend) return;

  const finalPayload = config.beforeSend === undefined ? payload : config.beforeSend(payload);
  if (finalPayload === null) return;

  await sendToNostr(finalPayload || payload);
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
