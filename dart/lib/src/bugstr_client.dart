/// Main Bugstr client for crash reporting.
///
/// For large crash reports (>50KB), uses CHK chunking:
/// - Chunks are published as public events (kind 10422)
/// - Manifest with root hash is gift-wrapped (kind 10421)
/// - Only the recipient can decrypt chunks using the root hash
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'dart:ui';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:ndk/ndk.dart';

import 'config.dart';
import 'payload.dart';
import 'compression.dart';
import 'transport.dart';
import 'chunking.dart';

/// Main entry point for Bugstr crash reporting.
class Bugstr {
  static BugstrConfig? _config;
  static KeyPair? _senderKeys;
  static String? _developerPubkeyHex;
  static bool _initialized = false;
  static FlutterExceptionHandler? _originalOnError;
  static ErrorCallback? _originalOnPlatformError;
  static BugstrProgressCallback? _onProgress;

  /// Track last post time per relay for rate limiting.
  static final Map<String, int> _lastPostTime = {};

  Bugstr._();

  /// Initialize Bugstr with the given configuration.
  ///
  /// This installs global error handlers for Flutter and Dart errors.
  /// Call this early in your app's main() function.
  ///
  /// Crash reports are sent asynchronously in the background - they never
  /// block the main thread or prevent user interaction after confirmation.
  ///
  /// For large reports (>50KB), use [onProgress] to show upload progress.
  /// The callback fires asynchronously and can be used to update UI state:
  ///
  /// ```dart
  /// void main() {
  ///   Bugstr.init(
  ///     developerPubkey: 'npub1...',
  ///     environment: 'production',
  ///     release: '1.0.0',
  ///     onProgress: (progress) {
  ///       // Update UI state (non-blocking, async callback)
  ///       uploadNotifier.value = progress;
  ///     },
  ///   );
  ///   runApp(MyApp());
  /// }
  /// ```
  static void init({
    required String developerPubkey,
    List<String> relays = const [],
    String? environment,
    String? release,
    List<RegExp> redactPatterns = const [],
    int maxStackCharacters = 200000,
    CrashPayload? Function(CrashPayload payload)? beforeSend,
    Future<bool> Function(String message, String? stackPreview)? confirmSend,
    BugstrProgressCallback? onProgress,
  }) {
    if (_initialized) return;

    _config = BugstrConfig(
      developerPubkey: developerPubkey,
      relays: relays,
      environment: environment,
      release: release,
      redactPatterns: redactPatterns,
      maxStackCharacters: maxStackCharacters,
      beforeSend: beforeSend != null
          ? (p) => beforeSend(CrashPayload.fromJson(p))?.toJson()
          : null,
      confirmSend: confirmSend,
    );

    _onProgress = onProgress;

    // Decode npub to hex
    _developerPubkeyHex = _decodePubkey(developerPubkey);
    if (_developerPubkeyHex == null || _developerPubkeyHex!.isEmpty) {
      throw ArgumentError('Invalid developerPubkey');
    }

    // Generate ephemeral sender keys
    _senderKeys = KeyPair.generate();

    // Install Flutter error handler
    _originalOnError = FlutterError.onError;
    FlutterError.onError = (details) {
      captureException(details.exception, details.stack);
      _originalOnError?.call(details);
    };

    // Install platform error handler
    _originalOnPlatformError = PlatformDispatcher.instance.onError;
    PlatformDispatcher.instance.onError = (error, stack) {
      captureException(error, stack);
      return _originalOnPlatformError?.call(error, stack) ?? false;
    };

    _initialized = true;
  }

  /// Capture an exception and send as crash report.
  ///
  /// ```dart
  /// try {
  ///   riskyOperation();
  /// } catch (e, stack) {
  ///   Bugstr.captureException(e, stack);
  /// }
  /// ```
  static void captureException(Object error, [StackTrace? stackTrace]) {
    if (!_initialized || _config == null) {
      debugPrint('Bugstr not initialized; dropping error');
      return;
    }

    final payload = CrashPayload.fromError(
      error,
      stackTrace,
      environment: _config!.environment,
      release: _config!.release,
      maxStackCharacters: _config!.maxStackCharacters,
      redactPatterns: _config!.effectiveRedactPatterns,
    );

    _maybeSend(payload);
  }

  /// Capture a message as crash report.
  static void captureMessage(String message) {
    captureException(Exception(message));
  }

  /// Decode npub to hex pubkey.
  static String? _decodePubkey(String pubkey) {
    if (pubkey.isEmpty) return null;
    if (pubkey.startsWith('npub')) {
      try {
        final decoded = Nip19.decodePubkey(pubkey);
        return decoded;
      } catch (_) {
        return null;
      }
    }
    return pubkey;
  }

  /// Generate a random timestamp within the past 2 days (for privacy).
  static int _randomPastTimestamp() {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final maxOffset = 60 * 60 * 24 * 2; // 2 days in seconds
    final offset = Random.secure().nextInt(maxOffset);
    return now - offset;
  }

  /// Apply hooks and send payload.
  static Future<void> _maybeSend(CrashPayload payload) async {
    if (_config == null) return;

    // Apply beforeSend hook
    var finalPayload = payload;
    if (_config!.beforeSend != null) {
      final result = _config!.beforeSend!(payload.toJson());
      if (result == null) return; // Dropped
      finalPayload = CrashPayload.fromJson(result);
    }

    // Apply confirmSend hook
    if (_config!.confirmSend != null) {
      final stackPreview = finalPayload.stack?.split('\n').take(3).join('\n');
      final shouldSend =
          await _config!.confirmSend!(finalPayload.message, stackPreview);
      if (!shouldSend) return;
    }

    // Send in background
    unawaited(_sendToNostr(finalPayload));
  }

  /// Build a NIP-17 gift-wrapped event for a rumor.
  static Nip01Event _buildGiftWrap(int rumorKind, String content) {
    // NIP-59: rumor uses actual timestamp, only seal/gift-wrap are randomized
    final rumorCreatedAt = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final rumorTags = [
      ['p', _developerPubkeyHex!]
    ];

    final serialized = jsonEncode([
      0,
      _senderKeys!.publicKey,
      rumorCreatedAt,
      rumorKind,
      rumorTags,
      content,
    ]);
    final rumorId = sha256.convert(utf8.encode(serialized)).toString();

    final rumor = {
      'id': rumorId,
      'pubkey': _senderKeys!.publicKey,
      'created_at': rumorCreatedAt,
      'kind': rumorKind,
      'tags': rumorTags,
      'content': content,
      'sig': '',
    };

    final rumorJson = jsonEncode(rumor);

    final sealContent = Nip44.encrypt(
      _senderKeys!.privateKey,
      _developerPubkeyHex!,
      rumorJson,
    );

    final sealEvent = Nip01Event(
      pubKey: _senderKeys!.publicKey,
      kind: 13,
      tags: [],
      content: sealContent,
      createdAt: _randomPastTimestamp(),
    );
    sealEvent.sign(_senderKeys!.privateKey);

    final wrapperKeys = KeyPair.generate();
    final giftContent = Nip44.encrypt(
      wrapperKeys.privateKey,
      _developerPubkeyHex!,
      sealEvent.toJsonString(),
    );

    final giftWrap = Nip01Event(
      pubKey: wrapperKeys.publicKey,
      kind: 1059,
      tags: [
        ['p', _developerPubkeyHex!]
      ],
      content: giftContent,
      createdAt: _randomPastTimestamp(),
    );
    giftWrap.sign(wrapperKeys.privateKey);

    return giftWrap;
  }

  /// Build a public chunk event (kind 10422).
  static Nip01Event _buildChunkEvent(ChunkData chunk) {
    final chunkKeys = KeyPair.generate();
    final chunkPayloadData = ChunkPayload(
      index: chunk.index,
      hash: encodeChunkHash(chunk),
      data: encodeChunkData(chunk),
    );

    final event = Nip01Event(
      pubKey: chunkKeys.publicKey,
      kind: kindChunk,
      tags: [],
      content: jsonEncode(chunkPayloadData.toJson()),
      createdAt: _randomPastTimestamp(),
    );
    event.sign(chunkKeys.privateKey);
    return event;
  }

  /// Publish event to first successful relay.
  static Future<void> _publishToRelays(Nip01Event event) async {
    for (final relayUrl in _config!.effectiveRelays) {
      try {
        await _publishToRelay(relayUrl, event);
        return;
      } catch (e) {
        debugPrint('Bugstr: Failed to publish to $relayUrl: $e');
      }
    }
  }

  /// Publish event to all relays (for chunk redundancy).
  static Future<void> _publishToAllRelays(Nip01Event event) async {
    final futures = _config!.effectiveRelays.map((url) async {
      try {
        await _publishToRelay(url, event);
      } catch (e) {
        debugPrint('Bugstr: Failed to publish chunk to $url: $e');
      }
    });
    await Future.wait(futures);
  }

  /// Wait for relay rate limit if needed.
  static Future<void> _waitForRateLimit(String relayUrl) async {
    final rateLimit = getRelayRateLimit(relayUrl);
    final lastTime = _lastPostTime[relayUrl] ?? 0;
    final now = DateTime.now().millisecondsSinceEpoch;
    final elapsed = now - lastTime;

    if (elapsed < rateLimit) {
      final waitMs = rateLimit - elapsed;
      debugPrint('Bugstr: rate limit wait ${waitMs}ms for $relayUrl');
      await Future.delayed(Duration(milliseconds: waitMs));
    }
  }

  /// Record post time for rate limiting.
  static void _recordPostTime(String relayUrl) {
    _lastPostTime[relayUrl] = DateTime.now().millisecondsSinceEpoch;
  }

  /// Publish chunk to a single relay with rate limiting.
  static Future<void> _publishChunkToRelay(
      String relayUrl, Nip01Event event) async {
    await _waitForRateLimit(relayUrl);
    await _publishToRelay(relayUrl, event);
    _recordPostTime(relayUrl);
  }

  /// Verify a chunk event exists on a relay.
  static Future<bool> _verifyChunkExists(String relayUrl, String eventId) async {
    try {
      final ndk = Ndk.defaultConfig();
      await ndk.relays.connectRelay(relayUrl);

      // Query for the specific event by ID
      final filter = Filter(
        ids: [eventId],
        kinds: [kindChunk],
        limit: 1,
      );

      final events = await ndk.requests
          .query(filters: [filter], relayUrls: [relayUrl])
          .timeout(const Duration(seconds: 5));

      await ndk.relays.disconnectRelay(relayUrl);

      return events.isNotEmpty;
    } catch (e) {
      debugPrint('Bugstr: verify chunk failed on $relayUrl: $e');
      return false;
    }
  }

  /// Publish chunk with verification and retry on failure.
  /// Returns the relay URL where the chunk was successfully published, or null if all failed.
  static Future<String?> _publishChunkWithVerify(
      Nip01Event event, List<String> relays, int startIndex) async {
    final numRelays = relays.length;

    // Try each relay starting from startIndex (round-robin)
    for (var attempt = 0; attempt < numRelays; attempt++) {
      final relayUrl = relays[(startIndex + attempt) % numRelays];

      try {
        // Publish with rate limiting
        await _publishChunkToRelay(relayUrl, event);

        // Brief delay before verification to allow relay to process
        await Future.delayed(const Duration(milliseconds: 500));

        // Verify the chunk exists
        if (await _verifyChunkExists(relayUrl, event.id)) {
          return relayUrl;
        }
        debugPrint('Bugstr: chunk verification failed on $relayUrl, trying next');
      } catch (e) {
        debugPrint('Bugstr: chunk publish failed on $relayUrl: $e');
      }
      // Try next relay
    }

    return null; // All relays failed
  }

  /// Estimate total upload time based on chunks and relays.
  static int _estimateUploadSeconds(int totalChunks, int numRelays) {
    // With round-robin, effective rate is numRelays * (1 post / 7.5s)
    // Time per chunk = 7.5s / numRelays
    final msPerChunk = defaultRelayRateLimit ~/ numRelays;
    return (totalChunks * msPerChunk / 1000).ceil();
  }

  /// Send payload via NIP-17 gift wrap, using chunking for large payloads.
  /// Uses round-robin relay distribution to maximize throughput while
  /// respecting per-relay rate limits (8 posts/min for strfry+noteguard).
  static Future<void> _sendToNostr(CrashPayload payload) async {
    if (_senderKeys == null || _developerPubkeyHex == null || _config == null) {
      return;
    }

    try {
      final plaintext = payload.toJsonString();
      final content = maybeCompressPayload(plaintext);
      final payloadBytes = Uint8List.fromList(utf8.encode(content));
      final transportKind = getTransportKind(payloadBytes.length);

      if (transportKind == TransportKind.direct) {
        // Small payload: direct gift-wrapped delivery (no progress needed)
        final directPayload = DirectPayload(crash: payload.toJson());
        final giftWrap =
            _buildGiftWrap(kindDirect, jsonEncode(directPayload.toJson()));
        await _publishToRelays(giftWrap);
        debugPrint('Bugstr: sent direct crash report');
      } else {
        // Large payload: chunked delivery with round-robin distribution
        debugPrint(
            'Bugstr: payload ${payloadBytes.length} bytes, using chunked transport');

        final result = chunkPayload(payloadBytes);
        final totalChunks = result.chunks.length;
        final relays = _config!.effectiveRelays;
        debugPrint('Bugstr: split into $totalChunks chunks across ${relays.length} relays');

        // Report initial progress
        final estimatedSeconds = _estimateUploadSeconds(totalChunks, relays.length);
        _onProgress?.call(BugstrProgress.preparing(totalChunks, estimatedSeconds));

        // Build chunk events and track relay assignments with verification
        final chunkIds = <String>[];
        final chunkRelays = <String, List<String>>{};

        for (var i = 0; i < totalChunks; i++) {
          final chunk = result.chunks[i];
          final chunkEvent = _buildChunkEvent(chunk);
          chunkIds.add(chunkEvent.id);

          // Publish with verification and retry (starts at round-robin relay)
          final successRelay =
              await _publishChunkWithVerify(chunkEvent, relays, i % relays.length);
          if (successRelay != null) {
            chunkRelays[chunkEvent.id] = [successRelay];
          }
          // If all relays failed, chunk is lost - receiver will report missing chunk

          // Report progress
          final remainingChunks = totalChunks - i - 1;
          final remainingSeconds =
              _estimateUploadSeconds(remainingChunks, relays.length);
          _onProgress
              ?.call(BugstrProgress.uploading(i + 1, totalChunks, remainingSeconds));
        }
        debugPrint('Bugstr: published $totalChunks chunks');

        // Report finalizing
        _onProgress?.call(BugstrProgress.finalizing(totalChunks));

        // Build and publish manifest with relay hints
        final manifest = ManifestPayload(
          rootHash: result.rootHash,
          totalSize: result.totalSize,
          chunkCount: totalChunks,
          chunkIds: chunkIds,
          chunkRelays: chunkRelays,
        );
        final manifestGiftWrap =
            _buildGiftWrap(kindManifest, jsonEncode(manifest.toJson()));
        await _publishToRelays(manifestGiftWrap);
        debugPrint('Bugstr: sent chunked crash report manifest');

        // Report complete
        _onProgress?.call(BugstrProgress.completed(totalChunks));
      }
    } catch (e) {
      debugPrint('Bugstr: Failed to send crash report: $e');
    }
  }

  /// Publish event to a single relay.
  static Future<void> _publishToRelay(String url, Nip01Event event) async {
    final ndk = Ndk.defaultConfig();
    await ndk.relays.connectRelay(url);
    await ndk.relays.publish(event);
    await ndk.relays.disconnectRelay(url);
  }
}
