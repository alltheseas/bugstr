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

  Bugstr._();

  /// Initialize Bugstr with the given configuration.
  ///
  /// This installs global error handlers for Flutter and Dart errors.
  /// Call this early in your app's main() function.
  ///
  /// ```dart
  /// void main() {
  ///   Bugstr.init(
  ///     developerPubkey: 'npub1...',
  ///     environment: 'production',
  ///     release: '1.0.0',
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
    final rumorCreatedAt = _randomPastTimestamp();
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

  /// Send payload via NIP-17 gift wrap, using chunking for large payloads.
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
        // Small payload: direct gift-wrapped delivery
        final directPayload = DirectPayload(crash: payload.toJson());
        final giftWrap = _buildGiftWrap(kindDirect, jsonEncode(directPayload.toJson()));
        await _publishToRelays(giftWrap);
        debugPrint('Bugstr: sent direct crash report');
      } else {
        // Large payload: chunked delivery
        debugPrint('Bugstr: payload ${payloadBytes.length} bytes, using chunked transport');

        final result = chunkPayload(payloadBytes);
        debugPrint('Bugstr: split into ${result.chunks.length} chunks');

        // Build and publish chunk events
        final chunkIds = <String>[];
        for (final chunk in result.chunks) {
          final chunkEvent = _buildChunkEvent(chunk);
          chunkIds.add(chunkEvent.id);
          await _publishToAllRelays(chunkEvent);
        }
        debugPrint('Bugstr: published ${result.chunks.length} chunks');

        // Build and publish manifest
        final manifest = ManifestPayload(
          rootHash: result.rootHash,
          totalSize: result.totalSize,
          chunkCount: result.chunks.length,
          chunkIds: chunkIds,
        );
        final manifestGiftWrap = _buildGiftWrap(kindManifest, jsonEncode(manifest.toJson()));
        await _publishToRelays(manifestGiftWrap);
        debugPrint('Bugstr: sent chunked crash report manifest');
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
