/// NIP-17 gift wrap payload builder.
///
/// Builds unsigned NIP-17 gift wraps (kind 1059) around chat rumors.
/// Implements NIP-17, NIP-44, NIP-59, and NIP-40 specifications.
///
/// ```dart
/// final builder = Nip17PayloadBuilder(encryptor: myNip44Encryptor);
/// final wraps = builder.buildGiftWraps(Nip17Request(
///   senderPubKey: myPubKey,
///   senderPrivateKeyHex: myPrivKey,
///   recipients: [Nip17Recipient(pubKeyHex: devPubKey)],
///   plaintext: crashReport,
///   expirationSeconds: 30 * 24 * 60 * 60, // 30 days
/// ));
/// ```
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

// TODO: Implement NIP-17 gift wrap
// - NIP-44 encryption (requires external library)
// - Timestamp randomization (±2 days)
// - Ephemeral key generation for gift wrap
// - Event ID computation per NIP-01

/// Request to build NIP-17 gift wraps.
class Nip17Request {
  final String senderPubKey;
  final String senderPrivateKeyHex;
  final List<Nip17Recipient> recipients;
  final String plaintext;
  final int? expirationSeconds;

  const Nip17Request({
    required this.senderPubKey,
    required this.senderPrivateKeyHex,
    required this.recipients,
    required this.plaintext,
    this.expirationSeconds,
  });
}

/// A recipient for NIP-17 messages.
class Nip17Recipient {
  final String pubKeyHex;
  final String? relayHint;

  const Nip17Recipient({
    required this.pubKeyHex,
    this.relayHint,
  });
}

/// Result of building a gift wrap.
class Nip17GiftWrap {
  final UnsignedNostrEvent rumor;
  final UnsignedNostrEvent seal;
  final UnsignedNostrEvent giftWrap;
  final String giftWrapPrivateKeyHex;

  const Nip17GiftWrap({
    required this.rumor,
    required this.seal,
    required this.giftWrap,
    required this.giftWrapPrivateKeyHex,
  });
}

/// Minimal unsigned Nostr event representation.
///
/// Per NIP-17, rumors (kind 14) must include:
/// - `id`: SHA256 hash of serialized event data
/// - `sig`: Empty string (not omitted) to indicate unsigned status
class UnsignedNostrEvent {
  final String pubKey;
  final int createdAt;
  final int kind;
  final List<List<String>> tags;
  final String content;
  final String sig;

  const UnsignedNostrEvent({
    required this.pubKey,
    required this.createdAt,
    required this.kind,
    required this.tags,
    required this.content,
    this.sig = '',
  });

  /// Compute event ID per NIP-01.
  ///
  /// ID = SHA256([0, pubkey, created_at, kind, tags, content])
  String computeId() {
    final serialized = jsonEncode([
      0,
      pubKey.toLowerCase(),
      createdAt,
      kind,
      tags,
      content,
    ]);
    final bytes = utf8.encode(serialized);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  /// Serialize to JSON with all required fields.
  Map<String, dynamic> toJson() => {
        'id': computeId(),
        'pubkey': pubKey.toLowerCase(),
        'created_at': createdAt,
        'kind': kind,
        'tags': tags,
        'content': content,
        'sig': sig,
      };
}

/// Interface for NIP-44 encryption.
abstract class Nip44Encryptor {
  String encrypt({
    required String senderPrivateKeyHex,
    required String receiverPubKeyHex,
    required String plaintext,
  });
}

/// Builds NIP-17 gift wraps.
class Nip17PayloadBuilder {
  final Nip44Encryptor encryptor;

  const Nip17PayloadBuilder({required this.encryptor});

  /// Build gift wraps for all recipients.
  List<Nip17GiftWrap> buildGiftWraps(Nip17Request request) {
    // TODO: Implement
    throw UnimplementedError();
  }
}
