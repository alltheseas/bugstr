/// CHK (Content Hash Key) chunking for large crash reports.
///
/// Implements hashtree-core compatible encryption where:
/// - Data is split into fixed-size chunks
/// - Each chunk's content hash is derived via HKDF to get the encryption key
/// - AES-256-GCM with zero nonce encrypts each chunk
/// - A root hash is computed from all chunk hashes
/// - Only the manifest (with root hash) needs to be encrypted via NIP-17
/// - Chunks are public but opaque without the root hash
///
/// **CRITICAL**: Must match hashtree-core crypto exactly:
/// - Key derivation: HKDF-SHA256(content_hash, salt="hashtree-chk", info="encryption-key")
/// - Cipher: AES-256-GCM with 12-byte zero nonce
/// - Format: [ciphertext][16-byte auth tag]
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'transport.dart';

/// HKDF salt for CHK derivation (must match hashtree-core)
const _chkSalt = 'hashtree-chk';

/// HKDF info for key derivation (must match hashtree-core)
const _chkInfo = 'encryption-key';

/// Nonce size for AES-GCM (96 bits)
const _nonceSize = 12;

/// Auth tag size for AES-GCM (128 bits)
const _tagSize = 16;

/// Encrypted chunk data before publishing.
class ChunkData {
  final int index;
  final Uint8List hash;
  final Uint8List encrypted;

  const ChunkData({
    required this.index,
    required this.hash,
    required this.encrypted,
  });
}

/// Result of chunking a payload.
class ChunkingResult {
  final String rootHash;
  final int totalSize;
  final List<ChunkData> chunks;

  const ChunkingResult({
    required this.rootHash,
    required this.totalSize,
    required this.chunks,
  });
}

/// Derives encryption key from content hash using HKDF-SHA256.
/// Must match hashtree-core: HKDF(content_hash, salt="hashtree-chk", info="encryption-key")
Uint8List _deriveKey(Uint8List contentHash) {
  final hkdf = HKDFKeyDerivator(HMac(SHA256Digest(), 64));
  hkdf.init(HkdfParameters(
    contentHash,
    32, // Output key length
    Uint8List.fromList(utf8.encode(_chkSalt)),
    Uint8List.fromList(utf8.encode(_chkInfo)),
  ));

  final key = Uint8List(32);
  hkdf.deriveKey(null, 0, key, 0);
  return key;
}

/// Encrypts data using AES-256-GCM with zero nonce (CHK-safe).
/// Returns: [ciphertext][16-byte auth tag]
///
/// Zero nonce is safe for CHK because same key = same content (convergent encryption).
Uint8List _chkEncrypt(Uint8List data, Uint8List contentHash) {
  final key = _deriveKey(contentHash);
  final zeroNonce = Uint8List(_nonceSize); // All zeros

  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(
    true, // encrypt
    AEADParameters(
      KeyParameter(key),
      _tagSize * 8, // tag length in bits
      zeroNonce,
      Uint8List(0), // no associated data
    ),
  );

  final ciphertext = Uint8List(cipher.getOutputSize(data.length));
  final len = cipher.processBytes(data, 0, data.length, ciphertext, 0);
  cipher.doFinal(ciphertext, len);

  return ciphertext; // Includes auth tag appended by GCM
}

/// Decrypts data using AES-256-GCM with zero nonce.
/// Expects: [ciphertext][16-byte auth tag]
Uint8List chkDecrypt(Uint8List data, Uint8List contentHash) {
  final key = _deriveKey(contentHash);
  final zeroNonce = Uint8List(_nonceSize);

  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(
    false, // decrypt
    AEADParameters(
      KeyParameter(key),
      _tagSize * 8,
      zeroNonce,
      Uint8List(0),
    ),
  );

  final plaintext = Uint8List(cipher.getOutputSize(data.length));
  final len = cipher.processBytes(data, 0, data.length, plaintext, 0);
  cipher.doFinal(plaintext, len);

  // Remove padding (GCM output size includes space for tag on decrypt)
  return plaintext.sublist(0, data.length - _tagSize);
}

/// Computes SHA-256 hash of data.
Uint8List _sha256(Uint8List data) {
  return Uint8List.fromList(sha256.convert(data).bytes);
}

/// Converts bytes to lowercase hex string.
String _bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Splits payload into chunks and encrypts each using CHK.
///
/// Each chunk is encrypted with a key derived from its content hash via HKDF.
/// The root hash is computed by hashing all chunk hashes concatenated.
///
/// **CRITICAL**: Uses hashtree-core compatible encryption:
/// - HKDF-SHA256 key derivation with salt="hashtree-chk"
/// - AES-256-GCM with zero nonce
ChunkingResult chunkPayload(Uint8List data, {int chunkSize = maxChunkSize}) {
  final chunks = <ChunkData>[];
  final chunkHashes = <Uint8List>[];

  var offset = 0;
  var index = 0;
  while (offset < data.length) {
    final end = offset + chunkSize > data.length ? data.length : offset + chunkSize;
    final chunkData = data.sublist(offset, end);

    // Compute hash of plaintext chunk (used for key derivation)
    final hash = _sha256(chunkData);
    chunkHashes.add(hash);

    // Encrypt chunk using HKDF-derived key from hash
    final encrypted = _chkEncrypt(chunkData, hash);

    chunks.add(ChunkData(
      index: index,
      hash: hash,
      encrypted: encrypted,
    ));

    offset = end;
    index++;
  }

  // Compute root hash from all chunk hashes
  final rootHashInput = Uint8List.fromList(
    chunkHashes.expand((h) => h).toList(),
  );
  final rootHash = _bytesToHex(_sha256(rootHashInput));

  return ChunkingResult(
    rootHash: rootHash,
    totalSize: data.length,
    chunks: chunks,
  );
}

/// Converts chunk data to base64 for transport.
String encodeChunkData(ChunkData chunk) {
  return base64Encode(chunk.encrypted);
}

/// Converts chunk hash to hex string.
String encodeChunkHash(ChunkData chunk) {
  return _bytesToHex(chunk.hash);
}

/// Estimates the number of chunks needed for a payload size.
int estimateChunkCount(int payloadSize, {int chunkSize = maxChunkSize}) {
  return (payloadSize / chunkSize).ceil();
}
