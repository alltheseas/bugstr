/// CHK (Content Hash Key) chunking for large crash reports.
///
/// Implements hashtree-style encryption where:
/// - Data is split into fixed-size chunks
/// - Each chunk is encrypted using its content hash as the key
/// - A root hash is computed from all chunk hashes
/// - Only the manifest (with root hash) needs to be encrypted via NIP-17
/// - Chunks are public but opaque without the root hash
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'transport.dart';

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

/// Encrypts data using AES-256-CBC with the given key.
/// IV is prepended to the ciphertext.
Uint8List _chkEncrypt(Uint8List data, Uint8List key) {
  final iv = encrypt.IV.fromSecureRandom(16);
  final encrypter = encrypt.Encrypter(
    encrypt.AES(encrypt.Key(key), mode: encrypt.AESMode.cbc),
  );
  final encrypted = encrypter.encryptBytes(data, iv: iv);

  // Prepend IV to ciphertext
  final result = Uint8List(iv.bytes.length + encrypted.bytes.length);
  result.setRange(0, iv.bytes.length, iv.bytes);
  result.setRange(iv.bytes.length, result.length, encrypted.bytes);
  return result;
}

/// Decrypts data using AES-256-CBC with the given key.
/// Expects IV prepended to the ciphertext.
Uint8List chkDecrypt(Uint8List data, Uint8List key) {
  final iv = encrypt.IV(data.sublist(0, 16));
  final ciphertext = encrypt.Encrypted(data.sublist(16));
  final encrypter = encrypt.Encrypter(
    encrypt.AES(encrypt.Key(key), mode: encrypt.AESMode.cbc),
  );
  return Uint8List.fromList(encrypter.decryptBytes(ciphertext, iv: iv));
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
/// Each chunk is encrypted with its own content hash as the key.
/// The root hash is computed by hashing all chunk hashes concatenated.
ChunkingResult chunkPayload(Uint8List data, {int chunkSize = maxChunkSize}) {
  final chunks = <ChunkData>[];
  final chunkHashes = <Uint8List>[];

  var offset = 0;
  var index = 0;
  while (offset < data.length) {
    final end = offset + chunkSize > data.length ? data.length : offset + chunkSize;
    final chunkData = data.sublist(offset, end);

    // Compute hash of plaintext chunk (becomes encryption key)
    final hash = _sha256(chunkData);
    chunkHashes.add(hash);

    // Encrypt chunk using its hash as key
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
