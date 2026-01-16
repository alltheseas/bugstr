import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:bugstr/bugstr.dart';

void main() {
  group('compressPayload', () {
    test('produces valid envelope', () {
      const plaintext = 'Hello, World!';
      final envelope = compressPayload(plaintext);
      final parsed = jsonDecode(envelope) as Map<String, dynamic>;

      expect(parsed['v'], 1);
      expect(parsed['compression'], 'gzip');
      expect(parsed['payload'], isA<String>());
    });
  });

  group('decompressPayload', () {
    test('round-trips correctly', () {
      const plaintext = '''Test crash report with stack trace
Error: NullPointerException
    at MyClass.method (MyClass.dart:42)''';

      final compressed = compressPayload(plaintext);
      final decompressed = decompressPayload(compressed);

      expect(decompressed, plaintext);
    });

    test('handles raw plaintext', () {
      const plaintext = 'This is not compressed';
      final result = decompressPayload(plaintext);

      expect(result, plaintext);
    });

    test('handles non-compression JSON', () {
      const json = '{"message": "error", "code": 500}';
      final result = decompressPayload(json);

      expect(result, json);
    });
  });

  group('shouldCompress', () {
    test('returns false for small payloads', () {
      expect(shouldCompress('tiny', threshold: 1024), isFalse);
    });

    test('returns true for large payloads', () {
      final large = 'x' * 2000;
      expect(shouldCompress(large, threshold: 1024), isTrue);
    });
  });

  group('maybeCompressPayload', () {
    test('skips small payloads', () {
      const small = 'tiny';
      final result = maybeCompressPayload(small, threshold: 1024);

      expect(result, small);
    });

    test('compresses large payloads', () {
      final large = 'x' * 2000;
      final result = maybeCompressPayload(large, threshold: 1024);
      final parsed = jsonDecode(result) as Map<String, dynamic>;

      expect(parsed['compression'], 'gzip');
      expect(decompressPayload(result), large);
    });
  });

  group('compression ratio', () {
    test('achieves significant size reduction for text', () {
      final stackTrace = List.generate(
        100,
        (i) => 'Error: RuntimeException $i\n    at Class$i.method (Class$i.dart:$i)',
      ).join('\n');

      final compressed = compressPayload(stackTrace);
      final originalSize = utf8.encode(stackTrace).length;
      final compressedSize = utf8.encode(compressed).length;

      // Text should compress to less than 50% of original
      expect(
        compressedSize,
        lessThan(originalSize ~/ 2),
        reason: 'Compression ratio should be < 0.5',
      );
    });
  });
}
