import 'package:flutter_test/flutter_test.dart';
import 'package:bugstr/bugstr.dart';

void main() {
  group('UnsignedNostrEvent', () {
    test('computeId returns valid hex', () {
      final event = UnsignedNostrEvent(
        pubKey: 'a' * 64,
        createdAt: 1234567890,
        kind: 14,
        tags: [],
        content: 'test',
      );

      final id = event.computeId();

      expect(id.length, 64);
      expect(RegExp(r'^[a-f0-9]{64}$').hasMatch(id), isTrue);
    });

    test('computeId is deterministic', () {
      final event = UnsignedNostrEvent(
        pubKey: 'a' * 64,
        createdAt: 1234567890,
        kind: 14,
        tags: [
          ['p', 'b' * 64],
        ],
        content: 'hello',
      );

      final id1 = event.computeId();
      final id2 = event.computeId();

      expect(id1, id2);
    });

    test('computeId changes with content', () {
      final event1 = UnsignedNostrEvent(
        pubKey: 'a' * 64,
        createdAt: 1234567890,
        kind: 14,
        tags: [],
        content: 'hello',
      );

      final event2 = UnsignedNostrEvent(
        pubKey: 'a' * 64,
        createdAt: 1234567890,
        kind: 14,
        tags: [],
        content: 'world',
      );

      expect(event1.computeId(), isNot(event2.computeId()));
    });

    test('toJson includes id and sig', () {
      final event = UnsignedNostrEvent(
        pubKey: 'A' * 64, // uppercase to test normalization
        createdAt: 1234567890,
        kind: 14,
        tags: [
          ['p', 'b' * 64],
        ],
        content: 'crash report',
      );

      final json = event.toJson();

      expect(json['id'], isA<String>());
      expect(json['sig'], '');
      expect(json['pubkey'], 'a' * 64); // should be lowercase
      expect(json['kind'], 14);
    });

    test('sig defaults to empty string', () {
      final event = UnsignedNostrEvent(
        pubKey: 'a' * 64,
        createdAt: 1234567890,
        kind: 14,
        tags: [],
        content: 'test',
      );

      expect(event.sig, '');
    });
  });
}
