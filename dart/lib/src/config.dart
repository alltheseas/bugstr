/// Configuration for Bugstr crash reporting.
library;

/// Default relay URLs chosen for reliability and generous size limits.
///
/// | Relay | Max Size |
/// |-------|----------|
/// | relay.damus.io | 1 MB |
/// | relay.primal.net | 1 MB |
/// | nos.lol | 128 KB |
const List<String> defaultRelays = [
  'wss://relay.damus.io',
  'wss://relay.primal.net',
  'wss://nos.lol',
];

/// Default patterns for redacting sensitive data from crash reports.
final List<RegExp> defaultRedactionPatterns = [
  RegExp(r'cashuA[a-zA-Z0-9]+'), // Cashu tokens
  RegExp(r'lnbc[a-z0-9]+', caseSensitive: false), // Lightning invoices
  RegExp(r'npub1[a-z0-9]+', caseSensitive: false), // Nostr public keys
  RegExp(r'nsec1[a-z0-9]+', caseSensitive: false), // Nostr secret keys
  RegExp(r'https?://[^\s"]*mint[^\s"]*', caseSensitive: false), // Mint URLs
];

/// Configuration for Bugstr.
class BugstrConfig {
  /// Recipient's public key (npub or hex).
  final String developerPubkey;

  /// Relay URLs to publish crash reports to.
  final List<String> relays;

  /// Environment tag (e.g., 'production', 'staging').
  final String? environment;

  /// Release version tag.
  final String? release;

  /// Patterns for redacting sensitive data.
  final List<RegExp> redactPatterns;

  /// Maximum stack trace characters before truncation.
  final int maxStackCharacters;

  /// Hook to modify/filter payloads before sending.
  /// Return null to drop the payload.
  final BugstrPayload? Function(BugstrPayload payload)? beforeSend;

  /// Hook to confirm before sending.
  /// Return true to send, false to cancel.
  final Future<bool> Function(String message, String? stackPreview)? confirmSend;

  const BugstrConfig({
    required this.developerPubkey,
    this.relays = const [],
    this.environment,
    this.release,
    this.redactPatterns = const [],
    this.maxStackCharacters = 200000,
    this.beforeSend,
    this.confirmSend,
  });

  /// Returns relays to use, falling back to defaults if empty.
  List<String> get effectiveRelays =>
      relays.isNotEmpty ? relays : defaultRelays;

  /// Returns redaction patterns to use, falling back to defaults if empty.
  List<RegExp> get effectiveRedactPatterns =>
      redactPatterns.isNotEmpty ? redactPatterns : defaultRedactionPatterns;
}

/// Placeholder for payload type - defined in payload.dart
typedef BugstrPayload = Map<String, dynamic>;
