/// Bugstr - Privacy-focused crash reporting for Flutter/Dart
///
/// Delivers crash reports via NIP-17 gift-wrapped encrypted DMs
/// with user consent and auto-expiration.
///
/// ## Quick Start
///
/// ```dart
/// import 'package:bugstr/bugstr.dart';
///
/// void main() {
///   Bugstr.init(
///     developerPubkey: 'npub1...',
///     environment: 'production',
///     release: '1.0.0',
///   );
///
///   runApp(MyApp());
/// }
/// ```
library bugstr;

export 'src/config.dart';
export 'src/payload.dart';
export 'src/bugstr_client.dart';
export 'src/compression.dart';
