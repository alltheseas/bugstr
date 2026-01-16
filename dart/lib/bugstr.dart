/// Bugstr - Privacy-focused crash reporting for Flutter/Dart
///
/// Delivers crash reports via NIP-17 gift-wrapped encrypted DMs
/// with user consent and auto-expiration.
library bugstr;

export 'src/bugstr_crash_handler.dart';
export 'src/bugstr_crash_report_cache.dart';
export 'src/bugstr_report_assembler.dart';
export 'src/nip17_payload_builder.dart';
export 'src/compression.dart';
