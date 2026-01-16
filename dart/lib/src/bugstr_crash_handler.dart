/// Crash handler for capturing uncaught exceptions.
///
/// Installs handlers for Flutter and Dart zone errors, caches reports
/// to disk, and provides hooks for custom attachments.
///
/// ```dart
/// void main() {
///   BugstrCrashHandler.install(
///     cache: BugstrCrashReportCache(),
///     assembler: BugstrReportAssembler(
///       appName: 'My App',
///       appVersion: '1.0.0',
///     ),
///   );
///   runApp(MyApp());
/// }
/// ```
library;

// TODO: Implement crash handler
// - FlutterError.onError handler
// - PlatformDispatcher.onError handler
// - Zone error handling
// - Async crash writing with timeout

/// Configuration for the crash handler.
class BugstrCrashHandlerConfig {
  /// Maximum time to wait for crash report to be written.
  final Duration writeTimeout;

  /// Provider for custom attachments (logs, state, etc.).
  final Future<Map<String, String>> Function()? attachmentsProvider;

  const BugstrCrashHandlerConfig({
    this.writeTimeout = const Duration(seconds: 1),
    this.attachmentsProvider,
  });
}

/// Installs crash handlers and writes reports to cache.
class BugstrCrashHandler {
  // TODO: Implement
  static void install({
    required BugstrCrashReportCache cache,
    required BugstrReportAssembler assembler,
    BugstrCrashHandlerConfig config = const BugstrCrashHandlerConfig(),
  }) {
    throw UnimplementedError('BugstrCrashHandler not yet implemented');
  }
}

// Placeholder imports - will be real once implemented
class BugstrCrashReportCache {
  const BugstrCrashReportCache();
}

class BugstrReportAssembler {
  final String appName;
  final String appVersion;

  const BugstrReportAssembler({
    required this.appName,
    required this.appVersion,
  });
}
