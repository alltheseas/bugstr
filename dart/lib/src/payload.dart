/// Crash report payload structure.
library;

import 'dart:convert';
import 'dart:io';

/// A crash report payload.
class CrashPayload {
  /// Error message.
  final String message;

  /// Stack trace (may be truncated/redacted).
  final String? stack;

  /// Timestamp in milliseconds since epoch.
  final int timestamp;

  /// Environment (e.g., 'production').
  final String? environment;

  /// Release version.
  final String? release;

  /// Platform identifier.
  final String? platform;

  /// Device/runtime information.
  final Map<String, dynamic>? deviceInfo;

  const CrashPayload({
    required this.message,
    this.stack,
    required this.timestamp,
    this.environment,
    this.release,
    this.platform,
    this.deviceInfo,
  });

  /// Creates a payload from an error and stack trace.
  factory CrashPayload.fromError(
    Object error,
    StackTrace? stackTrace, {
    String? environment,
    String? release,
    int maxStackCharacters = 200000,
    List<RegExp> redactPatterns = const [],
  }) {
    var message = error.toString();
    var stack = stackTrace?.toString();

    // Apply redaction patterns
    for (final pattern in redactPatterns) {
      message = message.replaceAll(pattern, '[redacted]');
      if (stack != null) {
        stack = stack.replaceAll(pattern, '[redacted]');
      }
    }

    // Truncate stack if needed
    if (stack != null && stack.length > maxStackCharacters) {
      stack = '${stack.substring(0, maxStackCharacters)}\n... [truncated]';
    }

    return CrashPayload(
      message: message.isNotEmpty ? message : 'Unknown error',
      stack: stack,
      timestamp: DateTime.now().millisecondsSinceEpoch,
      environment: environment,
      release: release,
      platform: Platform.operatingSystem,
      deviceInfo: {
        'os': Platform.operatingSystem,
        'osVersion': Platform.operatingSystemVersion,
        'dartVersion': Platform.version,
      },
    );
  }

  /// Converts to JSON map.
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'message': message,
      'timestamp': timestamp,
    };
    if (stack != null) json['stack'] = stack;
    if (environment != null) json['environment'] = environment;
    if (release != null) json['release'] = release;
    if (platform != null) json['platform'] = platform;
    if (deviceInfo != null) json['deviceInfo'] = deviceInfo;
    return json;
  }

  /// Converts to JSON string.
  String toJsonString() => jsonEncode(toJson());

  /// Creates from JSON map.
  factory CrashPayload.fromJson(Map<String, dynamic> json) {
    return CrashPayload(
      message: json['message'] as String,
      stack: json['stack'] as String?,
      timestamp: json['timestamp'] as int,
      environment: json['environment'] as String?,
      release: json['release'] as String?,
      platform: json['platform'] as String?,
      deviceInfo: json['deviceInfo'] as Map<String, dynamic>?,
    );
  }
}
