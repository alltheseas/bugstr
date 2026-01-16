/// Local file-based crash report storage with rotation.
///
/// Stores crash reports on disk with configurable slot rotation.
/// Reports persist across app restarts for user consent flow.
///
/// ```dart
/// final cache = BugstrCrashReportCache(maxReports: 3);
/// await cache.write(report);
/// final reports = await cache.readAll();
/// await cache.clear(report.id);
/// ```
library;

import 'dart:async';

// TODO: Implement cache
// - Use path_provider for app documents directory
// - JSON serialization for reports
// - Slot-based rotation (oldest deleted when full)
// - Atomic writes to prevent corruption

/// A cached crash report.
class CrashReport {
  final String id;
  final DateTime timestamp;
  final String content;

  const CrashReport({
    required this.id,
    required this.timestamp,
    required this.content,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'timestamp': timestamp.toIso8601String(),
        'content': content,
      };

  factory CrashReport.fromJson(Map<String, dynamic> json) => CrashReport(
        id: json['id'] as String,
        timestamp: DateTime.parse(json['timestamp'] as String),
        content: json['content'] as String,
      );
}

/// Caches crash reports to disk with rotation.
class BugstrCrashReportCache {
  /// Maximum number of reports to retain.
  final int maxReports;

  const BugstrCrashReportCache({this.maxReports = 3});

  /// Write a crash report to cache.
  Future<void> write(CrashReport report) async {
    // TODO: Implement
    throw UnimplementedError();
  }

  /// Read all cached reports, newest first.
  Future<List<CrashReport>> readAll() async {
    // TODO: Implement
    throw UnimplementedError();
  }

  /// Clear a specific report by ID.
  Future<void> clear(String id) async {
    // TODO: Implement
    throw UnimplementedError();
  }

  /// Clear all cached reports.
  Future<void> clearAll() async {
    // TODO: Implement
    throw UnimplementedError();
  }
}
