//! SQLite storage for crash reports.
//!
//! Stores decrypted crash reports with indexing for efficient querying
//! and grouping by fingerprint (Rollbar-style: exception_class + filenames + methods).
//!
//! # Fingerprint Invariants (do not change without updating test-vectors/)
//!
//! - Line numbers MUST be stripped from frame fingerprints
//!   (see test: test_same_stack_different_line_numbers_same_fingerprint)
//! - Framework frames MUST be excluded (dart:*, java.lang.*, node:*, etc.)
//!   (see: is_in_app_frame)
//! - Fingerprints are versioned with "v1:" prefix. Changing the algorithm
//!   requires a new version prefix and migration logic.
//! - Reference vectors: test-vectors/sdk-conformance/fingerprint-vectors.json
//! - Payload schema: test-vectors/sdk-conformance/crash-payload.schema.json

use regex::Regex;
use rusqlite::{params, Connection, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::OnceLock;

/// A stored crash report.
#[derive(Debug, Clone)]
pub struct CrashReport {
    pub id: i64,
    pub event_id: String,
    pub sender_pubkey: String,
    pub received_at: i64,
    pub created_at: i64,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub exception_type: Option<String>,
    pub message: Option<String>,
    pub stack_trace: Option<String>,
    pub raw_content: String,
    pub environment: Option<String>,
    pub release: Option<String>,
    pub fingerprint: Option<String>,
    pub group_title: Option<String>,
    pub is_crash: bool,
}

/// A group of crashes by fingerprint.
#[derive(Debug, Clone)]
pub struct CrashGroup {
    pub fingerprint: String,
    pub title: String,
    pub exception_type: String,
    pub count: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub app_versions: Vec<String>,
    pub sample_message: Option<String>,
}

/// SQLite-backed crash report storage.
pub struct CrashStorage {
    conn: Connection,
}

impl CrashStorage {
    /// Opens or creates a crash storage database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let storage = Self { conn };
        storage.init_schema()?;
        storage.migrate()?;
        Ok(storage)
    }

    /// Opens an in-memory database (useful for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS crashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                sender_pubkey TEXT NOT NULL,
                received_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                app_name TEXT,
                app_version TEXT,
                exception_type TEXT,
                message TEXT,
                stack_trace TEXT,
                raw_content TEXT NOT NULL,
                environment TEXT,
                release TEXT,
                fingerprint TEXT,
                group_title TEXT,
                is_crash INTEGER DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_crashes_received_at ON crashes(received_at DESC);
            CREATE INDEX IF NOT EXISTS idx_crashes_exception_type ON crashes(exception_type);
            CREATE INDEX IF NOT EXISTS idx_crashes_app_version ON crashes(app_version);
            CREATE INDEX IF NOT EXISTS idx_crashes_sender ON crashes(sender_pubkey);
            CREATE INDEX IF NOT EXISTS idx_crashes_fingerprint ON crashes(fingerprint);

            CREATE TABLE IF NOT EXISTS failed_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                relay_url TEXT,
                error_reason TEXT NOT NULL,
                received_at INTEGER NOT NULL
            );
            ",
        )
    }

    /// Migrate existing databases: add new columns if missing.
    fn migrate(&self) -> Result<()> {
        let alters = [
            "ALTER TABLE crashes ADD COLUMN fingerprint TEXT",
            "ALTER TABLE crashes ADD COLUMN group_title TEXT",
            "ALTER TABLE crashes ADD COLUMN is_crash INTEGER DEFAULT 1",
        ];
        for sql in &alters {
            match self.conn.execute_batch(sql) {
                Ok(_) => {}
                Err(e) if e.to_string().contains("duplicate column") => {}
                Err(e) => return Err(e),
            }
        }
        self.conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_crashes_fingerprint ON crashes(fingerprint)"
        )?;
        Ok(())
    }

    /// Backfill fingerprints for rows that have NULL fingerprint.
    /// Also marks URL-only rows as is_crash = 0.
    pub fn backfill_fingerprints(&self) -> Result<usize> {
        let mut stmt = self.conn.prepare(
            "SELECT id, exception_type, message, stack_trace, raw_content
             FROM crashes WHERE fingerprint IS NULL"
        )?;

        let rows: Vec<(i64, Option<String>, Option<String>, Option<String>, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut count = 0;
        for (id, exc_type, msg, stack, raw) in &rows {
            let is_crash = !is_url_only(raw);
            let fp = compute_fingerprint(
                exc_type.as_deref(),
                msg.as_deref(),
                stack.as_deref(),
            );
            let title = compute_group_title(
                exc_type.as_deref(),
                stack.as_deref(),
                msg.as_deref(),
            );
            self.conn.execute(
                "UPDATE crashes SET fingerprint = ?1, group_title = ?2, is_crash = ?3 WHERE id = ?4",
                params![fp, title, is_crash as i32, id],
            )?;
            count += 1;
        }
        Ok(count)
    }

    /// Inserts a new crash report. Returns the inserted row ID.
    /// If the event_id already exists, returns None (duplicate).
    pub fn insert(&self, report: &CrashReport) -> Result<Option<i64>> {
        let result = self.conn.execute(
            "INSERT OR IGNORE INTO crashes (
                event_id, sender_pubkey, received_at, created_at,
                app_name, app_version, exception_type, message,
                stack_trace, raw_content, environment, release,
                fingerprint, group_title, is_crash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                report.event_id,
                report.sender_pubkey,
                report.received_at,
                report.created_at,
                report.app_name,
                report.app_version,
                report.exception_type,
                report.message,
                report.stack_trace,
                report.raw_content,
                report.environment,
                report.release,
                report.fingerprint,
                report.group_title,
                report.is_crash as i32,
            ],
        )?;

        if result == 0 {
            Ok(None) // Duplicate
        } else {
            Ok(Some(self.conn.last_insert_rowid()))
        }
    }

    /// Gets recent crash reports, ordered by received_at descending.
    pub fn get_recent(&self, limit: usize) -> Result<Vec<CrashReport>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_id, sender_pubkey, received_at, created_at,
                    app_name, app_version, exception_type, message,
                    stack_trace, raw_content, environment, release,
                    fingerprint, group_title, is_crash
             FROM crashes
             WHERE is_crash = 1
             ORDER BY received_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| row_to_crash_report(row))?;
        rows.collect()
    }

    /// Gets crash groups aggregated by fingerprint.
    pub fn get_groups(&self, limit: usize) -> Result<Vec<CrashGroup>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                COALESCE(fingerprint, COALESCE(exception_type, 'Unknown')) as fp,
                MAX(COALESCE(group_title, COALESCE(exception_type, 'Unknown'))) as title,
                MAX(COALESCE(exception_type, 'Unknown')) as exc_type,
                COUNT(*) as count,
                MIN(received_at) as first_seen,
                MAX(received_at) as last_seen,
                GROUP_CONCAT(DISTINCT app_version) as versions,
                (SELECT message FROM crashes c2
                 WHERE COALESCE(c2.fingerprint, COALESCE(c2.exception_type, 'Unknown')) = COALESCE(crashes.fingerprint, COALESCE(crashes.exception_type, 'Unknown'))
                   AND c2.is_crash = 1
                 ORDER BY c2.received_at DESC LIMIT 1) as sample_msg
             FROM crashes
             WHERE is_crash = 1
             GROUP BY fp
             ORDER BY last_seen DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            let versions_str: Option<String> = row.get(6)?;
            let app_versions = versions_str
                .map(|s| s.split(',').filter(|v| !v.is_empty()).map(String::from).collect())
                .unwrap_or_default();

            Ok(CrashGroup {
                fingerprint: row.get(0)?,
                title: row.get(1)?,
                exception_type: row.get(2)?,
                count: row.get(3)?,
                first_seen: row.get(4)?,
                last_seen: row.get(5)?,
                app_versions,
                sample_message: row.get(7)?,
            })
        })?;

        rows.collect()
    }

    /// Gets crashes filtered by fingerprint.
    pub fn get_by_fingerprint(&self, fingerprint: &str, limit: usize) -> Result<Vec<CrashReport>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_id, sender_pubkey, received_at, created_at,
                    app_name, app_version, exception_type, message,
                    stack_trace, raw_content, environment, release,
                    fingerprint, group_title, is_crash
             FROM crashes
             WHERE COALESCE(fingerprint, COALESCE(exception_type, 'Unknown')) = ?1
               AND is_crash = 1
             ORDER BY received_at DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![fingerprint, limit], |row| row_to_crash_report(row))?;
        rows.collect()
    }

    /// Gets crashes filtered by exception type (legacy, kept for compatibility).
    pub fn get_by_exception_type(&self, exception_type: &str, limit: usize) -> Result<Vec<CrashReport>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_id, sender_pubkey, received_at, created_at,
                    app_name, app_version, exception_type, message,
                    stack_trace, raw_content, environment, release,
                    fingerprint, group_title, is_crash
             FROM crashes
             WHERE COALESCE(exception_type, 'Unknown') = ?1 AND is_crash = 1
             ORDER BY received_at DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![exception_type, limit], |row| row_to_crash_report(row))?;
        rows.collect()
    }

    /// Gets total crash count (only actual crashes).
    pub fn count(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM crashes WHERE is_crash = 1", [], |row| row.get(0))
    }

    /// Deletes crashes older than the given timestamp.
    pub fn delete_older_than(&self, timestamp: i64) -> Result<usize> {
        self.conn.execute(
            "DELETE FROM crashes WHERE received_at < ?1",
            [timestamp],
        )
    }

    /// Gets a crash by ID.
    pub fn get_by_id(&self, id: i64) -> Result<Option<CrashReport>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_id, sender_pubkey, received_at, created_at,
                    app_name, app_version, exception_type, message,
                    stack_trace, raw_content, environment, release,
                    fingerprint, group_title, is_crash
             FROM crashes
             WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map([id], |row| row_to_crash_report(row))?;
        rows.next().transpose()
    }

    /// Inserts a failed event record (no encrypted content stored for privacy).
    pub fn insert_failed_event(
        &self,
        event_id: &str,
        relay_url: Option<&str>,
        error_reason: &str,
        received_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO failed_events (event_id, relay_url, error_reason, received_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![event_id, relay_url, error_reason, received_at],
        )?;
        Ok(())
    }

    /// Gets the total count of failed events.
    pub fn failed_event_count(&self) -> Result<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM failed_events",
            [],
            |row| row.get(0),
        )
    }
}

fn row_to_crash_report(row: &rusqlite::Row) -> rusqlite::Result<CrashReport> {
    let is_crash_int: i32 = row.get::<_, Option<i32>>(15)?.unwrap_or(1);
    Ok(CrashReport {
        id: row.get(0)?,
        event_id: row.get(1)?,
        sender_pubkey: row.get(2)?,
        received_at: row.get(3)?,
        created_at: row.get(4)?,
        app_name: row.get(5)?,
        app_version: row.get(6)?,
        exception_type: row.get(7)?,
        message: row.get(8)?,
        stack_trace: row.get(9)?,
        raw_content: row.get(10)?,
        environment: row.get(11)?,
        release: row.get(12)?,
        fingerprint: row.get(13)?,
        group_title: row.get(14)?,
        is_crash: is_crash_int != 0,
    })
}

// ============================================================================
// Fingerprint computation (Rollbar-style)
// ============================================================================

/// Returns `true` if `content` is a bare URL rather than a crash report.
///
/// A bare URL is a single line starting with `http://` or `https://`.
/// These are filtered out of crash groups (`is_crash = 0`) during backfill.
///
/// # Examples
/// ```
/// use bugstr::is_url_only;
/// assert!(is_url_only("https://cdn.example.com/file.bin"));
/// assert!(!is_url_only("{\"message\": \"crash\"}"));
/// ```
pub fn is_url_only(content: &str) -> bool {
    let trimmed = content.trim();
    // Single line starting with http
    !trimmed.contains('\n') && (trimmed.starts_with("http://") || trimmed.starts_with("https://"))
}

/// Compute a deterministic fingerprint for crash grouping (Rollbar-style).
///
/// Groups crashes by hashing the exception class and all in-app stack frames
/// (file + method, line numbers stripped). Falls back to a normalized message
/// hash when no parseable in-app frames exist.
///
/// # Parameters
/// - `exception_type`: Exception class name (e.g. `"StateError"`, `"NullPointerException"`).
///   Defaults to `"Unknown"` when `None`.
/// - `message`: Human-readable error message. Used as fallback when no in-app frames found.
///   Variable data (hex, IPs, timestamps, large numbers) is stripped before hashing.
/// - `stack_trace`: Full stack trace as a multi-line string. Supports Dart, Java, and JS
///   frame formats. Only in-app frames contribute to the fingerprint.
///
/// # Returns
/// A fingerprint string in the format `"v1:<32 hex chars>"`.
///
/// # Algorithm
/// ```text
/// input = exception_type + "\n"
/// for each in-app frame: input += normalized_file + ":" + method + "\n"
/// if no in-app frames: input += normalize_message(message)
/// fingerprint = "v1:" + hex(sha256(input))[..32]
/// ```
///
/// # INVARIANT: Changing this algorithm changes ALL fingerprints.
/// Update the version prefix (v1 -> v2), add migration logic for existing
/// databases, and regenerate test-vectors/sdk-conformance/fingerprint-vectors.json.
pub fn compute_fingerprint(
    exception_type: Option<&str>,
    message: Option<&str>,
    stack_trace: Option<&str>,
) -> String {
    let mut input = String::new();

    // Exception type
    input.push_str(exception_type.unwrap_or("Unknown"));
    input.push('\n');

    // Extract in-app frames
    let mut found_frames = false;
    if let Some(stack) = stack_trace {
        for line in stack.lines() {
            if let Some((method, file)) = extract_frame_parts(line) {
                if is_in_app_frame(&file, &method) {
                    input.push_str(&file);
                    input.push(':');
                    input.push_str(&method);
                    input.push('\n');
                    found_frames = true;
                }
            }
        }
    }

    // Fallback to normalized message if no frames found
    if !found_frames {
        if let Some(msg) = message {
            input.push_str(&normalize_message(msg));
        }
    }

    let hash = Sha256::digest(input.as_bytes());
    let hex = hex::encode(hash);
    format!("v1:{}", &hex[..32])
}

/// Compute a human-readable title for a crash group.
///
/// # Parameters
/// - `exception_type`: Exception class name. Defaults to `"Unknown"` when `None`.
/// - `stack_trace`: Stack trace string. The first in-app frame determines the title.
/// - `message`: Error message fallback. First line is used, truncated to 80 chars.
///
/// # Returns
/// A title string in one of these formats:
/// - `"StateError in build (profile_screen.dart)"` — when in-app frames exist
/// - `"Exception: connection refused"` — when only a message is available
/// - `"Unknown"` — when neither stack nor message is provided
pub fn compute_group_title(
    exception_type: Option<&str>,
    stack_trace: Option<&str>,
    message: Option<&str>,
) -> String {
    let exc = exception_type.unwrap_or("Unknown");

    // Try to find the first in-app frame
    if let Some(stack) = stack_trace {
        for line in stack.lines() {
            if let Some((method, file)) = extract_frame_parts(line) {
                if is_in_app_frame(&file, &method) {
                    // Shorten method: take last segment if dotted
                    let short_method = method.rsplit('.').next().unwrap_or(&method);
                    return format!("{} in {} ({})", exc, short_method, file);
                }
            }
        }
    }

    // Fall back to message
    if let Some(msg) = message {
        let first_line = msg.lines().next().unwrap_or(msg);
        let truncated: String = first_line.chars().take(80).collect();
        if truncated.len() < first_line.len() {
            return format!("{}: {}...", exc, truncated);
        }
        return format!("{}: {}", exc, truncated);
    }

    exc.to_string()
}

// Compiled regex patterns (OnceLock = compile once)

fn dart_frame_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // #0      ClassName.method (package:app/path/file.dart:123:45)
        // #0      ClassName.method (package:app/path/file.dart)
        Regex::new(r"#\d+\s+(\S+)\s+\(package:[\w.]+/(.+?)(?::\d+(?::\d+)?)?\)").unwrap()
    })
}

fn dart_frame_alt_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // #0      ClassName.method (dart:async/zone.dart:123:45)
        Regex::new(r"#\d+\s+(\S+)\s+\((dart:\S+?)(?::\d+(?::\d+)?)?\)").unwrap()
    })
}

fn java_frame_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // at com.example.Class.method(File.java:123)
        Regex::new(r"^\s*at\s+([\w.$]+)\(([^:)]+?)(?::\d+)?\)").unwrap()
    })
}

fn js_frame_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // at functionName (file.js:10:20)
        // at functionName (node:internal/process/task_queues:95:5)
        // at file.js:10:20
        Regex::new(r"^\s*at\s+(?:(\S+)\s+\()(.+?)(?::\d+(?::\d+)?)?\)?$").unwrap()
    })
}

fn js_frame_bare_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // at file.js:10:20  (no function name, no parens)
        Regex::new(r"^\s*at\s+([^(]\S+?)(?::\d+(?::\d+)?)?$").unwrap()
    })
}

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"0x[0-9a-fA-F]+").unwrap())
}

fn large_number_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{5,}\b").unwrap())
}

fn ip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap())
}

fn timestamp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap()
    })
}

/// Parse a single stack frame line into `(method_name, filename)`.
///
/// Supports three frame formats:
/// - **Dart**: `#0 ClassName.method (package:app/path/file.dart:123:45)` → `("ClassName.method", "path/file.dart")`
/// - **Java**: `at com.example.Class.method(File.java:123)` → `("com.example.Class.method", "File.java")`
/// - **JS**: `at functionName (file.js:10:20)` → `("functionName", "file.js")`
///
/// Line numbers and column numbers are always stripped from the filename.
///
/// # Returns
/// `Some((method, file))` if the line matches a known frame format, `None` otherwise.
pub fn extract_frame_parts(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Dart package frames: #0 ClassName.method (package:app/path/file.dart:123:45)
    if let Some(caps) = dart_frame_re().captures(line) {
        let method = caps.get(1)?.as_str().to_string();
        let file = caps.get(2)?.as_str().to_string();
        return Some((method, file));
    }

    // Dart runtime frames: #0 ClassName.method (dart:async/zone.dart:123)
    if let Some(caps) = dart_frame_alt_re().captures(line) {
        let method = caps.get(1)?.as_str().to_string();
        let file = caps.get(2)?.as_str().to_string();
        return Some((method, file));
    }

    // Java frames: at com.example.Class.method(File.java:123)
    if let Some(caps) = java_frame_re().captures(line) {
        let method = caps.get(1)?.as_str().to_string();
        let file = caps.get(2)?.as_str().to_string();
        return Some((method, file));
    }

    // JS frames with function name: at functionName (file.js:10:20)
    if let Some(caps) = js_frame_re().captures(line) {
        let method = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let file = caps.get(2)?.as_str().to_string();
        if !file.is_empty() {
            return Some((method, file));
        }
    }

    // JS frames without function name: at file.js:10:20
    if let Some(caps) = js_frame_bare_re().captures(line) {
        let file = caps.get(1)?.as_str().to_string();
        if !file.is_empty() {
            return Some((String::new(), file));
        }
    }

    None
}

/// Returns `true` if a stack frame is "in-app" (not framework/runtime).
///
/// Excluded prefixes:
/// - Dart runtime (`dart:*`), Flutter framework (`flutter/`, `packages/flutter/`)
/// - Java/Android (`java.lang.*`, `android.*`, `androidx.*`, `dalvik.*`, etc.)
/// - Node internals (`node:*`, `internal/*`)
/// - Generic placeholders (`<anonymous>`, `native`, `Unknown Source`)
///
/// # Parameters
/// - `file`: Filename portion from [`extract_frame_parts`].
/// - `method`: Method/function name from [`extract_frame_parts`].
///
/// # INVARIANT
/// Adding new exclusions changes fingerprints for affected crashes.
/// Verify against fingerprint-vectors.json after modifying.
pub fn is_in_app_frame(file: &str, method: &str) -> bool {
    // Dart runtime
    if file.starts_with("dart:") {
        return false;
    }
    // Flutter framework
    if file.starts_with("flutter/") || file.starts_with("packages/flutter/") {
        return false;
    }
    // Java/Android framework
    let framework_prefixes = [
        "java.lang.", "java.util.", "java.io.",
        "android.", "androidx.", "dalvik.", "com.android.",
        "sun.", "kotlin.", "kotlinx.",
    ];
    for prefix in &framework_prefixes {
        if method.starts_with(prefix) {
            return false;
        }
    }
    // Node internals
    if file.starts_with("node:") || file.starts_with("internal/") {
        return false;
    }
    // Generic <anonymous> or native
    if file == "<anonymous>" || file == "native" || file == "Unknown Source" {
        return false;
    }

    true
}

/// Normalize an error message by stripping variable data for stable hashing.
///
/// Replaces hex addresses (`0x...`), IP addresses, ISO timestamps, and
/// large numbers (5+ digits) with fixed placeholders. This ensures messages
/// like `"Connection to 192.168.1.1 failed at 2024-01-01T00:00:00"` produce
/// the same fingerprint regardless of the specific IP or timestamp.
///
/// Used as a fallback in [`compute_fingerprint`] when no in-app stack frames exist.
pub fn normalize_message(msg: &str) -> String {
    let s = hex_re().replace_all(msg, "<hex>");
    let s = ip_re().replace_all(&s, "<ip>");
    let s = timestamp_re().replace_all(&s, "<timestamp>");
    let s = large_number_re().replace_all(&s, "<N>");
    s.to_string()
}

// ============================================================================
// Parsing
// ============================================================================

/// Parses crash content to extract structured fields.
/// Handles both JSON payloads (TypeScript SDK) and markdown (Android SDK).
pub fn parse_crash_content(content: &str) -> ParsedCrash {
    // Check for URL-only content first
    if is_url_only(content) {
        return ParsedCrash {
            is_crash: false,
            ..Default::default()
        };
    }

    // Try JSON first
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        return ParsedCrash {
            message: json.get("message").and_then(|v| v.as_str()).map(String::from),
            stack_trace: json.get("stack").and_then(|v| v.as_str()).map(String::from),
            exception_type: extract_exception_type(
                json.get("message").and_then(|v| v.as_str()),
                json.get("stack").and_then(|v| v.as_str()),
            ),
            environment: json.get("environment").and_then(|v| v.as_str()).map(String::from),
            release: json.get("release").and_then(|v| v.as_str()).map(String::from),
            app_name: None,
            app_version: None,
            is_crash: true,
        };
    }

    // Try markdown (Android format)
    let lines: Vec<&str> = content.lines().collect();
    let mut exception_type = None;
    let mut message = None;
    let mut app_version = None;

    for line in &lines {
        // Look for exception type in stack trace
        if line.contains("Exception") || line.contains("Error") {
            if exception_type.is_none() {
                exception_type = extract_exception_name(line);
                message = Some(line.to_string());
            }
        }
        // Look for version in header
        if line.contains('-') && (line.contains("RELEASE") || line.contains("DEBUG")) {
            if let Some(version) = line.split('-').next() {
                app_version = Some(version.trim().to_string());
            }
        }
    }

    ParsedCrash {
        message,
        stack_trace: Some(content.to_string()),
        exception_type,
        environment: None,
        release: None,
        app_name: lines.first().map(|s| s.to_string()),
        app_version,
        is_crash: true,
    }
}

/// Parsed crash report fields.
#[derive(Debug, Default)]
pub struct ParsedCrash {
    pub message: Option<String>,
    pub stack_trace: Option<String>,
    pub exception_type: Option<String>,
    pub environment: Option<String>,
    pub release: Option<String>,
    pub app_name: Option<String>,
    pub app_version: Option<String>,
    pub is_crash: bool,
}

fn extract_exception_type(message: Option<&str>, stack: Option<&str>) -> Option<String> {
    // Try to extract from stack trace first
    if let Some(stack) = stack {
        if let Some(exc) = extract_exception_name(stack.lines().next().unwrap_or("")) {
            return Some(exc);
        }
    }
    // Try message
    if let Some(msg) = message {
        return extract_exception_name(msg).map(String::from);
    }
    None
}

fn extract_exception_name(line: &str) -> Option<String> {
    // Common patterns: "java.lang.NullPointerException: message"
    // or "Error: message" or "TypeError: message"
    let line = line.trim();

    // Java-style: com.example.MyException: message
    if let Some(colon_pos) = line.find(':') {
        let prefix = &line[..colon_pos];
        if prefix.contains('.') || prefix.ends_with("Exception") || prefix.ends_with("Error") {
            // Get just the class name
            return Some(prefix.split('.').last().unwrap_or(prefix).to_string());
        }
    }

    // JS-style: Error or TypeError at beginning
    if line.starts_with("Error") || line.contains("Error:") {
        return Some("Error".to_string());
    }
    if let Some(pos) = line.find("Exception") {
        let start = line[..pos].rfind(|c: char| !c.is_alphanumeric()).map(|i| i + 1).unwrap_or(0);
        return Some(line[start..pos + 9].to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report(event_id: &str, exc: Option<&str>, msg: Option<&str>, stack: Option<&str>) -> CrashReport {
        let fingerprint = compute_fingerprint(exc, msg, stack);
        let group_title = compute_group_title(exc, stack, msg);
        CrashReport {
            id: 0,
            event_id: event_id.to_string(),
            sender_pubkey: "pubkey".to_string(),
            received_at: 1000,
            created_at: 999,
            app_name: None,
            app_version: Some("1.0.0".to_string()),
            exception_type: exc.map(String::from),
            message: msg.map(String::from),
            stack_trace: stack.map(String::from),
            raw_content: "raw".to_string(),
            environment: None,
            release: None,
            fingerprint: Some(fingerprint),
            group_title: Some(group_title),
            is_crash: true,
        }
    }

    #[test]
    fn test_insert_and_query() {
        let storage = CrashStorage::open_in_memory().unwrap();

        let report = make_report("abc123", Some("NullPointerException"), Some("Something went wrong"), Some("at com.example.Test(Test.java:42)"));

        let id = storage.insert(&report).unwrap();
        assert!(id.is_some());

        let recent = storage.get_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event_id, "abc123");
        assert!(recent[0].fingerprint.is_some());
    }

    #[test]
    fn test_duplicate_prevention() {
        let storage = CrashStorage::open_in_memory().unwrap();

        let report = CrashReport {
            id: 0,
            event_id: "same_id".to_string(),
            sender_pubkey: "pubkey".to_string(),
            received_at: 1000,
            created_at: 999,
            app_name: None,
            app_version: None,
            exception_type: None,
            message: None,
            stack_trace: None,
            raw_content: "raw".to_string(),
            environment: None,
            release: None,
            fingerprint: None,
            group_title: None,
            is_crash: true,
        };

        let id1 = storage.insert(&report).unwrap();
        let id2 = storage.insert(&report).unwrap();

        assert!(id1.is_some());
        assert!(id2.is_none()); // Duplicate
        assert_eq!(storage.count().unwrap(), 1);
    }

    #[test]
    fn test_grouping_by_fingerprint() {
        let storage = CrashStorage::open_in_memory().unwrap();

        // Insert multiple crashes with same fingerprint (same stack)
        for i in 0..5 {
            let mut report = make_report(
                &format!("event_{}", i),
                Some("NullPointerException"),
                Some("null ref"),
                Some("at com.example.MyApp.run(MyApp.java:42)"),
            );
            report.received_at = 1000 + i;
            storage.insert(&report).unwrap();
        }

        let groups = storage.get_groups(10).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 5);
        assert!(groups[0].fingerprint.starts_with("v1:"));
        assert!(groups[0].title.contains("NullPointerException"));
    }

    #[test]
    fn test_same_exception_different_stack_different_fingerprints() {
        let fp1 = compute_fingerprint(
            Some("Exception"),
            None,
            Some("#0      _HomeState.build (package:app/screens/home.dart:42:5)"),
        );
        let fp2 = compute_fingerprint(
            Some("Exception"),
            None,
            Some("#0      _ProfileState.build (package:app/screens/profile.dart:18:3)"),
        );
        assert_ne!(fp1, fp2, "Different stacks must produce different fingerprints");
    }

    #[test]
    fn test_same_stack_different_line_numbers_same_fingerprint() {
        let fp1 = compute_fingerprint(
            Some("Exception"),
            None,
            Some("#0      _HomeState.build (package:app/screens/home.dart:42:5)"),
        );
        let fp2 = compute_fingerprint(
            Some("Exception"),
            None,
            Some("#0      _HomeState.build (package:app/screens/home.dart:99:10)"),
        );
        assert_eq!(fp1, fp2, "Same stack with different line numbers must produce same fingerprint");
    }

    #[test]
    fn test_url_only_not_crash() {
        assert!(is_url_only("https://example.com/blossom/abc123"));
        assert!(is_url_only("  https://example.com/test  "));
        assert!(!is_url_only("Error: something broke\nat foo.js:10"));
        assert!(!is_url_only("https://example.com\nsecond line"));
    }

    #[test]
    fn test_parse_url_only_content() {
        let parsed = parse_crash_content("https://cdn.example.com/blossom/abc123");
        assert!(!parsed.is_crash);
    }

    #[test]
    fn test_extract_dart_frame() {
        let line = "#0      _AboutSection.build (package:zapstore/screens/profile_screen.dart:123:45)";
        let (method, file) = extract_frame_parts(line).unwrap();
        assert_eq!(method, "_AboutSection.build");
        assert_eq!(file, "screens/profile_screen.dart");
    }

    #[test]
    fn test_extract_dart_runtime_frame() {
        let line = "#5      _rootRun (dart:async/zone.dart:1399:13)";
        let (method, file) = extract_frame_parts(line).unwrap();
        assert_eq!(method, "_rootRun");
        assert_eq!(file, "dart:async/zone.dart");
        assert!(!is_in_app_frame(&file, &method));
    }

    #[test]
    fn test_extract_java_frame() {
        let line = "    at com.example.MyApp.onCreate(MyApp.java:42)";
        let (method, file) = extract_frame_parts(line).unwrap();
        assert_eq!(method, "com.example.MyApp.onCreate");
        assert_eq!(file, "MyApp.java");
        assert!(is_in_app_frame(&file, &method));
    }

    #[test]
    fn test_java_framework_frame_excluded() {
        let line = "    at java.lang.Thread.run(Thread.java:929)";
        let (method, file) = extract_frame_parts(line).unwrap();
        assert!(!is_in_app_frame(&file, &method));
    }

    #[test]
    fn test_extract_js_frame() {
        let line = "    at processTicksAndRejections (node:internal/process/task_queues:95:5)";
        let (method, file) = extract_frame_parts(line).unwrap();
        assert_eq!(method, "processTicksAndRejections");
        assert!(!is_in_app_frame(&file, &method));

        let line2 = "    at handleError (app/utils/error-handler.js:10:5)";
        let (method2, file2) = extract_frame_parts(line2).unwrap();
        assert_eq!(method2, "handleError");
        assert!(is_in_app_frame(&file2, &method2));
    }

    #[test]
    fn test_normalize_message() {
        let msg = "Connection to 192.168.1.1 failed at 2024-01-15T10:30:00 with code 0xDEAD after 100000 retries";
        let normalized = normalize_message(msg);
        assert!(normalized.contains("<ip>"));
        assert!(normalized.contains("<timestamp>"));
        assert!(normalized.contains("<hex>"));
        assert!(normalized.contains("<N>"));
    }

    #[test]
    fn test_group_title_with_stack() {
        let title = compute_group_title(
            Some("StateError"),
            Some("#0      _AboutSection.build (package:zapstore/screens/profile_screen.dart:42:5)"),
            Some("Bad state: no element"),
        );
        assert_eq!(title, "StateError in build (screens/profile_screen.dart)");
    }

    #[test]
    fn test_group_title_no_stack() {
        let title = compute_group_title(
            Some("Error"),
            None,
            Some("Something went wrong"),
        );
        assert_eq!(title, "Error: Something went wrong");
    }

    #[test]
    fn test_parse_json_crash() {
        let content = r#"{"message":"Something failed","stack":"Error: Something failed\n    at foo.js:10","environment":"production"}"#;
        let parsed = parse_crash_content(content);

        assert_eq!(parsed.message, Some("Something failed".to_string()));
        assert!(parsed.stack_trace.is_some());
        assert_eq!(parsed.environment, Some("production".to_string()));
        assert!(parsed.is_crash);
    }

    #[test]
    fn test_extract_exception_name() {
        assert_eq!(
            extract_exception_name("java.lang.NullPointerException: message"),
            Some("NullPointerException".to_string())
        );
        assert_eq!(
            extract_exception_name("Error: something went wrong"),
            Some("Error".to_string())
        );
    }

    #[test]
    fn test_get_by_fingerprint() {
        let storage = CrashStorage::open_in_memory().unwrap();

        let report1 = make_report(
            "event_1",
            Some("Exception"),
            None,
            Some("#0      _HomeState.build (package:app/screens/home.dart:42:5)"),
        );
        let fp = report1.fingerprint.clone().unwrap();
        storage.insert(&report1).unwrap();

        // Different stack = different fingerprint
        let report2 = make_report(
            "event_2",
            Some("Exception"),
            None,
            Some("#0      _ProfileState.build (package:app/screens/profile.dart:18:3)"),
        );
        storage.insert(&report2).unwrap();

        let results = storage.get_by_fingerprint(&fp, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, "event_1");
    }

    #[test]
    fn test_non_crash_excluded_from_groups() {
        let storage = CrashStorage::open_in_memory().unwrap();

        // Insert a real crash
        let crash = make_report("event_1", Some("Error"), Some("real crash"), None);
        storage.insert(&crash).unwrap();

        // Insert a non-crash (URL)
        let url_report = CrashReport {
            id: 0,
            event_id: "event_url".to_string(),
            sender_pubkey: "pubkey".to_string(),
            received_at: 1000,
            created_at: 999,
            app_name: None,
            app_version: None,
            exception_type: None,
            message: None,
            stack_trace: None,
            raw_content: "https://cdn.example.com/blossom/abc".to_string(),
            environment: None,
            release: None,
            fingerprint: Some("v1:url".to_string()),
            group_title: None,
            is_crash: false,
        };
        storage.insert(&url_report).unwrap();

        let groups = storage.get_groups(10).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 1);

        // count() should only count crashes
        assert_eq!(storage.count().unwrap(), 1);
    }

    #[test]
    fn test_backfill_fingerprints() {
        let storage = CrashStorage::open_in_memory().unwrap();

        // Insert without fingerprint (simulating old data)
        storage.conn.execute(
            "INSERT INTO crashes (event_id, sender_pubkey, received_at, created_at, raw_content, exception_type, message, stack_trace)
             VALUES ('old_event', 'pk', 1000, 999, 'raw', 'Error', 'old msg', 'at com.example.Test(Test.java:10)')",
            [],
        ).unwrap();

        // Insert a URL row without fingerprint
        storage.conn.execute(
            "INSERT INTO crashes (event_id, sender_pubkey, received_at, created_at, raw_content)
             VALUES ('url_event', 'pk', 1000, 999, 'https://example.com/blossom/test')",
            [],
        ).unwrap();

        let count = storage.backfill_fingerprints().unwrap();
        assert_eq!(count, 2);

        // Verify fingerprint was set
        let crash = storage.get_by_id(1).unwrap().unwrap();
        assert!(crash.fingerprint.is_some());
        assert!(crash.fingerprint.unwrap().starts_with("v1:"));
        assert!(crash.is_crash);

        // Verify URL row marked as not a crash
        let url_row = storage.get_by_id(2).unwrap().unwrap();
        assert!(!url_row.is_crash);
    }

    /// Validate fingerprint computation against the shared test vectors.
    /// If this test fails, either the algorithm changed (bump version prefix)
    /// or the vectors need regenerating.
    #[test]
    fn test_conformance_fingerprint_vectors() {
        let vectors_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/sdk-conformance/fingerprint-vectors.json"
        );
        let content = std::fs::read_to_string(vectors_path)
            .expect("fingerprint-vectors.json must exist at test-vectors/sdk-conformance/");
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let vectors = json["vectors"].as_array().expect("vectors must be an array");
        for vector in vectors {
            let desc = vector["description"].as_str().unwrap();
            let input = &vector["input"];

            let exc = input["exception_type"].as_str();
            let msg = input["message"].as_str();
            let stack = input["stack_trace"].as_str();

            let expected_fp = vector["expected_fingerprint"].as_str().unwrap();
            let actual_fp = compute_fingerprint(exc, msg, stack);

            assert_eq!(
                actual_fp, expected_fp,
                "Fingerprint mismatch for vector '{}': expected {}, got {}",
                desc, expected_fp, actual_fp
            );
        }

        // Also validate the assertions section
        let assertions = json["assertions"].as_array().expect("assertions must be an array");
        let vector_map: std::collections::HashMap<&str, &str> = vectors.iter().map(|v| {
            (v["description"].as_str().unwrap(), v["expected_fingerprint"].as_str().unwrap())
        }).collect();

        for assertion in assertions {
            let rule = assertion["rule"].as_str().unwrap();
            let relation = assertion["relation"].as_str().unwrap();
            let vector_names: Vec<&str> = assertion["vectors"].as_array().unwrap()
                .iter().map(|v| v.as_str().unwrap()).collect();

            let fp0 = vector_map[vector_names[0]];
            let fp1 = vector_map[vector_names[1]];

            match relation {
                "equal" => assert_eq!(fp0, fp1, "Assertion '{}' failed: {} and {} should be equal", rule, vector_names[0], vector_names[1]),
                "not_equal" => assert_ne!(fp0, fp1, "Assertion '{}' failed: {} and {} should differ", rule, vector_names[0], vector_names[1]),
                _ => panic!("Unknown relation: {}", relation),
            }
        }
    }

    /// Hardcoded fingerprint stability test — these values must never change.
    /// If this test fails, the fingerprint algorithm was accidentally modified.
    /// Bump the version prefix (v1 → v2) and add migration logic.
    #[test]
    fn test_fingerprint_stability_golden_values() {
        // Case 1: Exception + Dart in-app frame
        let fp1 = compute_fingerprint(
            Some("StateError"),
            Some("Bad state"),
            Some("#0      _ProfileState.build (package:app/screens/profile.dart:42:5)"),
        );
        assert_eq!(fp1, "v1:81b4ba2e6b8d682a9150203b134a7e69",
            "Fingerprint for StateError+Dart frame changed — algorithm broken");

        // Case 2: Same exception + same method/file, different line number = SAME fingerprint
        let fp2 = compute_fingerprint(
            Some("StateError"),
            Some("Different message"),
            Some("#0      _ProfileState.build (package:app/screens/profile.dart:99:1)"),
        );
        assert_eq!(fp1, fp2, "Line number stripping broken — same frame should produce same fingerprint");

        // Case 3: No stack trace — falls back to normalized message
        let fp3 = compute_fingerprint(
            Some("HttpException"),
            Some("Connection to 192.168.1.1 failed at 2024-01-01T00:00:00"),
            None,
        );
        assert_eq!(fp3, "v1:37c7e320a9456c02e37ddb7ed6e06a0b",
            "Fingerprint for message-only HttpException changed — algorithm broken");

        // Case 4: Same exception + same normalized message with different IPs = SAME
        let fp4 = compute_fingerprint(
            Some("HttpException"),
            Some("Connection to 10.0.0.1 failed at 2025-06-15T12:00:00"),
            None,
        );
        assert_eq!(fp3, fp4, "Message normalization broken — variable data should be stripped");

        // Case 5: Java frame
        let fp5 = compute_fingerprint(
            Some("NullPointerException"),
            None,
            Some("at com.myapp.UserService.getUser(UserService.java:55)"),
        );
        assert_eq!(fp5, "v1:81808db226349a185027b48510102dd0",
            "Fingerprint for Java frame changed — algorithm broken");

        // Case 6: No exception, no stack, no message
        let fp6 = compute_fingerprint(None, None, None);
        assert_eq!(fp6, "v1:c80c3db2b2cb606bacf75bac6c2e4b92",
            "Fingerprint for empty input changed — algorithm broken");
    }

    #[test]
    fn test_insert_and_count_failed_events() {
        let storage = CrashStorage::open_in_memory().unwrap();

        assert_eq!(storage.failed_event_count().unwrap(), 0);

        storage
            .insert_failed_event("event_1", Some("wss://relay.example.com"), "decrypt failed", 1000)
            .unwrap();
        storage
            .insert_failed_event("event_2", None, "invalid seal kind", 1001)
            .unwrap();

        assert_eq!(storage.failed_event_count().unwrap(), 2);
    }

    /// Validate that all payloads in payload-valid.json parse without error.
    #[test]
    fn test_conformance_valid_payloads() {
        let payloads_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/sdk-conformance/payload-valid.json"
        );
        let content = std::fs::read_to_string(payloads_path)
            .expect("payload-valid.json must exist at test-vectors/sdk-conformance/");
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();

        let payloads = json["payloads"].as_array().expect("payloads must be an array");
        for entry in payloads {
            let desc = entry["description"].as_str().unwrap();
            let payload = &entry["payload"];

            // Verify the payload can be serialized and parsed as crash content
            let payload_str = serde_json::to_string(payload).unwrap();
            let parsed = parse_crash_content(&payload_str);

            // Valid payloads must either be a crash or have a non-empty message
            assert!(
                parsed.is_crash || parsed.message.as_ref().map_or(false, |m| !m.is_empty()),
                "Valid payload '{}' must be a crash or have a non-empty message",
                desc
            );
        }
    }
}
