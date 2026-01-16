//! SQLite storage for crash reports.
//!
//! Stores decrypted crash reports with indexing for efficient querying
//! and grouping by exception type, app version, etc.

use rusqlite::{params, Connection, Result};
use std::path::Path;

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
}

/// A group of crashes by exception type.
#[derive(Debug, Clone)]
pub struct CrashGroup {
    pub exception_type: String,
    pub count: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub app_versions: Vec<String>,
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
                release TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_crashes_received_at ON crashes(received_at DESC);
            CREATE INDEX IF NOT EXISTS idx_crashes_exception_type ON crashes(exception_type);
            CREATE INDEX IF NOT EXISTS idx_crashes_app_version ON crashes(app_version);
            CREATE INDEX IF NOT EXISTS idx_crashes_sender ON crashes(sender_pubkey);
            ",
        )
    }

    /// Inserts a new crash report. Returns the inserted row ID.
    /// If the event_id already exists, returns None (duplicate).
    pub fn insert(&self, report: &CrashReport) -> Result<Option<i64>> {
        let result = self.conn.execute(
            "INSERT OR IGNORE INTO crashes (
                event_id, sender_pubkey, received_at, created_at,
                app_name, app_version, exception_type, message,
                stack_trace, raw_content, environment, release
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
                    stack_trace, raw_content, environment, release
             FROM crashes
             ORDER BY received_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
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
            })
        })?;

        rows.collect()
    }

    /// Gets crash groups aggregated by exception type.
    pub fn get_groups(&self, limit: usize) -> Result<Vec<CrashGroup>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                COALESCE(exception_type, 'Unknown') as exc_type,
                COUNT(*) as count,
                MIN(received_at) as first_seen,
                MAX(received_at) as last_seen,
                GROUP_CONCAT(DISTINCT app_version) as versions
             FROM crashes
             GROUP BY exc_type
             ORDER BY count DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            let versions_str: Option<String> = row.get(4)?;
            let app_versions = versions_str
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_default();

            Ok(CrashGroup {
                exception_type: row.get(0)?,
                count: row.get(1)?,
                first_seen: row.get(2)?,
                last_seen: row.get(3)?,
                app_versions,
            })
        })?;

        rows.collect()
    }

    /// Gets total crash count.
    pub fn count(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM crashes", [], |row| row.get(0))
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
                    stack_trace, raw_content, environment, release
             FROM crashes
             WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map([id], |row| {
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
            })
        })?;

        rows.next().transpose()
    }
}

/// Parses crash content to extract structured fields.
/// Handles both JSON payloads (TypeScript SDK) and markdown (Android SDK).
pub fn parse_crash_content(content: &str) -> ParsedCrash {
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

    #[test]
    fn test_insert_and_query() {
        let storage = CrashStorage::open_in_memory().unwrap();

        let report = CrashReport {
            id: 0,
            event_id: "abc123".to_string(),
            sender_pubkey: "pubkey123".to_string(),
            received_at: 1000,
            created_at: 999,
            app_name: Some("TestApp".to_string()),
            app_version: Some("1.0.0".to_string()),
            exception_type: Some("NullPointerException".to_string()),
            message: Some("Something went wrong".to_string()),
            stack_trace: Some("at com.example.Test".to_string()),
            raw_content: "raw".to_string(),
            environment: None,
            release: None,
        };

        let id = storage.insert(&report).unwrap();
        assert!(id.is_some());

        let recent = storage.get_recent(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event_id, "abc123");
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
        };

        let id1 = storage.insert(&report).unwrap();
        let id2 = storage.insert(&report).unwrap();

        assert!(id1.is_some());
        assert!(id2.is_none()); // Duplicate
        assert_eq!(storage.count().unwrap(), 1);
    }

    #[test]
    fn test_grouping() {
        let storage = CrashStorage::open_in_memory().unwrap();

        // Insert multiple crashes with same exception type
        for i in 0..5 {
            let report = CrashReport {
                id: 0,
                event_id: format!("event_{}", i),
                sender_pubkey: "pubkey".to_string(),
                received_at: 1000 + i,
                created_at: 999,
                app_name: None,
                app_version: Some("1.0.0".to_string()),
                exception_type: Some("NullPointerException".to_string()),
                message: None,
                stack_trace: None,
                raw_content: "raw".to_string(),
                environment: None,
                release: None,
            };
            storage.insert(&report).unwrap();
        }

        let groups = storage.get_groups(10).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].exception_type, "NullPointerException");
        assert_eq!(groups[0].count, 5);
    }

    #[test]
    fn test_parse_json_crash() {
        let content = r#"{"message":"Something failed","stack":"Error: Something failed\n    at foo.js:10","environment":"production"}"#;
        let parsed = parse_crash_content(content);

        assert_eq!(parsed.message, Some("Something failed".to_string()));
        assert!(parsed.stack_trace.is_some());
        assert_eq!(parsed.environment, Some("production".to_string()));
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
}
