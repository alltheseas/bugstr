//! Bugstr - Privacy-focused crash reporting for Rust applications
//!
//! Delivers crash reports via NIP-17 gift-wrapped encrypted DMs
//! with user consent and auto-expiration.
//!
//! # Features
//!
//! - Panic hook for capturing crashes
//! - Local file-based caching
//! - Gzip compression for large payloads
//! - NIP-17/44/59 gift wrap building
//!
//! # Example
//!
//! ```rust,no_run
//! use bugstr::{install_panic_hook, CrashReportCache};
//!
//! fn main() {
//!     let cache = CrashReportCache::new("/tmp/crashes").unwrap();
//!     install_panic_hook(cache);
//!
//!     // Your application code...
//! }
//! ```

pub mod compression;
pub mod event;
pub mod storage;
pub mod web;

pub use compression::{compress_payload, decompress_payload, maybe_compress_payload, DEFAULT_THRESHOLD};
pub use event::UnsignedNostrEvent;
pub use storage::{CrashReport, CrashGroup, CrashStorage, parse_crash_content};
pub use web::{create_router, AppState};

/// Configuration for the crash report handler.
#[derive(Debug, Clone)]
pub struct BugstrConfig {
    /// Recipient's public key (hex, 64 chars)
    pub recipient_pubkey: String,
    /// Relay URLs to publish to
    pub relays: Vec<String>,
    /// Application name
    pub app_name: String,
    /// Application version
    pub app_version: String,
    /// Maximum stack trace characters
    pub max_stack_chars: usize,
}

impl Default for BugstrConfig {
    fn default() -> Self {
        Self {
            recipient_pubkey: String::new(),
            relays: vec![
                "wss://relay.damus.io".into(),
                "wss://nos.lol".into(),
            ],
            app_name: "Unknown".into(),
            app_version: "0.0.0".into(),
            max_stack_chars: 200_000,
        }
    }
}

/// Installs a panic hook that caches crash reports.
///
/// When a panic occurs, the stack trace is captured and saved
/// to the provided cache for later user-consented transmission.
pub fn install_panic_hook(_cache: CrashReportCache) {
    // TODO: Implement panic hook
    // std::panic::set_hook(Box::new(move |info| { ... }));
    unimplemented!("Panic hook not yet implemented")
}

/// Local file-based crash report cache.
#[derive(Debug)]
pub struct CrashReportCache {
    path: std::path::PathBuf,
}

impl CrashReportCache {
    /// Creates a new cache at the specified directory.
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Returns the cache directory path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}
