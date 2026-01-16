//! Symbolication support for crash reports.
//!
//! This module provides functionality to symbolicate stack traces from various platforms
//! using their respective mapping files (ProGuard, source maps, DWARF, etc.).
//!
//! # Supported Platforms
//!
//! - **Android**: ProGuard/R8 mapping.txt files
//! - **JavaScript/Electron**: Source map (.map) files
//! - **Flutter/Dart**: Flutter symbol files or external `flutter symbolize`
//! - **Rust**: DWARF debug info via addr2line
//! - **Go**: Go symbol tables (usually embedded)
//! - **Python**: Source file mapping for bundled apps
//! - **React Native**: Hermes bytecode maps + JS source maps
//!
//! # Example
//!
//! ```rust,ignore
//! use bugstr::symbolication::{Symbolicator, MappingStore, Platform, SymbolicationContext};
//!
//! let store = MappingStore::new("/path/to/mappings");
//! let symbolicator = Symbolicator::new(store);
//!
//! let context = SymbolicationContext {
//!     platform: Platform::Android,
//!     app_id: Some("com.myapp".to_string()),
//!     version: Some("1.0.0".to_string()),
//!     build_id: None,
//! };
//!
//! let stack_trace = "...";
//! let result = symbolicator.symbolicate(stack_trace, &context);
//! ```

mod android;
mod javascript;
mod flutter;
mod rust_sym;
mod go;
mod python;
mod react_native;
mod store;

pub use android::AndroidSymbolicator;
pub use javascript::JavaScriptSymbolicator;
pub use flutter::FlutterSymbolicator;
pub use rust_sym::RustSymbolicator;
pub use go::GoSymbolicator;
pub use python::PythonSymbolicator;
pub use react_native::ReactNativeSymbolicator;
pub use store::MappingStore;

use thiserror::Error;

/// Errors that can occur during symbolication.
#[derive(Error, Debug)]
pub enum SymbolicationError {
    #[error("No mapping file found for {platform} {app_id} {version}")]
    MappingNotFound {
        platform: String,
        app_id: String,
        version: String,
    },

    #[error("Failed to parse mapping file: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("External tool error: {0}")]
    ToolError(String),
}

/// Platform identifier for crash reports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Platform {
    Android,
    Electron,
    Flutter,
    Rust,
    Go,
    Python,
    ReactNative,
    Unknown(String),
}

impl Platform {
    /// Parse platform from string.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "android" => Platform::Android,
            "electron" | "javascript" | "js" => Platform::Electron,
            "flutter" | "dart" => Platform::Flutter,
            "rust" => Platform::Rust,
            "go" | "golang" => Platform::Go,
            "python" => Platform::Python,
            "react-native" | "reactnative" | "rn" => Platform::ReactNative,
            other => Platform::Unknown(other.to_string()),
        }
    }

    /// Get platform name as string.
    pub fn as_str(&self) -> &str {
        match self {
            Platform::Android => "android",
            Platform::Electron => "electron",
            Platform::Flutter => "flutter",
            Platform::Rust => "rust",
            Platform::Go => "go",
            Platform::Python => "python",
            Platform::ReactNative => "react-native",
            Platform::Unknown(s) => s,
        }
    }
}

/// Information needed to symbolicate a stack trace.
#[derive(Debug, Clone)]
pub struct SymbolicationContext {
    /// Platform the crash came from
    pub platform: Platform,
    /// Application identifier (package name, bundle id, etc.)
    pub app_id: Option<String>,
    /// Application version
    pub version: Option<String>,
    /// Build ID or commit hash
    pub build_id: Option<String>,
}

/// A symbolicated stack frame.
#[derive(Debug, Clone)]
pub struct SymbolicatedFrame {
    /// Original raw frame text
    pub raw: String,
    /// Symbolicated function/method name
    pub function: Option<String>,
    /// Source file path
    pub file: Option<String>,
    /// Line number
    pub line: Option<u32>,
    /// Column number
    pub column: Option<u32>,
    /// Whether this frame was successfully symbolicated
    pub symbolicated: bool,
}

impl SymbolicatedFrame {
    /// Create a new frame that wasn't symbolicated.
    pub fn raw(text: String) -> Self {
        Self {
            raw: text,
            function: None,
            file: None,
            line: None,
            column: None,
            symbolicated: false,
        }
    }

    /// Create a symbolicated frame.
    pub fn symbolicated(
        raw: String,
        function: String,
        file: Option<String>,
        line: Option<u32>,
        column: Option<u32>,
    ) -> Self {
        Self {
            raw,
            function: Some(function),
            file,
            line,
            column,
            symbolicated: true,
        }
    }

    /// Format the frame for display.
    pub fn display(&self) -> String {
        if self.symbolicated {
            let location = match (&self.file, self.line) {
                (Some(f), Some(l)) => format!(" ({}:{})", f, l),
                (Some(f), None) => format!(" ({})", f),
                _ => String::new(),
            };
            format!(
                "{}{}",
                self.function.as_deref().unwrap_or("<unknown>"),
                location
            )
        } else {
            self.raw.clone()
        }
    }
}

/// Result of symbolicating a stack trace.
#[derive(Debug)]
pub struct SymbolicatedStack {
    /// Original raw stack trace
    pub raw: String,
    /// Symbolicated frames
    pub frames: Vec<SymbolicatedFrame>,
    /// Number of frames that were successfully symbolicated
    pub symbolicated_count: usize,
    /// Total number of frames
    pub total_count: usize,
}

impl SymbolicatedStack {
    /// Format the symbolicated stack for display.
    pub fn display(&self) -> String {
        self.frames
            .iter()
            .map(|f| f.display())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get symbolication percentage.
    pub fn percentage(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            (self.symbolicated_count as f64 / self.total_count as f64) * 100.0
        }
    }
}

/// Main symbolicator that dispatches to platform-specific implementations.
pub struct Symbolicator {
    store: MappingStore,
}

impl Symbolicator {
    /// Create a new symbolicator with the given mapping store.
    pub fn new(store: MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate a stack trace.
    pub fn symbolicate(
        &self,
        stack_trace: &str,
        context: &SymbolicationContext,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        match &context.platform {
            Platform::Android => {
                let sym = AndroidSymbolicator::new(&self.store);
                sym.symbolicate(stack_trace, context)
            }
            Platform::Electron => {
                let sym = JavaScriptSymbolicator::new(&self.store);
                sym.symbolicate(stack_trace, context)
            }
            Platform::Flutter => {
                let sym = FlutterSymbolicator::new(&self.store);
                sym.symbolicate(stack_trace, context)
            }
            Platform::Rust => {
                let sym = RustSymbolicator::new(&self.store);
                sym.symbolicate(stack_trace, context)
            }
            Platform::Go => {
                let sym = GoSymbolicator::new(&self.store);
                sym.symbolicate(stack_trace, context)
            }
            Platform::Python => {
                let sym = PythonSymbolicator::new(&self.store);
                sym.symbolicate(stack_trace, context)
            }
            Platform::ReactNative => {
                let sym = ReactNativeSymbolicator::new(&self.store);
                sym.symbolicate(stack_trace, context)
            }
            Platform::Unknown(p) => Err(SymbolicationError::UnsupportedPlatform(p.clone())),
        }
    }
}
