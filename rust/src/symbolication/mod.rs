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
//! - **Rust**: Backtrace parsing (debug builds include source locations)
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

    #[error("Invalid path component: {0}")]
    InvalidPath(String),
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

/// Context information needed to symbolicate a stack trace.
///
/// Provides metadata about the crash report that helps locate the correct
/// mapping files and apply platform-specific symbolication logic.
///
/// # Fields
///
/// * `platform` - The platform/runtime the crash originated from. Determines
///   which symbolicator implementation to use. See [`Platform`] for supported values.
///
/// * `app_id` - Optional application identifier such as:
///   - Android: package name (e.g., `"com.example.myapp"`)
///   - iOS/Flutter: bundle ID (e.g., `"com.example.myapp"`)
///   - Electron: app name (e.g., `"my-desktop-app"`)
///   - Other: any unique identifier
///   When `None`, defaults to `"unknown"` for mapping file lookup.
///
/// * `version` - Optional semantic version string (e.g., `"1.2.3"`).
///   Used to locate version-specific mapping files. When `None`, defaults to
///   `"unknown"`. If exact version not found, [`MappingStore::get_with_fallback`]
///   returns the newest available version using semver comparison.
///
/// * `build_id` - Optional build identifier or commit hash.
///   Currently unused but reserved for future build-specific mapping lookup.
///
/// # Example
///
/// ```
/// use bugstr::symbolication::{SymbolicationContext, Platform};
///
/// let context = SymbolicationContext {
///     platform: Platform::Android,
///     app_id: Some("com.myapp".to_string()),
///     version: Some("2.1.0".to_string()),
///     build_id: None,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SymbolicationContext {
    /// Platform the crash came from. Determines which symbolicator to use.
    pub platform: Platform,
    /// Application identifier (package name, bundle ID, app name).
    /// Defaults to `"unknown"` if `None`.
    pub app_id: Option<String>,
    /// Application version (e.g., `"1.0.0"`).
    /// Falls back to newest available if exact match not found.
    pub version: Option<String>,
    /// Build ID or commit hash. Reserved for future use.
    pub build_id: Option<String>,
}

/// A single stack frame with optional symbolication information.
///
/// Represents one frame in a stack trace. If symbolication succeeded,
/// the `function`, `file`, and `line` fields contain human-readable
/// source information. If not, only the `raw` field contains the
/// original obfuscated/minified frame text.
///
/// # Fields
///
/// * `raw` - Original frame text as it appeared in the stack trace.
///   Always populated, useful for debugging and fallback display.
///
/// * `function` - Symbolicated function or method name (e.g., `"MyClass.myMethod"`).
///   `None` if symbolication failed or function name unavailable.
///
/// * `file` - Source file path (e.g., `"src/main.rs"`, `"MyClass.java"`).
///   `None` if symbolication failed or file info unavailable.
///
/// * `line` - 1-based line number in the source file.
///   `None` if symbolication failed or line info unavailable.
///
/// * `column` - 1-based column number in the source file.
///   `None` if symbolication failed or column info unavailable.
///   Primarily available for JavaScript/source map symbolication.
///
/// * `symbolicated` - `true` if this frame was successfully symbolicated,
///   `false` if it contains only raw/unparsed data.
///
/// # Display Format
///
/// The [`display()`](Self::display) method formats frames as:
/// - Symbolicated: `"functionName (file.rs:42)"` or `"functionName (file.rs)"` or `"functionName"`
/// - Unsymbolicated: returns the raw text unchanged
///
/// # Example
///
/// ```
/// use bugstr::symbolication::SymbolicatedFrame;
///
/// // Create a symbolicated frame
/// let frame = SymbolicatedFrame::symbolicated(
///     "at a.b.c(Unknown:1)".to_string(),
///     "com.example.MyClass.method".to_string(),
///     Some("MyClass.java".to_string()),
///     Some(42),
///     None,
/// );
/// assert!(frame.symbolicated);
/// assert_eq!(frame.display(), "com.example.MyClass.method (MyClass.java:42)");
///
/// // Create an unsymbolicated frame
/// let raw_frame = SymbolicatedFrame::raw("at a.b.c(Unknown:1)".to_string());
/// assert!(!raw_frame.symbolicated);
/// assert_eq!(raw_frame.display(), "at a.b.c(Unknown:1)");
/// ```
#[derive(Debug, Clone)]
pub struct SymbolicatedFrame {
    /// Original raw frame text as it appeared in the stack trace.
    pub raw: String,
    /// Symbolicated function/method name, or `None` if unavailable.
    pub function: Option<String>,
    /// Source file path, or `None` if unavailable.
    pub file: Option<String>,
    /// 1-based line number, or `None` if unavailable.
    pub line: Option<u32>,
    /// 1-based column number, or `None` if unavailable.
    pub column: Option<u32>,
    /// Whether this frame was successfully symbolicated.
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
///
/// Contains both the original raw stack trace and the processed frames,
/// along with statistics about symbolication success. This struct is returned
/// by [`Symbolicator::symbolicate`] on successful symbolication.
///
/// # Fields
///
/// * `raw` - The original stack trace text exactly as provided to the symbolicator.
///   Preserved for logging, debugging, and fallback display.
///
/// * `frames` - Vector of [`SymbolicatedFrame`] objects, one per line/frame in the
///   stack trace. Frames maintain the same order as the original stack trace.
///   Each frame indicates whether it was successfully symbolicated via its
///   `symbolicated` field.
///
/// * `symbolicated_count` - Number of frames where symbolication succeeded
///   (i.e., frames where `symbolicated == true`). Use this with `total_count`
///   to calculate success rate.
///
/// * `total_count` - Total number of non-empty lines/frames in the stack trace.
///   Note: This counts all non-empty lines, which may differ from `frames.len()`
///   depending on the platform-specific parser implementation.
///
/// # Example
///
/// ```
/// use bugstr::symbolication::SymbolicatedStack;
///
/// fn process_result(result: SymbolicatedStack) {
///     println!("Symbolicated {}/{} frames ({:.1}%)",
///         result.symbolicated_count,
///         result.total_count,
///         result.percentage());
///
///     // Display the symbolicated stack
///     println!("{}", result.display());
/// }
/// ```
#[derive(Debug)]
pub struct SymbolicatedStack {
    /// Original raw stack trace text as provided to the symbolicator.
    pub raw: String,
    /// Processed frames in stack trace order.
    pub frames: Vec<SymbolicatedFrame>,
    /// Count of frames where symbolication succeeded.
    pub symbolicated_count: usize,
    /// Total count of non-empty lines in the original stack trace.
    pub total_count: usize,
}

impl SymbolicatedStack {
    /// Format the symbolicated stack trace for human-readable display.
    ///
    /// Iterates through all frames and calls [`SymbolicatedFrame::display()`] on each,
    /// joining them with newlines. Symbolicated frames show function names and source
    /// locations; unsymbolicated frames show the original raw text.
    ///
    /// # Returns
    ///
    /// A newline-separated string of all frames suitable for terminal output or logging.
    ///
    /// # Example
    ///
    /// ```text
    /// com.example.MyClass.method (MyClass.java:42)
    /// com.example.OtherClass.call (OtherClass.java:15)
    /// at a.b.c(Unknown:1)
    /// ```
    pub fn display(&self) -> String {
        self.frames
            .iter()
            .map(|f| f.display())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Calculate the percentage of frames that were successfully symbolicated.
    ///
    /// Returns `(symbolicated_count / total_count) * 100.0`. If `total_count` is zero,
    /// returns `0.0` to avoid division by zero.
    ///
    /// # Returns
    ///
    /// A floating-point percentage from `0.0` to `100.0`.
    ///
    /// # Example
    ///
    /// ```
    /// # use bugstr::symbolication::{SymbolicatedStack, SymbolicatedFrame};
    /// # let stack = SymbolicatedStack {
    /// #     raw: String::new(),
    /// #     frames: vec![],
    /// #     symbolicated_count: 8,
    /// #     total_count: 10,
    /// # };
    /// let pct = stack.percentage();
    /// assert!((pct - 80.0).abs() < 0.001);
    /// ```
    pub fn percentage(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            (self.symbolicated_count as f64 / self.total_count as f64) * 100.0
        }
    }
}

/// Main symbolicator that dispatches to platform-specific implementations.
///
/// `Symbolicator` is the primary entry point for stack trace symbolication.
/// It holds a [`MappingStore`] containing mapping files and dispatches
/// symbolication requests to the appropriate platform-specific implementation
/// based on the [`SymbolicationContext::platform`] field.
///
/// # Supported Platforms
///
/// - [`Platform::Android`] - Uses [`AndroidSymbolicator`] with ProGuard/R8 mapping.txt files
/// - [`Platform::Electron`] - Uses [`JavaScriptSymbolicator`] with source map files
/// - [`Platform::Flutter`] - Uses [`FlutterSymbolicator`] with Flutter symbol files
/// - [`Platform::Rust`] - Uses [`RustSymbolicator`] for backtrace parsing
/// - [`Platform::Go`] - Uses [`GoSymbolicator`] for goroutine stack parsing
/// - [`Platform::Python`] - Uses [`PythonSymbolicator`] for Python traceback parsing
/// - [`Platform::ReactNative`] - Uses [`ReactNativeSymbolicator`] with Hermes + JS source maps
///
/// # Thread Safety
///
/// `Symbolicator` is `Send` but not `Sync`. For use in async contexts with multiple
/// concurrent requests, wrap in `Arc<Symbolicator>` and use `spawn_blocking` for
/// the CPU-bound symbolication work.
///
/// # Example
///
/// ```rust,ignore
/// use bugstr::symbolication::{Symbolicator, MappingStore, Platform, SymbolicationContext};
///
/// // Create and scan mapping store
/// let mut store = MappingStore::new("/path/to/mappings");
/// store.scan()?;
///
/// let symbolicator = Symbolicator::new(store);
///
/// let context = SymbolicationContext {
///     platform: Platform::Android,
///     app_id: Some("com.example.app".to_string()),
///     version: Some("1.0.0".to_string()),
///     build_id: None,
/// };
///
/// let stack = "java.lang.NullPointerException\n\tat a.b.c(Unknown:1)";
/// match symbolicator.symbolicate(stack, &context) {
///     Ok(result) => println!("{}", result.display()),
///     Err(e) => eprintln!("Symbolication failed: {}", e),
/// }
/// ```
pub struct Symbolicator {
    store: MappingStore,
}

impl Symbolicator {
    /// Create a new symbolicator with the given mapping store.
    ///
    /// # Arguments
    ///
    /// * `store` - A [`MappingStore`] that has been populated with mapping files.
    ///   Call [`MappingStore::scan()`] before creating the symbolicator to load
    ///   available mapping files from disk.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut store = MappingStore::new("/path/to/mappings");
    /// store.scan()?;
    /// let symbolicator = Symbolicator::new(store);
    /// ```
    pub fn new(store: MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate a stack trace using platform-specific logic.
    ///
    /// Dispatches to the appropriate platform symbolicator based on `context.platform`,
    /// loads the corresponding mapping file from the store, and processes the stack trace.
    ///
    /// # Arguments
    ///
    /// * `stack_trace` - Raw stack trace text. Format varies by platform:
    ///   - Android: Java stack trace with `at` frames
    ///   - JavaScript/Electron: Error stack with `at` or `@` frames
    ///   - Flutter: Dart stack trace with `#N` numbered frames
    ///   - Rust: Backtrace with `N:` numbered frames
    ///   - Go: Goroutine stack with `goroutine N [status]:` header
    ///   - Python: Traceback with `File "...", line N` frames
    ///   - React Native: Mixed Hermes/JavaScript stack traces
    ///
    /// * `context` - [`SymbolicationContext`] providing platform, app ID, and version
    ///   for locating the correct mapping file.
    ///
    /// # Returns
    ///
    /// * `Ok(SymbolicatedStack)` - Successfully processed stack trace. Note that
    ///   individual frames may still be unsymbolicated if they couldn't be mapped;
    ///   check `symbolicated_count` vs `total_count` for success rate.
    ///
    /// * `Err(SymbolicationError)` - Symbolication failed. Possible errors:
    ///   - [`SymbolicationError::MappingNotFound`] - No mapping file for the given
    ///     platform/app/version combination (only for platforms that require mappings)
    ///   - [`SymbolicationError::ParseError`] - Mapping file exists but couldn't be parsed
    ///   - [`SymbolicationError::IoError`] - Failed to read mapping file from disk
    ///   - [`SymbolicationError::UnsupportedPlatform`] - Platform is `Unknown(...)`,
    ///     returned for unrecognized platform strings
    ///   - [`SymbolicationError::ToolError`] - External tool (e.g., `flutter symbolize`)
    ///     failed or is not available
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let result = symbolicator.symbolicate(stack_trace, &context)?;
    ///
    /// if result.symbolicated_count == result.total_count {
    ///     println!("Fully symbolicated:");
    /// } else {
    ///     println!("Partially symbolicated ({:.0}%):", result.percentage());
    /// }
    /// println!("{}", result.display());
    /// ```
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
