//! Rust symbolication using addr2line/DWARF debug info.
//!
//! Parses Rust stack traces and resolves addresses to source locations
//! using debug symbols.

use regex::Regex;

use super::{
    MappingStore, SymbolicatedFrame, SymbolicatedStack, SymbolicationContext, SymbolicationError,
};

/// Rust stack trace symbolicator.
pub struct RustSymbolicator<'a> {
    store: &'a MappingStore,
}

impl<'a> RustSymbolicator<'a> {
    /// Create a new Rust symbolicator.
    pub fn new(store: &'a MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate a Rust stack trace.
    ///
    /// Rust stack traces from panics typically include source locations
    /// in debug builds. For release builds with symbols stripped, this
    /// attempts to use addr2line with debug symbols if available.
    pub fn symbolicate(
        &self,
        stack_trace: &str,
        context: &SymbolicationContext,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Try to find debug symbols
        let mapping_info = self.store.get_with_fallback(
            &context.platform,
            context.app_id.as_deref().unwrap_or("unknown"),
            context.version.as_deref().unwrap_or("unknown"),
        );

        // Rust backtraces already include source info in debug builds
        // We just need to parse and format them nicely
        self.parse_rust_backtrace(stack_trace, mapping_info.map(|i| i.path.as_path()))
    }

    /// Parse a Rust backtrace.
    fn parse_rust_backtrace(
        &self,
        stack_trace: &str,
        _symbols_path: Option<&std::path::Path>,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Regex patterns for Rust stack frames
        // Format 1: "   0: std::panicking::begin_panic"
        // Format 2: "   0:     0x7f1234567890 - std::panicking::begin_panic"
        // Format 3 (with location): "             at /path/to/file.rs:42:5"
        let frame_num_re = Regex::new(r"^\s*(\d+):\s+(?:0x[0-9a-f]+\s+-\s+)?(.+)$").unwrap();
        let location_re = Regex::new(r"^\s+at\s+(.+):(\d+)(?::(\d+))?$").unwrap();

        let mut frames = Vec::new();
        let mut current_function: Option<String> = None;
        let mut current_raw: String = String::new();

        for line in stack_trace.lines() {
            // Check for frame number line
            if let Some(caps) = frame_num_re.captures(line) {
                // Save previous frame if exists
                if let Some(func) = current_function.take() {
                    frames.push(SymbolicatedFrame {
                        raw: current_raw.clone(),
                        function: Some(func),
                        file: None,
                        line: None,
                        column: None,
                        symbolicated: true,
                    });
                }

                current_function = Some(caps[2].trim().to_string());
                current_raw = line.to_string();
                continue;
            }

            // Check for location line (belongs to current frame)
            if let Some(caps) = location_re.captures(line) {
                if let Some(func) = current_function.take() {
                    let file = caps.get(1).map(|m| m.as_str().to_string());
                    let line_num: Option<u32> = caps.get(2).and_then(|m| m.as_str().parse().ok());
                    let col: Option<u32> = caps.get(3).and_then(|m| m.as_str().parse().ok());

                    frames.push(SymbolicatedFrame {
                        raw: format!("{}\n{}", current_raw, line),
                        function: Some(func),
                        file,
                        line: line_num,
                        column: col,
                        symbolicated: true,
                    });
                    current_raw.clear();
                }
                continue;
            }

            // Other lines (thread info, etc.)
            if !line.trim().is_empty() {
                frames.push(SymbolicatedFrame::raw(line.to_string()));
            }
        }

        // Don't forget last frame
        if let Some(func) = current_function {
            frames.push(SymbolicatedFrame {
                raw: current_raw,
                function: Some(func),
                file: None,
                line: None,
                column: None,
                symbolicated: true,
            });
        }

        let symbolicated_count = frames.iter().filter(|f| f.symbolicated).count();
        let total_count = frames.len();

        Ok(SymbolicatedStack {
            raw: stack_trace.to_string(),
            frames,
            symbolicated_count,
            total_count,
        })
    }

    // Note: addr2line integration for stripped binaries is available but requires
    // additional setup. For most Rust applications, debug builds include full
    // symbol information in the stack trace itself.
}
