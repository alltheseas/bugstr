//! Flutter/Dart symbolication.
//!
//! Uses Flutter symbol files or the external `flutter symbolize` command
//! to symbolicate Dart stack traces from release builds.

use std::fs;
use std::process::Command;

use regex::Regex;

use super::{
    MappingStore, SymbolicatedFrame, SymbolicatedStack, SymbolicationContext, SymbolicationError,
};

/// Flutter stack trace symbolicator.
pub struct FlutterSymbolicator<'a> {
    store: &'a MappingStore,
}

impl<'a> FlutterSymbolicator<'a> {
    /// Create a new Flutter symbolicator.
    pub fn new(store: &'a MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate a Flutter stack trace.
    ///
    /// Attempts to use the `flutter symbolize` command if available,
    /// otherwise falls back to basic symbol file parsing.
    pub fn symbolicate(
        &self,
        stack_trace: &str,
        context: &SymbolicationContext,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Try to find symbols file
        let mapping_info = self.store.get_with_fallback(
            &context.platform,
            context.app_id.as_deref().unwrap_or("unknown"),
            context.version.as_deref().unwrap_or("unknown"),
        );

        // Try flutter symbolize command first
        if let Some(info) = &mapping_info {
            if let Ok(result) = self.symbolicate_with_flutter_command(stack_trace, &info.path) {
                return Ok(result);
            }
        }

        // Fall back to basic parsing
        self.symbolicate_basic(stack_trace, mapping_info.map(|i| i.path.as_path()))
    }

    /// Use `flutter symbolize` command for symbolication.
    fn symbolicate_with_flutter_command(
        &self,
        stack_trace: &str,
        symbols_path: &std::path::Path,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Write stack trace to temp file
        let temp_dir = std::env::temp_dir();
        let input_path = temp_dir.join("bugstr_flutter_input.txt");
        fs::write(&input_path, stack_trace)?;

        // Run flutter symbolize
        let output = Command::new("flutter")
            .args([
                "symbolize",
                "-i",
                input_path.to_str().unwrap(),
                "-d",
                symbols_path.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| SymbolicationError::ToolError(format!("flutter symbolize failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SymbolicationError::ToolError(format!(
                "flutter symbolize failed: {}",
                stderr
            )));
        }

        let symbolicated = String::from_utf8_lossy(&output.stdout);

        // Parse the symbolicated output
        let frames: Vec<SymbolicatedFrame> = symbolicated
            .lines()
            .map(|line| {
                // Check if line was symbolicated (contains source location)
                if line.contains("(") && line.contains(".dart:") {
                    SymbolicatedFrame {
                        raw: line.to_string(),
                        function: self.extract_function(line),
                        file: self.extract_file(line),
                        line: self.extract_line(line),
                        column: None,
                        symbolicated: true,
                    }
                } else {
                    SymbolicatedFrame::raw(line.to_string())
                }
            })
            .collect();

        let symbolicated_count = frames.iter().filter(|f| f.symbolicated).count();

        Ok(SymbolicatedStack {
            raw: stack_trace.to_string(),
            frames,
            symbolicated_count,
            total_count: stack_trace.lines().filter(|l| !l.trim().is_empty()).count(),
        })
    }

    /// Basic symbolication without flutter command.
    fn symbolicate_basic(
        &self,
        stack_trace: &str,
        _symbols_path: Option<&std::path::Path>,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Regex for Dart stack frames
        // Example: #0      MyClass.myMethod (package:myapp/src/my_class.dart:42:15)
        let frame_re = Regex::new(
            r"#(\d+)\s+(.+?)\s+\((.+?):(\d+)(?::(\d+))?\)"
        ).unwrap();

        let mut frames = Vec::new();

        for line in stack_trace.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(caps) = frame_re.captures(line) {
                let function = caps.get(2).map(|m| m.as_str().to_string());
                let file = caps.get(3).map(|m| m.as_str().to_string());
                let line_num: Option<u32> = caps.get(4).and_then(|m| m.as_str().parse().ok());
                let col: Option<u32> = caps.get(5).and_then(|m| m.as_str().parse().ok());

                frames.push(SymbolicatedFrame {
                    raw: line.to_string(),
                    function,
                    file,
                    line: line_num,
                    column: col,
                    symbolicated: true, // Already readable in debug builds
                });
            } else {
                frames.push(SymbolicatedFrame::raw(line.to_string()));
            }
        }

        let symbolicated_count = frames.iter().filter(|f| f.symbolicated).count();

        Ok(SymbolicatedStack {
            raw: stack_trace.to_string(),
            frames,
            symbolicated_count,
            total_count: stack_trace.lines().filter(|l| !l.trim().is_empty()).count(),
        })
    }

    fn extract_function(&self, line: &str) -> Option<String> {
        // Extract function name from symbolicated line
        let re = Regex::new(r"#\d+\s+(.+?)\s+\(").ok()?;
        re.captures(line)?.get(1).map(|m| m.as_str().to_string())
    }

    fn extract_file(&self, line: &str) -> Option<String> {
        // Extract file path from symbolicated line
        let re = Regex::new(r"\((.+\.dart):\d+").ok()?;
        re.captures(line)?.get(1).map(|m| m.as_str().to_string())
    }

    fn extract_line(&self, line: &str) -> Option<u32> {
        // Extract line number from symbolicated line
        let re = Regex::new(r"\.dart:(\d+)").ok()?;
        re.captures(line)?.get(1)?.as_str().parse().ok()
    }
}
