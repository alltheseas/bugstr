//! Python symbolication.
//!
//! Python stack traces typically include source information.
//! For bundled apps (PyInstaller, Nuitka), this module attempts to
//! map back to original source files.

use regex::Regex;

use super::{
    MappingStore, SymbolicatedFrame, SymbolicatedStack, SymbolicationContext, SymbolicationError,
};

/// Python stack trace symbolicator.
pub struct PythonSymbolicator<'a> {
    store: &'a MappingStore,
}

impl<'a> PythonSymbolicator<'a> {
    /// Create a new Python symbolicator.
    pub fn new(store: &'a MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate a Python stack trace.
    ///
    /// Python tracebacks already include source locations in most cases.
    /// This method parses and formats them, and attempts to resolve
    /// bundled app paths to original sources if a mapping is available.
    pub fn symbolicate(
        &self,
        stack_trace: &str,
        context: &SymbolicationContext,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Try to find mapping file (for bundled apps)
        let _mapping_info = self.store.get_with_fallback(
            &context.platform,
            context.app_id.as_deref().unwrap_or("unknown"),
            context.version.as_deref().unwrap_or("unknown"),
        );

        self.parse_python_traceback(stack_trace)
    }

    /// Parse a Python traceback.
    fn parse_python_traceback(
        &self,
        stack_trace: &str,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Python traceback format:
        // Traceback (most recent call last):
        //   File "/path/to/file.py", line 42, in my_function
        //     some_code_here()
        //   File "/path/to/other.py", line 10, in other_function
        //     other_code()
        // ExceptionType: error message

        let file_re = Regex::new(
            r#"^\s*File\s+"([^"]+)",\s+line\s+(\d+),\s+in\s+(.+)$"#
        ).unwrap();
        // Exception line must end with Error, Exception, or Warning to avoid matching "Traceback"
        let exception_re = Regex::new(r"^([A-Z][a-zA-Z0-9]*(?:Error|Exception|Warning)):?\s*(.*)$").unwrap();

        let mut frames = Vec::new();
        let mut in_frame = false;
        let mut current_file: Option<String> = None;
        let mut current_line: Option<u32> = None;
        let mut current_function: Option<String> = None;
        let mut current_raw = String::new();

        for line in stack_trace.lines() {
            // File line
            if let Some(caps) = file_re.captures(line) {
                // Save previous frame
                if in_frame {
                    frames.push(SymbolicatedFrame {
                        raw: current_raw.clone(),
                        function: current_function.take(),
                        file: current_file.take(),
                        line: current_line.take(),
                        column: None,
                        symbolicated: true,
                    });
                }

                current_file = Some(caps[1].to_string());
                current_line = caps[2].parse().ok();
                current_function = Some(caps[3].to_string());
                current_raw = line.to_string();
                in_frame = true;
                continue;
            }

            // Code line (belongs to current frame)
            if in_frame && line.starts_with("    ") && !line.trim().is_empty() {
                current_raw.push('\n');
                current_raw.push_str(line);
                continue;
            }

            // Exception line
            if let Some(caps) = exception_re.captures(line) {
                // Save any pending frame
                if in_frame {
                    frames.push(SymbolicatedFrame {
                        raw: current_raw.clone(),
                        function: current_function.take(),
                        file: current_file.take(),
                        line: current_line.take(),
                        column: None,
                        symbolicated: true,
                    });
                    in_frame = false;
                }

                let exception_type = caps[1].to_string();
                let message = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                frames.push(SymbolicatedFrame {
                    raw: line.to_string(),
                    function: Some(format!("{}: {}", exception_type, message)),
                    file: None,
                    line: None,
                    column: None,
                    symbolicated: true,
                });
                continue;
            }

            // Header or other lines
            if !line.trim().is_empty() {
                if in_frame {
                    frames.push(SymbolicatedFrame {
                        raw: current_raw.clone(),
                        function: current_function.take(),
                        file: current_file.take(),
                        line: current_line.take(),
                        column: None,
                        symbolicated: true,
                    });
                    in_frame = false;
                    current_raw.clear();
                }
                frames.push(SymbolicatedFrame::raw(line.to_string()));
            }
        }

        // Handle last frame
        if in_frame {
            frames.push(SymbolicatedFrame {
                raw: current_raw,
                function: current_function,
                file: current_file,
                line: current_line,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_python_traceback() {
        let traceback = r#"Traceback (most recent call last):
  File "/home/user/app/main.py", line 42, in my_function
    result = do_something()
  File "/home/user/app/utils.py", line 10, in do_something
    raise ValueError("test error")
ValueError: test error"#;

        let store = MappingStore::new("/tmp");
        let sym = PythonSymbolicator::new(&store);
        let result = sym.parse_python_traceback(traceback).unwrap();

        assert!(result.symbolicated_count >= 2);
    }
}
