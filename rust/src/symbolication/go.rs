//! Go symbolication.
//!
//! Go binaries typically include symbol information by default.
//! For stripped binaries, this module attempts to use external symbol files.

use regex::Regex;

use super::{
    MappingStore, SymbolicatedFrame, SymbolicatedStack, SymbolicationContext, SymbolicationError,
};

/// Go stack trace symbolicator.
pub struct GoSymbolicator<'a> {
    store: &'a MappingStore,
}

impl<'a> GoSymbolicator<'a> {
    /// Create a new Go symbolicator.
    pub fn new(store: &'a MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate a Go stack trace.
    ///
    /// Go stack traces typically already include source locations.
    /// This method parses and formats them for display.
    pub fn symbolicate(
        &self,
        stack_trace: &str,
        context: &SymbolicationContext,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Try to find symbol file (for stripped binaries)
        let _mapping_info = self.store.get_with_fallback(
            &context.platform,
            context.app_id.as_deref().unwrap_or("unknown"),
            context.version.as_deref().unwrap_or("unknown"),
        );

        self.parse_go_stack(stack_trace)
    }

    /// Parse a Go stack trace.
    fn parse_go_stack(
        &self,
        stack_trace: &str,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Go stack trace format:
        // goroutine 1 [running]:
        // main.myFunction(0x123, 0x456)
        //         /path/to/file.go:42 +0x1a
        // main.main()
        //         /path/to/main.go:10 +0x2b

        let func_re = Regex::new(r"^([a-zA-Z0-9_./*]+)\(([^)]*)\)$").unwrap();
        let location_re = Regex::new(r"^\s+(.+\.go):(\d+)\s+\+0x[0-9a-f]+$").unwrap();
        let goroutine_re = Regex::new(r"^goroutine\s+\d+\s+\[.+\]:$").unwrap();

        let mut frames = Vec::new();
        let mut current_function: Option<String> = None;
        let mut current_args: Option<String> = None;
        let mut current_raw = String::new();

        for line in stack_trace.lines() {
            let line_trimmed = line.trim();

            // Skip goroutine header
            if goroutine_re.is_match(line_trimmed) {
                frames.push(SymbolicatedFrame::raw(line.to_string()));
                continue;
            }

            // Function line
            if let Some(caps) = func_re.captures(line_trimmed) {
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

                current_function = Some(caps[1].to_string());
                current_args = Some(caps[2].to_string());
                current_raw = line.to_string();
                continue;
            }

            // Location line
            if let Some(caps) = location_re.captures(line) {
                if let Some(func) = current_function.take() {
                    let file = caps.get(1).map(|m| m.as_str().to_string());
                    let line_num: Option<u32> = caps.get(2).and_then(|m| m.as_str().parse().ok());

                    let display_func = if let Some(args) = current_args.take() {
                        if args.is_empty() {
                            func
                        } else {
                            format!("{}(...)", func)
                        }
                    } else {
                        func
                    };

                    frames.push(SymbolicatedFrame {
                        raw: format!("{}\n{}", current_raw, line),
                        function: Some(display_func),
                        file,
                        line: line_num,
                        column: None,
                        symbolicated: true,
                    });
                    current_raw.clear();
                }
                continue;
            }

            // Other lines
            if !line_trimmed.is_empty() {
                frames.push(SymbolicatedFrame::raw(line.to_string()));
            }
        }

        // Handle last frame without location
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go_stack() {
        let stack = r#"goroutine 1 [running]:
main.myFunction(0x123, 0x456)
        /home/user/project/main.go:42 +0x1a
main.main()
        /home/user/project/main.go:10 +0x2b"#;

        let store = MappingStore::new("/tmp");
        let sym = GoSymbolicator::new(&store);
        let result = sym.parse_go_stack(stack).unwrap();

        assert!(result.symbolicated_count >= 2);
    }
}
