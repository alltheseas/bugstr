//! JavaScript/Electron symbolication using source maps.
//!
//! Parses source map files (.map) and uses them to map minified
//! JavaScript stack traces back to original source locations.

use std::fs;

use regex::Regex;
use sourcemap::SourceMap;

use super::{
    MappingStore, SymbolicatedFrame, SymbolicatedStack, SymbolicationContext, SymbolicationError,
};

/// JavaScript stack trace symbolicator.
pub struct JavaScriptSymbolicator<'a> {
    store: &'a MappingStore,
}

impl<'a> JavaScriptSymbolicator<'a> {
    /// Create a new JavaScript symbolicator.
    pub fn new(store: &'a MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate a JavaScript stack trace.
    pub fn symbolicate(
        &self,
        stack_trace: &str,
        context: &SymbolicationContext,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Load source map file
        let mapping_info = self
            .store
            .get_with_fallback(
                &context.platform,
                context.app_id.as_deref().unwrap_or("unknown"),
                context.version.as_deref().unwrap_or("unknown"),
            )
            .ok_or_else(|| SymbolicationError::MappingNotFound {
                platform: "javascript".to_string(),
                app_id: context.app_id.clone().unwrap_or_default(),
                version: context.version.clone().unwrap_or_default(),
            })?;

        let content = fs::read_to_string(&mapping_info.path)?;
        let sourcemap = SourceMap::from_reader(content.as_bytes())
            .map_err(|e| SymbolicationError::ParseError(e.to_string()))?;

        // Parse and symbolicate each frame
        let mut frames = Vec::new();
        let mut symbolicated_count = 0;

        // Regex patterns for JavaScript stack frames
        // Chrome/V8 style: "    at functionName (file.js:line:col)"
        // Firefox style: "functionName@file.js:line:col"
        // Node.js style: "    at functionName (file.js:line:col)"
        // Note: File paths can contain colons (URLs, Windows paths), so we match
        // greedily up to the last :line:col pattern
        let chrome_re = Regex::new(
            r"^\s*at\s+(?:(.+?)\s+)?\(?(.+):(\d+):(\d+)\)?"
        ).unwrap();
        let firefox_re = Regex::new(
            r"^(.+?)@(.+):(\d+):(\d+)$"
        ).unwrap();

        for line in stack_trace.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parsed = chrome_re.captures(line).or_else(|| firefox_re.captures(line));

            if let Some(caps) = parsed {
                let _function = caps.get(1).map(|m| m.as_str());
                let _file = caps.get(2).map(|m| m.as_str());
                let line_num: u32 = caps
                    .get(3)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0);
                let col_num: u32 = caps
                    .get(4)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0);

                // Source maps use 0-based line/column numbers
                let line_0 = if line_num > 0 { line_num - 1 } else { 0 };
                let col_0 = if col_num > 0 { col_num - 1 } else { 0 };

                if let Some(token) = sourcemap.lookup_token(line_0, col_0) {
                    let orig_function = token.get_name().map(|s| s.to_string());
                    let orig_file = token.get_source().map(|s| s.to_string());
                    let orig_line = token.get_src_line();
                    let orig_col = token.get_src_col();

                    let function_name = orig_function
                        .or_else(|| _function.map(|s| s.to_string()))
                        .unwrap_or_else(|| "<anonymous>".to_string());

                    frames.push(SymbolicatedFrame::symbolicated(
                        line.to_string(),
                        function_name,
                        orig_file,
                        Some(orig_line + 1), // Convert back to 1-based
                        Some(orig_col + 1),
                    ));
                    symbolicated_count += 1;
                } else {
                    frames.push(SymbolicatedFrame::raw(line.to_string()));
                }
            } else {
                frames.push(SymbolicatedFrame::raw(line.to_string()));
            }
        }

        Ok(SymbolicatedStack {
            raw: stack_trace.to_string(),
            frames,
            symbolicated_count,
            total_count: stack_trace.lines().filter(|l| !l.trim().is_empty()).count(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chrome_stack_frame() {
        let chrome_re = Regex::new(
            r"^\s*at\s+(?:(.+?)\s+)?\(?(.+):(\d+):(\d+)\)?"
        ).unwrap();

        let frame = "    at myFunction (bundle.js:1:2345)";
        let caps = chrome_re.captures(frame).unwrap();

        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("myFunction"));
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("bundle.js"));
        assert_eq!(caps.get(3).map(|m| m.as_str()), Some("1"));
        assert_eq!(caps.get(4).map(|m| m.as_str()), Some("2345"));
    }

    #[test]
    fn test_parse_chrome_stack_frame_with_url() {
        let chrome_re = Regex::new(
            r"^\s*at\s+(?:(.+?)\s+)?\(?(.+):(\d+):(\d+)\)?"
        ).unwrap();

        let frame = "    at myFunction (http://localhost:8080/bundle.js:1:2345)";
        let caps = chrome_re.captures(frame).unwrap();

        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("myFunction"));
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("http://localhost:8080/bundle.js"));
        assert_eq!(caps.get(3).map(|m| m.as_str()), Some("1"));
        assert_eq!(caps.get(4).map(|m| m.as_str()), Some("2345"));
    }

    #[test]
    fn test_parse_firefox_stack_frame() {
        let firefox_re = Regex::new(r"^(.+?)@(.+):(\d+):(\d+)$").unwrap();

        let frame = "myFunction@bundle.js:1:2345";
        let caps = firefox_re.captures(frame).unwrap();

        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("myFunction"));
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("bundle.js"));
        assert_eq!(caps.get(3).map(|m| m.as_str()), Some("1"));
        assert_eq!(caps.get(4).map(|m| m.as_str()), Some("2345"));
    }
}
