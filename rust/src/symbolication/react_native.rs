//! React Native symbolication.
//!
//! Handles both Hermes bytecode symbolication and JavaScript source maps
//! for React Native applications.

use std::fs;

use regex::Regex;
use sourcemap::SourceMap;

use super::{
    MappingStore, SymbolicatedFrame, SymbolicatedStack, SymbolicationContext, SymbolicationError,
};

/// React Native stack trace symbolicator.
pub struct ReactNativeSymbolicator<'a> {
    store: &'a MappingStore,
}

impl<'a> ReactNativeSymbolicator<'a> {
    /// Create a new React Native symbolicator.
    pub fn new(store: &'a MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate a React Native stack trace.
    ///
    /// React Native stacks can contain:
    /// - JavaScript frames (bundled, need source maps)
    /// - Native frames (Java/ObjC, may need ProGuard/dSYM)
    /// - Hermes bytecode frames (need Hermes source maps)
    pub fn symbolicate(
        &self,
        stack_trace: &str,
        context: &SymbolicationContext,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Try to find source map
        let mapping_info = self.store.get_with_fallback(
            &context.platform,
            context.app_id.as_deref().unwrap_or("unknown"),
            context.version.as_deref().unwrap_or("unknown"),
        );

        let sourcemap = if let Some(info) = mapping_info {
            let content = fs::read_to_string(&info.path)?;
            SourceMap::from_reader(content.as_bytes()).ok()
        } else {
            None
        };

        self.parse_react_native_stack(stack_trace, sourcemap.as_ref())
    }

    /// Parse a React Native stack trace.
    fn parse_react_native_stack(
        &self,
        stack_trace: &str,
        sourcemap: Option<&SourceMap>,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // React Native stack frame formats:
        // JS: "    at myFunction (index.bundle:1:2345)"
        // Hermes: "    at myFunction (address at index.android.bundle:1:2345)"
        // Native Android: "    at com.example.MyClass.method(MyClass.java:42)"
        // Native iOS: "0   MyApp    0x00000001 myFunction + 123"

        // Note: File paths can contain colons (URLs), so we match greedily
        let js_frame_re = Regex::new(
            r"^\s*at\s+(?:(.+?)\s+)?\(?(?:address at\s+)?(.+):(\d+):(\d+)\)?"
        ).unwrap();
        let native_android_re = Regex::new(
            r"^\s*at\s+([a-zA-Z0-9_.]+)\.([a-zA-Z0-9_<>]+)\(([^:]+):(\d+)\)"
        ).unwrap();
        let native_ios_re = Regex::new(
            r"^\d+\s+(\S+)\s+0x[0-9a-f]+\s+(.+)\s+\+\s+\d+"
        ).unwrap();

        let mut frames = Vec::new();
        let mut symbolicated_count = 0;

        for line in stack_trace.lines() {
            let line_trimmed = line.trim();
            if line_trimmed.is_empty() {
                continue;
            }

            // Try JS/Hermes frame
            if let Some(caps) = js_frame_re.captures(line_trimmed) {
                let function = caps.get(1).map(|m| m.as_str());
                let file = caps.get(2).map(|m| m.as_str());
                let line_num: u32 = caps
                    .get(3)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0);
                let col_num: u32 = caps
                    .get(4)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0);

                // Try to symbolicate with source map
                if let Some(sm) = sourcemap {
                    let line_0 = if line_num > 0 { line_num - 1 } else { 0 };
                    let col_0 = if col_num > 0 { col_num - 1 } else { 0 };

                    if let Some(token) = sm.lookup_token(line_0, col_0) {
                        let orig_function = token
                            .get_name()
                            .map(|s| s.to_string())
                            .or_else(|| function.map(|s| s.to_string()))
                            .unwrap_or_else(|| "<anonymous>".to_string());
                        let orig_file = token.get_source().map(|s| s.to_string());
                        let orig_line = token.get_src_line();
                        let orig_col = token.get_src_col();

                        frames.push(SymbolicatedFrame::symbolicated(
                            line.to_string(),
                            orig_function,
                            orig_file,
                            Some(orig_line + 1),
                            Some(orig_col + 1),
                        ));
                        symbolicated_count += 1;
                        continue;
                    }
                }

                // No source map or token not found - preserve original file path
                frames.push(SymbolicatedFrame {
                    raw: line.to_string(),
                    function: function.map(|s| s.to_string()),
                    file: file.map(|s| s.to_string()),
                    line: Some(line_num),
                    column: Some(col_num),
                    symbolicated: false,
                });
                continue;
            }

            // Try native Android frame
            if let Some(caps) = native_android_re.captures(line_trimmed) {
                let class = &caps[1];
                let method = &caps[2];
                let file = caps.get(3).map(|m| m.as_str().to_string());
                let line_num: Option<u32> = caps.get(4).and_then(|m| m.as_str().parse().ok());

                frames.push(SymbolicatedFrame {
                    raw: line.to_string(),
                    function: Some(format!("{}.{}", class, method)),
                    file,
                    line: line_num,
                    column: None,
                    symbolicated: true, // Native frames are usually not obfuscated
                });
                symbolicated_count += 1;
                continue;
            }

            // Try native iOS frame
            if let Some(caps) = native_ios_re.captures(line_trimmed) {
                let _binary = &caps[1];
                let symbol = &caps[2];

                frames.push(SymbolicatedFrame {
                    raw: line.to_string(),
                    function: Some(symbol.to_string()),
                    file: None,
                    line: None,
                    column: None,
                    symbolicated: true,
                });
                symbolicated_count += 1;
                continue;
            }

            // Other lines
            frames.push(SymbolicatedFrame::raw(line.to_string()));
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
    fn test_parse_js_frame() {
        let js_frame_re = Regex::new(
            r"^\s*at\s+(?:(.+?)\s+)?\(?(?:address at\s+)?(.+):(\d+):(\d+)\)?"
        ).unwrap();

        let frame = "    at myFunction (index.bundle:1:2345)";
        let caps = js_frame_re.captures(frame).unwrap();

        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("myFunction"));
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("index.bundle"));
        assert_eq!(caps.get(3).map(|m| m.as_str()), Some("1"));
        assert_eq!(caps.get(4).map(|m| m.as_str()), Some("2345"));
    }

    #[test]
    fn test_parse_js_frame_with_url() {
        let js_frame_re = Regex::new(
            r"^\s*at\s+(?:(.+?)\s+)?\(?(?:address at\s+)?(.+):(\d+):(\d+)\)?"
        ).unwrap();

        let frame = "    at myFunction (http://localhost:8081/index.bundle:1:2345)";
        let caps = js_frame_re.captures(frame).unwrap();

        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("myFunction"));
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("http://localhost:8081/index.bundle"));
        assert_eq!(caps.get(3).map(|m| m.as_str()), Some("1"));
        assert_eq!(caps.get(4).map(|m| m.as_str()), Some("2345"));
    }
}
