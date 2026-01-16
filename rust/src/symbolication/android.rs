//! Android symbolication using ProGuard/R8 mapping files.
//!
//! Parses ProGuard mapping.txt files and uses them to deobfuscate
//! Android stack traces. Supports the full R8/ProGuard line range format
//! including original line number mappings for inlined methods.
//!
//! # ProGuard Mapping Format
//!
//! ```text
//! original.ClassName -> obfuscated.name:
//!     returnType methodName(params) -> obfuscatedMethod
//!     startLine:endLine:returnType methodName(params) -> obfuscatedMethod
//!     startLine:endLine:returnType methodName(params):origStart:origEnd -> obfuscatedMethod
//!     startLine:endLine:returnType methodName(params):origStart -> obfuscatedMethod
//! ```
//!
//! The `:origStart:origEnd` suffix indicates the original source line range,
//! which differs from the obfuscated line range when methods are inlined.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};

use regex::Regex;

use super::{
    MappingStore, SymbolicatedFrame, SymbolicatedStack, SymbolicationContext, SymbolicationError,
};

/// A single line range mapping entry.
///
/// Each entry maps an obfuscated line range to an original method and line range.
/// Multiple entries can exist for the same obfuscated method name when methods
/// are inlined or overloaded.
#[derive(Debug, Clone)]
struct LineRangeEntry {
    /// Obfuscated line range start
    obf_start: u32,
    /// Obfuscated line range end
    obf_end: u32,
    /// Original line range start
    orig_start: u32,
    /// Original line range end
    orig_end: u32,
    /// Original method name for this line range
    method_name: String,
}

/// Parsed ProGuard mapping entry for a class.
#[derive(Debug, Clone)]
struct ClassMapping {
    /// Original class name
    original: String,
    /// Obfuscated class name
    #[allow(dead_code)]
    obfuscated: String,
    /// Line range mappings indexed by obfuscated method name.
    /// Each method can have multiple line ranges (for inlined/overloaded methods).
    method_line_ranges: HashMap<String, Vec<LineRangeEntry>>,
    /// Methods without line info (obfuscated -> original name)
    methods_no_lines: HashMap<String, String>,
    /// Field mappings (obfuscated -> original)
    #[allow(dead_code)]
    fields: HashMap<String, String>,
}

/// Parsed ProGuard mapping file.
#[derive(Debug)]
struct ProguardMapping {
    /// Class mappings (obfuscated name -> mapping)
    classes: HashMap<String, ClassMapping>,
}

impl ProguardMapping {
    /// Parse a ProGuard mapping file.
    ///
    /// Handles the full R8/ProGuard format including:
    /// - `startLine:endLine:returnType method(params) -> obfuscated`
    /// - `startLine:endLine:returnType method(params):origStart -> obfuscated`
    /// - `startLine:endLine:returnType method(params):origStart:origEnd -> obfuscated`
    fn parse<R: BufRead>(reader: R) -> Result<Self, SymbolicationError> {
        let mut classes = HashMap::new();
        let mut current_class: Option<ClassMapping> = None;

        // Regex patterns
        let class_re = Regex::new(r"^(\S+)\s+->\s+(\S+):$").unwrap();

        // Method with line numbers and optional original line range
        // Format: startLine:endLine:returnType methodName(params):origStart:origEnd -> obfuscated
        //     or: startLine:endLine:returnType methodName(params):origStart -> obfuscated
        //     or: startLine:endLine:returnType methodName(params) -> obfuscated
        let method_re = Regex::new(
            r"^\s+(\d+):(\d+):(\S+)\s+(\S+)\(([^)]*)\)(?::(\d+)(?::(\d+))?)?\s+->\s+(\S+)$"
        ).unwrap();

        // Method without line numbers
        let method_no_line_re = Regex::new(
            r"^\s+(\S+)\s+([^\s(]+)\(([^)]*)\)\s+->\s+(\S+)$"
        ).unwrap();

        let field_re = Regex::new(r"^\s+(\S+)\s+(\S+)\s+->\s+(\S+)$").unwrap();

        for line in reader.lines() {
            let line = line.map_err(|e| SymbolicationError::ParseError(e.to_string()))?;

            // Skip comments and empty lines
            if line.trim().is_empty() || line.trim().starts_with('#') {
                continue;
            }

            // Class mapping
            if let Some(caps) = class_re.captures(&line) {
                // Save previous class
                if let Some(class) = current_class.take() {
                    classes.insert(class.obfuscated.clone(), class);
                }

                current_class = Some(ClassMapping {
                    original: caps[1].to_string(),
                    obfuscated: caps[2].to_string(),
                    method_line_ranges: HashMap::new(),
                    methods_no_lines: HashMap::new(),
                    fields: HashMap::new(),
                });
                continue;
            }

            // Method or field mapping (only if we have a current class)
            if let Some(ref mut class) = current_class {
                // Method with line numbers
                if let Some(caps) = method_re.captures(&line) {
                    let obf_start: u32 = caps[1].parse().unwrap_or(0);
                    let obf_end: u32 = caps[2].parse().unwrap_or(0);
                    let _return_type = &caps[3];
                    let method_name = caps[4].to_string();
                    let _params = &caps[5];
                    // Original line start (group 6) - if present
                    let orig_start: u32 = caps.get(6)
                        .and_then(|m| m.as_str().parse().ok())
                        .unwrap_or(obf_start);
                    // Original line end (group 7) - if present
                    let orig_end: u32 = caps.get(7)
                        .and_then(|m| m.as_str().parse().ok())
                        .unwrap_or(orig_start + (obf_end - obf_start));
                    let obfuscated_name = caps[8].to_string();

                    let entry = LineRangeEntry {
                        obf_start,
                        obf_end,
                        orig_start,
                        orig_end,
                        method_name,
                    };

                    class.method_line_ranges
                        .entry(obfuscated_name)
                        .or_insert_with(Vec::new)
                        .push(entry);
                    continue;
                }

                // Method without line numbers
                if let Some(caps) = method_no_line_re.captures(&line) {
                    let _return_type = &caps[1];
                    let method_name = caps[2].to_string();
                    let _params = &caps[3];
                    let obfuscated_name = caps[4].to_string();

                    // Only store if we don't already have line range info for this method
                    if !class.method_line_ranges.contains_key(&obfuscated_name) {
                        class.methods_no_lines.entry(obfuscated_name)
                            .or_insert(method_name);
                    }
                    continue;
                }

                // Field mapping
                if let Some(caps) = field_re.captures(&line) {
                    let _field_type = &caps[1];
                    let original_name = caps[2].to_string();
                    let obfuscated_name = caps[3].to_string();

                    class.fields.insert(obfuscated_name, original_name);
                }
            }
        }

        // Save last class
        if let Some(class) = current_class {
            classes.insert(class.obfuscated.clone(), class);
        }

        Ok(Self { classes })
    }

    /// Deobfuscate a class name.
    #[allow(dead_code)]
    fn deobfuscate_class(&self, obfuscated: &str) -> Option<&str> {
        self.classes.get(obfuscated).map(|c| c.original.as_str())
    }

    /// Deobfuscate a method name (without line number context).
    #[allow(dead_code)]
    fn deobfuscate_method(&self, class: &str, method: &str) -> Option<&str> {
        let class_mapping = self.classes.get(class)?;

        // First check methods without line info
        if let Some(name) = class_mapping.methods_no_lines.get(method) {
            return Some(name.as_str());
        }

        // Then check line range entries (return first match)
        if let Some(entries) = class_mapping.method_line_ranges.get(method) {
            if let Some(entry) = entries.first() {
                return Some(entry.method_name.as_str());
            }
        }

        None
    }

    /// Deobfuscate a full stack frame.
    ///
    /// Returns (original_class, original_method, original_line).
    /// Preserves the original line number if no mapping is found.
    fn deobfuscate_frame(
        &self,
        class: &str,
        method: &str,
        line: Option<u32>,
    ) -> Option<(String, String, Option<u32>)> {
        let class_mapping = self.classes.get(class)?;
        let original_class = &class_mapping.original;

        // Try to find method and line mapping
        if let Some(line_num) = line {
            // Check line range entries for this obfuscated method
            if let Some(entries) = class_mapping.method_line_ranges.get(method) {
                for entry in entries {
                    if line_num >= entry.obf_start && line_num <= entry.obf_end {
                        // Found matching line range - calculate original line
                        let offset = line_num - entry.obf_start;
                        let orig_line = entry.orig_start + offset;
                        return Some((
                            original_class.clone(),
                            entry.method_name.clone(),
                            Some(orig_line),
                        ));
                    }
                }
            }
        }

        // No line range match - try to get method name without line info
        let original_method = class_mapping.methods_no_lines.get(method)
            .map(|s| s.as_str())
            .or_else(|| {
                // Fallback: use first line range entry's method name if available
                class_mapping.method_line_ranges.get(method)
                    .and_then(|entries| entries.first())
                    .map(|e| e.method_name.as_str())
            })
            .unwrap_or(method);

        // IMPORTANT: Preserve original line number when method mapping exists
        // but line range doesn't match
        Some((original_class.clone(), original_method.to_string(), line))
    }
}

/// Android stack trace symbolicator.
pub struct AndroidSymbolicator<'a> {
    store: &'a MappingStore,
}

impl<'a> AndroidSymbolicator<'a> {
    /// Create a new Android symbolicator.
    pub fn new(store: &'a MappingStore) -> Self {
        Self { store }
    }

    /// Symbolicate an Android stack trace.
    pub fn symbolicate(
        &self,
        stack_trace: &str,
        context: &SymbolicationContext,
    ) -> Result<SymbolicatedStack, SymbolicationError> {
        // Load mapping file
        let mapping_info = self
            .store
            .get_with_fallback(
                &context.platform,
                context.app_id.as_deref().unwrap_or("unknown"),
                context.version.as_deref().unwrap_or("unknown"),
            )
            .ok_or_else(|| SymbolicationError::MappingNotFound {
                platform: "android".to_string(),
                app_id: context.app_id.clone().unwrap_or_default(),
                version: context.version.clone().unwrap_or_default(),
            })?;

        let file = fs::File::open(&mapping_info.path)?;
        let reader = BufReader::new(file);
        let mapping = ProguardMapping::parse(reader)?;

        // Parse and symbolicate each frame
        let mut frames = Vec::new();
        let mut symbolicated_count = 0;

        // Regex for Android stack frames
        // Examples:
        //   at com.example.a.b(Unknown Source:12)
        //   at a.b.c.d(SourceFile:34)
        let frame_re = Regex::new(
            r"^\s*at\s+([a-zA-Z0-9_.]+)\.([a-zA-Z0-9_<>]+)\(([^:)]+)?:?(\d+)?\)"
        ).unwrap();

        for line in stack_trace.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(caps) = frame_re.captures(line) {
                let class = &caps[1];
                let method = &caps[2];
                let _source = caps.get(3).map(|m| m.as_str());
                let line_num: Option<u32> = caps.get(4).and_then(|m| m.as_str().parse().ok());

                if let Some((orig_class, orig_method, orig_line)) =
                    mapping.deobfuscate_frame(class, method, line_num)
                {
                    // Extract source file from original class name
                    let source_file = orig_class
                        .rsplit('.')
                        .next()
                        .map(|s| format!("{}.java", s));

                    frames.push(SymbolicatedFrame::symbolicated(
                        line.to_string(),
                        format!("{}.{}", orig_class, orig_method),
                        source_file,
                        orig_line,
                        None,
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
    use std::io::Cursor;

    #[test]
    fn test_parse_proguard_mapping() {
        let mapping_content = r#"
# This is a comment
com.example.MyClass -> a.a:
    void myMethod() -> a
    int myField -> b
com.example.OtherClass -> a.b:
    1:10:void doSomething(java.lang.String) -> c
"#;

        let reader = Cursor::new(mapping_content);
        let mapping = ProguardMapping::parse(reader).unwrap();

        assert_eq!(
            mapping.deobfuscate_class("a.a"),
            Some("com.example.MyClass")
        );
        assert_eq!(
            mapping.deobfuscate_class("a.b"),
            Some("com.example.OtherClass")
        );
        assert_eq!(
            mapping.deobfuscate_method("a.a", "a"),
            Some("myMethod")
        );
    }

    #[test]
    fn test_parse_r8_format_with_original_line_ranges() {
        // R8 format with :origStart:origEnd suffix
        let mapping_content = r#"
com.example.Inlined -> a.a:
    1:5:void inlinedMethod():100:104 -> a
    6:10:void anotherMethod():200:204 -> a
"#;

        let reader = Cursor::new(mapping_content);
        let mapping = ProguardMapping::parse(reader).unwrap();

        // Line 3 in obfuscated maps to line 102 in original (100 + offset 2)
        let result = mapping.deobfuscate_frame("a.a", "a", Some(3));
        assert!(result.is_some());
        let (class, method, line) = result.unwrap();
        assert_eq!(class, "com.example.Inlined");
        assert_eq!(method, "inlinedMethod");
        assert_eq!(line, Some(102));

        // Line 8 in obfuscated maps to line 202 in original (200 + offset 2)
        let result = mapping.deobfuscate_frame("a.a", "a", Some(8));
        assert!(result.is_some());
        let (class, method, line) = result.unwrap();
        assert_eq!(class, "com.example.Inlined");
        assert_eq!(method, "anotherMethod");
        assert_eq!(line, Some(202));
    }

    #[test]
    fn test_parse_r8_format_with_single_original_line() {
        // R8 format with just :origStart (no origEnd)
        let mapping_content = r#"
com.example.MyClass -> a.a:
    1:3:void singleLine():50 -> b
"#;

        let reader = Cursor::new(mapping_content);
        let mapping = ProguardMapping::parse(reader).unwrap();

        // Line 2 maps to 51 (50 + offset 1)
        let result = mapping.deobfuscate_frame("a.a", "b", Some(2));
        assert!(result.is_some());
        let (_, method, line) = result.unwrap();
        assert_eq!(method, "singleLine");
        assert_eq!(line, Some(51));
    }

    #[test]
    fn test_overloaded_methods_different_line_ranges() {
        // Multiple methods with same obfuscated name but different line ranges
        let mapping_content = r#"
com.example.Overloads -> a.a:
    1:5:void process(int):10:14 -> a
    6:10:void process(java.lang.String):20:24 -> a
    11:15:void helper():30:34 -> a
"#;

        let reader = Cursor::new(mapping_content);
        let mapping = ProguardMapping::parse(reader).unwrap();

        // Line 3 -> process(int) at line 12
        let result = mapping.deobfuscate_frame("a.a", "a", Some(3));
        let (_, method, line) = result.unwrap();
        assert_eq!(method, "process");
        assert_eq!(line, Some(12));

        // Line 8 -> process(String) at line 22
        let result = mapping.deobfuscate_frame("a.a", "a", Some(8));
        let (_, method, line) = result.unwrap();
        assert_eq!(method, "process");
        assert_eq!(line, Some(22));

        // Line 13 -> helper at line 32
        let result = mapping.deobfuscate_frame("a.a", "a", Some(13));
        let (_, method, line) = result.unwrap();
        assert_eq!(method, "helper");
        assert_eq!(line, Some(32));
    }

    #[test]
    fn test_preserve_line_number_when_method_mapping_missing() {
        let mapping_content = r#"
com.example.MyClass -> a.a:
    void knownMethod() -> a
"#;

        let reader = Cursor::new(mapping_content);
        let mapping = ProguardMapping::parse(reader).unwrap();

        // Unknown method 'b' with line 42 - should preserve the line number
        let result = mapping.deobfuscate_frame("a.a", "b", Some(42));
        assert!(result.is_some());
        let (class, method, line) = result.unwrap();
        assert_eq!(class, "com.example.MyClass");
        assert_eq!(method, "b"); // Unknown method name preserved
        assert_eq!(line, Some(42)); // Line number preserved!
    }

    #[test]
    fn test_preserve_line_number_when_line_range_not_matched() {
        let mapping_content = r#"
com.example.MyClass -> a.a:
    1:10:void myMethod():100:109 -> a
"#;

        let reader = Cursor::new(mapping_content);
        let mapping = ProguardMapping::parse(reader).unwrap();

        // Line 50 is outside the mapped range 1-10, should preserve original line
        let result = mapping.deobfuscate_frame("a.a", "a", Some(50));
        assert!(result.is_some());
        let (class, method, line) = result.unwrap();
        assert_eq!(class, "com.example.MyClass");
        assert_eq!(method, "myMethod"); // Method name still resolved
        assert_eq!(line, Some(50)); // Line number preserved since no range matched
    }
}
