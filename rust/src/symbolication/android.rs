//! Android symbolication using ProGuard/R8 mapping files.
//!
//! Parses ProGuard mapping.txt files and uses them to deobfuscate
//! Android stack traces.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};

use regex::Regex;

use super::{
    MappingStore, SymbolicatedFrame, SymbolicatedStack, SymbolicationContext, SymbolicationError,
};

/// Parsed ProGuard mapping entry for a class.
#[derive(Debug, Clone)]
struct ClassMapping {
    /// Original class name
    original: String,
    /// Obfuscated class name
    obfuscated: String,
    /// Method mappings (obfuscated -> original)
    methods: HashMap<String, MethodMapping>,
    /// Field mappings (obfuscated -> original)
    fields: HashMap<String, String>,
}

/// Parsed ProGuard mapping entry for a method.
#[derive(Debug, Clone)]
struct MethodMapping {
    /// Original method name
    original: String,
    /// Original return type
    return_type: String,
    /// Original parameter types
    parameters: Vec<String>,
    /// Line number mapping (obfuscated -> original)
    line_mapping: Vec<(u32, u32, u32, u32)>, // (start_obf, end_obf, start_orig, end_orig)
}

/// Parsed ProGuard mapping file.
#[derive(Debug)]
struct ProguardMapping {
    /// Class mappings (obfuscated name -> mapping)
    classes: HashMap<String, ClassMapping>,
}

impl ProguardMapping {
    /// Parse a ProGuard mapping file.
    fn parse<R: BufRead>(reader: R) -> Result<Self, SymbolicationError> {
        let mut classes = HashMap::new();
        let mut current_class: Option<ClassMapping> = None;

        // Regex patterns
        let class_re = Regex::new(r"^(\S+)\s+->\s+(\S+):$").unwrap();
        let method_re = Regex::new(
            r"^\s+(\d+):(\d+):(\S+)\s+(\S+)\((.*)\)\s+->\s+(\S+)$"
        ).unwrap();
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
                    methods: HashMap::new(),
                    fields: HashMap::new(),
                });
                continue;
            }

            // Method or field mapping (only if we have a current class)
            if let Some(ref mut class) = current_class {
                // Method with line numbers
                if let Some(caps) = method_re.captures(&line) {
                    let start_line: u32 = caps[1].parse().unwrap_or(0);
                    let end_line: u32 = caps[2].parse().unwrap_or(0);
                    let return_type = caps[3].to_string();
                    let method_name = caps[4].to_string();
                    let params = caps[5].to_string();
                    let obfuscated_name = caps[6].to_string();

                    let parameters: Vec<String> = if params.is_empty() {
                        vec![]
                    } else {
                        params.split(',').map(|s| s.trim().to_string()).collect()
                    };

                    let mapping = class.methods.entry(obfuscated_name).or_insert_with(|| {
                        MethodMapping {
                            original: method_name.clone(),
                            return_type: return_type.clone(),
                            parameters: parameters.clone(),
                            line_mapping: vec![],
                        }
                    });

                    mapping.line_mapping.push((start_line, end_line, start_line, end_line));
                    continue;
                }

                // Method without line numbers
                if let Some(caps) = method_no_line_re.captures(&line) {
                    let return_type = caps[1].to_string();
                    let method_name = caps[2].to_string();
                    let params = caps[3].to_string();
                    let obfuscated_name = caps[4].to_string();

                    let parameters: Vec<String> = if params.is_empty() {
                        vec![]
                    } else {
                        params.split(',').map(|s| s.trim().to_string()).collect()
                    };

                    class.methods.entry(obfuscated_name).or_insert_with(|| {
                        MethodMapping {
                            original: method_name,
                            return_type,
                            parameters,
                            line_mapping: vec![],
                        }
                    });
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
    fn deobfuscate_class(&self, obfuscated: &str) -> Option<&str> {
        self.classes.get(obfuscated).map(|c| c.original.as_str())
    }

    /// Deobfuscate a method name.
    fn deobfuscate_method(&self, class: &str, method: &str) -> Option<&str> {
        self.classes
            .get(class)
            .and_then(|c| c.methods.get(method))
            .map(|m| m.original.as_str())
    }

    /// Deobfuscate a full stack frame.
    fn deobfuscate_frame(&self, class: &str, method: &str, line: Option<u32>) -> Option<(String, String, Option<u32>)> {
        let class_mapping = self.classes.get(class)?;
        let original_class = &class_mapping.original;

        let method_mapping = class_mapping.methods.get(method);
        let original_method = method_mapping
            .map(|m| m.original.as_str())
            .unwrap_or(method);

        // Try to map line number
        let original_line = line.and_then(|l| {
            method_mapping.and_then(|m| {
                for (start_obf, end_obf, start_orig, _end_orig) in &m.line_mapping {
                    if l >= *start_obf && l <= *end_obf {
                        return Some(start_orig + (l - start_obf));
                    }
                }
                Some(l) // Return original if no mapping found
            })
        });

        Some((original_class.clone(), original_method.to_string(), original_line))
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
}
