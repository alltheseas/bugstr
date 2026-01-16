//! Mapping file storage and management.
//!
//! Manages mapping files for different platforms and versions.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use semver::Version;

use super::{Platform, SymbolicationError};

/// Key for looking up mapping files.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MappingKey {
    pub platform: Platform,
    pub app_id: String,
    pub version: String,
}

/// Information about a loaded mapping file.
#[derive(Debug, Clone)]
pub struct MappingInfo {
    pub path: PathBuf,
    pub platform: Platform,
    pub app_id: String,
    pub version: String,
    pub loaded_at: std::time::SystemTime,
}

/// Storage for mapping files.
///
/// Organizes mapping files by platform/app/version and provides
/// lookup functionality for symbolicators.
pub struct MappingStore {
    /// Root directory for mapping files
    root: PathBuf,
    /// Cached mapping file paths
    mappings: HashMap<MappingKey, MappingInfo>,
}

impl MappingStore {
    /// Create a new mapping store at the given root directory.
    ///
    /// Directory structure:
    /// ```text
    /// root/
    ///   android/
    ///     com.example.app/
    ///       1.0.0/
    ///         mapping.txt
    ///   electron/
    ///     my-app/
    ///       1.0.0/
    ///         main.js.map
    ///         renderer.js.map
    ///   flutter/
    ///     com.example.app/
    ///       1.0.0/
    ///         app.android-arm64.symbols
    ///   ...
    /// ```
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            mappings: HashMap::new(),
        }
    }

    /// Get the root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Scan the root directory and load all mapping file metadata.
    pub fn scan(&mut self) -> Result<usize, SymbolicationError> {
        self.mappings.clear();
        let mut count = 0;

        if !self.root.exists() {
            fs::create_dir_all(&self.root)?;
            return Ok(0);
        }

        // Scan platform directories
        for platform_entry in fs::read_dir(&self.root)? {
            let platform_entry = platform_entry?;
            if !platform_entry.file_type()?.is_dir() {
                continue;
            }

            let platform_name = platform_entry.file_name().to_string_lossy().to_string();
            let platform = Platform::from_str(&platform_name);

            // Scan app directories
            for app_entry in fs::read_dir(platform_entry.path())? {
                let app_entry = app_entry?;
                if !app_entry.file_type()?.is_dir() {
                    continue;
                }

                let app_id = app_entry.file_name().to_string_lossy().to_string();

                // Scan version directories
                for version_entry in fs::read_dir(app_entry.path())? {
                    let version_entry = version_entry?;
                    if !version_entry.file_type()?.is_dir() {
                        continue;
                    }

                    let version = version_entry.file_name().to_string_lossy().to_string();
                    let version_path = version_entry.path();

                    // Look for mapping files based on platform
                    if let Some(mapping_path) = self.find_mapping_file(&platform, &version_path) {
                        let key = MappingKey {
                            platform: platform.clone(),
                            app_id: app_id.clone(),
                            version: version.clone(),
                        };

                        let info = MappingInfo {
                            path: mapping_path,
                            platform: platform.clone(),
                            app_id: app_id.clone(),
                            version: version.clone(),
                            loaded_at: std::time::SystemTime::now(),
                        };

                        self.mappings.insert(key, info);
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }

    /// Find the primary mapping file for a platform in a directory.
    fn find_mapping_file(&self, platform: &Platform, dir: &Path) -> Option<PathBuf> {
        let candidates: &[&str] = match platform {
            Platform::Android => &["mapping.txt", "proguard-mapping.txt", "r8-mapping.txt"],
            Platform::Electron => &["main.js.map", "index.js.map", "bundle.js.map"],
            Platform::Flutter => &["app.android-arm64.symbols", "app.ios-arm64.symbols", "app.symbols"],
            Platform::Rust => &["symbols.txt", "debug.dwarf"],
            Platform::Go => &["symbols.txt", "go.sym"],
            Platform::Python => &["source-map.json", "mapping.json"],
            Platform::ReactNative => &["index.android.bundle.map", "index.ios.bundle.map", "main.jsbundle.map"],
            Platform::Unknown(_) => &[],
        };

        for candidate in candidates {
            let path = dir.join(candidate);
            if path.exists() {
                return Some(path);
            }
        }

        // Also check for any .map or .txt files
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    let ext = ext.to_string_lossy().to_lowercase();
                    if ext == "map" || ext == "txt" || ext == "symbols" {
                        return Some(path);
                    }
                }
            }
        }

        None
    }

    /// Get mapping info for a specific app version.
    pub fn get(&self, platform: &Platform, app_id: &str, version: &str) -> Option<&MappingInfo> {
        let key = MappingKey {
            platform: platform.clone(),
            app_id: app_id.to_string(),
            version: version.to_string(),
        };
        self.mappings.get(&key)
    }

    /// Get mapping info, trying version fallbacks.
    ///
    /// Tries exact version first, then looks for closest match using semantic versioning.
    pub fn get_with_fallback(
        &self,
        platform: &Platform,
        app_id: &str,
        version: &str,
    ) -> Option<&MappingInfo> {
        // Try exact match first
        if let Some(info) = self.get(platform, app_id, version) {
            return Some(info);
        }

        // Try to find the newest version for this app using semantic versioning
        self.mappings
            .iter()
            .filter(|(k, _)| k.platform == *platform && k.app_id == app_id)
            .max_by(|(a, _), (b, _)| {
                // Parse as semver, fallback to lexicographic if parsing fails
                match (Version::parse(&a.version), Version::parse(&b.version)) {
                    (Ok(va), Ok(vb)) => va.cmp(&vb),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Greater, // Valid semver > invalid
                    (Err(_), Ok(_)) => std::cmp::Ordering::Less,
                    (Err(_), Err(_)) => a.version.cmp(&b.version), // Fallback to lexicographic
                }
            })
            .map(|(_, v)| v)
    }

    /// Add a mapping file manually.
    pub fn add_mapping(
        &mut self,
        platform: Platform,
        app_id: String,
        version: String,
        path: PathBuf,
    ) {
        let key = MappingKey {
            platform: platform.clone(),
            app_id: app_id.clone(),
            version: version.clone(),
        };

        let info = MappingInfo {
            path,
            platform,
            app_id,
            version,
            loaded_at: std::time::SystemTime::now(),
        };

        self.mappings.insert(key, info);
    }

    /// List all loaded mappings.
    pub fn list(&self) -> impl Iterator<Item = &MappingInfo> {
        self.mappings.values()
    }

    /// Get the expected path for a new mapping file.
    pub fn mapping_path(
        &self,
        platform: &Platform,
        app_id: &str,
        version: &str,
        filename: &str,
    ) -> PathBuf {
        self.root
            .join(platform.as_str())
            .join(app_id)
            .join(version)
            .join(filename)
    }

    /// Save a mapping file to the store.
    pub fn save_mapping(
        &mut self,
        platform: Platform,
        app_id: &str,
        version: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<PathBuf, SymbolicationError> {
        let path = self.mapping_path(&platform, app_id, version, filename);

        // Create parent directories
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&path, content)?;

        // Add to cache
        self.add_mapping(
            platform,
            app_id.to_string(),
            version.to_string(),
            path.clone(),
        );

        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_mapping_store_scan() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Create test structure
        let android_path = root.join("android/com.test.app/1.0.0");
        fs::create_dir_all(&android_path).unwrap();
        fs::write(android_path.join("mapping.txt"), "# test mapping").unwrap();

        let mut store = MappingStore::new(root);
        let count = store.scan().unwrap();

        assert_eq!(count, 1);
        assert!(store.get(&Platform::Android, "com.test.app", "1.0.0").is_some());
    }
}
