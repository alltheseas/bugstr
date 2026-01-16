//! Mapping file storage and management.
//!
//! This module provides [`MappingStore`], a file-system-based storage system for
//! mapping files used during stack trace symbolication. It organizes files in a
//! hierarchical directory structure by platform, application ID, and version.
//!
//! # Directory Structure
//!
//! ```text
//! <root>/
//!   <platform>/           # e.g., "android", "electron", "flutter"
//!     <app_id>/           # e.g., "com.example.app", "my-desktop-app"
//!       <version>/        # e.g., "1.0.0", "2.1.3"
//!         <mapping_file>  # e.g., "mapping.txt", "main.js.map"
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use bugstr::symbolication::{MappingStore, Platform};
//!
//! // Create and scan store
//! let mut store = MappingStore::new("./mappings");
//! let count = store.scan()?;
//! println!("Loaded {} mapping files", count);
//!
//! // Look up a mapping (with version fallback)
//! if let Some(info) = store.get_with_fallback(&Platform::Android, "com.myapp", "1.2.0") {
//!     println!("Found mapping at: {:?}", info.path);
//! }
//!
//! // Save a new mapping file
//! store.save_mapping(
//!     Platform::Android,
//!     "com.myapp",
//!     "1.3.0",
//!     "mapping.txt",
//!     mapping_content.as_bytes(),
//! )?;
//! ```

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

/// Storage and management for symbolication mapping files.
///
/// `MappingStore` provides a file-system-based storage system for mapping files
/// organized by platform, application ID, and version. It supports scanning
/// existing files, looking up mappings with version fallback, and saving new
/// mapping files with path validation.
///
/// # Directory Structure
///
/// Mapping files are organized in a three-level hierarchy:
///
/// ```text
/// <root>/
///   android/
///     com.example.app/
///       1.0.0/
///         mapping.txt          # ProGuard/R8 mapping
///       1.1.0/
///         mapping.txt
///   electron/
///     my-desktop-app/
///       1.0.0/
///         main.js.map          # Source map
///         renderer.js.map
///   flutter/
///     com.example.app/
///       1.0.0/
///         app.android-arm64.symbols
/// ```
///
/// # Thread Safety
///
/// `MappingStore` is **not thread-safe**. For concurrent access, wrap in
/// `Arc<Mutex<MappingStore>>` or use separate instances per thread.
/// The [`scan()`](Self::scan) method clears and rebuilds the internal cache,
/// so concurrent reads during a scan will produce inconsistent results.
///
/// # Security
///
/// The [`save_mapping()`](Self::save_mapping) method validates all path components
/// to prevent directory traversal attacks. It rejects:
/// - Absolute paths
/// - Path components containing `..`
/// - Path components containing path separators (`/` or `\`)
/// - Empty path components
///
/// # Example
///
/// ```rust,ignore
/// use bugstr::symbolication::{MappingStore, Platform};
///
/// // Create store pointing to mappings directory
/// let mut store = MappingStore::new("./mappings");
///
/// // Scan to discover existing mapping files
/// let count = store.scan()?;
/// println!("Found {} mapping files", count);
///
/// // Look up a mapping with version fallback
/// if let Some(info) = store.get_with_fallback(&Platform::Android, "com.myapp", "1.0.0") {
///     println!("Using mapping: {:?}", info.path);
/// }
///
/// // Save a new mapping file
/// store.save_mapping(
///     Platform::Android,
///     "com.myapp",
///     "2.0.0",
///     "mapping.txt",
///     content.as_bytes(),
/// )?;
/// ```
pub struct MappingStore {
    /// Root directory for mapping files.
    root: PathBuf,
    /// In-memory cache of discovered mapping files, keyed by platform/app/version.
    mappings: HashMap<MappingKey, MappingInfo>,
}

impl MappingStore {
    /// Create a new mapping store at the given root directory.
    ///
    /// Creates an empty `MappingStore` instance. The directory does not need
    /// to exist yet; it will be created by [`scan()`](Self::scan) if missing.
    /// Call `scan()` after construction to discover existing mapping files.
    ///
    /// # Arguments
    ///
    /// * `root` - Path to the root directory for mapping files. Can be any type
    ///   implementing `AsRef<Path>` (e.g., `&str`, `String`, `PathBuf`).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bugstr::symbolication::MappingStore;
    ///
    /// let store = MappingStore::new("./mappings");
    /// let store = MappingStore::new(PathBuf::from("/var/lib/bugstr/mappings"));
    /// ```
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            mappings: HashMap::new(),
        }
    }

    /// Get a reference to the root directory path.
    ///
    /// # Returns
    ///
    /// Borrowed reference to the root directory `Path`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Scan the root directory and load all mapping file metadata.
    ///
    /// Recursively walks the directory structure looking for mapping files.
    /// Each discovered mapping is indexed by its platform/app_id/version tuple.
    ///
    /// # Side Effects
    ///
    /// - **Clears** the internal mapping cache before scanning
    /// - **Creates** the root directory if it doesn't exist
    /// - Does **not** load file contents into memory (only paths are cached)
    ///
    /// # Returns
    ///
    /// * `Ok(count)` - Number of mapping files discovered
    /// * `Err(SymbolicationError::IoError)` - Failed to read directory or create root
    ///
    /// # Platform-Specific Files
    ///
    /// The scanner looks for these files by platform:
    /// - **Android**: `mapping.txt`, `proguard-mapping.txt`, `r8-mapping.txt`
    /// - **Electron**: `main.js.map`, `index.js.map`, `bundle.js.map`
    /// - **Flutter**: `app.android-arm64.symbols`, `app.ios-arm64.symbols`, `app.symbols`
    /// - **Rust**: `symbols.txt`, `debug.dwarf`
    /// - **Go**: `symbols.txt`, `go.sym`
    /// - **Python**: `source-map.json`, `mapping.json`
    /// - **React Native**: `index.android.bundle.map`, `index.ios.bundle.map`, `main.jsbundle.map`
    ///
    /// Falls back to any `.map`, `.txt`, or `.symbols` file if primary names not found.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut store = MappingStore::new("./mappings");
    /// match store.scan() {
    ///     Ok(0) => println!("No mapping files found"),
    ///     Ok(n) => println!("Loaded {} mapping files", n),
    ///     Err(e) => eprintln!("Scan failed: {}", e),
    /// }
    /// ```
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

    /// Get mapping info for a specific platform/app/version combination.
    ///
    /// Performs an exact match lookup in the cache. Returns `None` if no mapping
    /// was found for the exact combination. For fallback behavior, use
    /// [`get_with_fallback()`](Self::get_with_fallback).
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform to look up (e.g., `Platform::Android`)
    /// * `app_id` - Application identifier (e.g., `"com.example.app"`)
    /// * `version` - Exact version string (e.g., `"1.0.0"`)
    ///
    /// # Returns
    ///
    /// * `Some(&MappingInfo)` - Mapping found for exact match
    /// * `None` - No mapping for this exact combination
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if let Some(info) = store.get(&Platform::Android, "com.myapp", "1.0.0") {
    ///     let content = std::fs::read_to_string(&info.path)?;
    /// }
    /// ```
    pub fn get(&self, platform: &Platform, app_id: &str, version: &str) -> Option<&MappingInfo> {
        let key = MappingKey {
            platform: platform.clone(),
            app_id: app_id.to_string(),
            version: version.to_string(),
        };
        self.mappings.get(&key)
    }

    /// Get mapping info with version fallback.
    ///
    /// First attempts an exact version match. If not found, returns the mapping
    /// for the **newest available version** of the same app/platform, using
    /// semantic versioning comparison.
    ///
    /// This is useful when crash reports may reference versions that don't have
    /// their own mapping files, but an older or newer mapping may still be useful.
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform to look up
    /// * `app_id` - Application identifier
    /// * `version` - Preferred version (exact match attempted first)
    ///
    /// # Returns
    ///
    /// * `Some(&MappingInfo)` - Mapping found (exact or fallback)
    /// * `None` - No mappings exist for this app/platform at any version
    ///
    /// # Version Comparison
    ///
    /// Uses the [`semver`] crate for version comparison. Non-semver version strings
    /// fall back to lexicographic comparison. Valid semver versions sort higher than
    /// invalid version strings.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // If 1.0.0 exists but 1.0.1 doesn't, returns 1.0.0 mapping
    /// // If only 2.0.0 exists, returns 2.0.0 (newest available)
    /// let info = store.get_with_fallback(&Platform::Android, "com.myapp", "1.0.1");
    /// ```
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

    /// Add a mapping file to the cache manually.
    ///
    /// Registers a mapping file in the internal cache without scanning the filesystem.
    /// Useful for adding mappings after [`save_mapping()`](Self::save_mapping) or for
    /// testing. Does not validate that the file exists.
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform for this mapping
    /// * `app_id` - Application identifier
    /// * `version` - Version string
    /// * `path` - Path to the mapping file
    ///
    /// # Note
    ///
    /// This method takes ownership of the `app_id` and `version` strings.
    /// If a mapping already exists for the same platform/app/version, it is replaced.
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
    ///
    /// Returns an iterator over all [`MappingInfo`] entries in the cache.
    /// Order is not guaranteed (depends on internal `HashMap` iteration).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// for info in store.list() {
    ///     println!("{}/{}/{}: {:?}",
    ///         info.platform.as_str(),
    ///         info.app_id,
    ///         info.version,
    ///         info.path
    ///     );
    /// }
    /// ```
    pub fn list(&self) -> impl Iterator<Item = &MappingInfo> {
        self.mappings.values()
    }

    /// Get the expected filesystem path for a mapping file.
    ///
    /// Constructs the path where a mapping file would be stored based on
    /// the directory layout convention: `<root>/<platform>/<app_id>/<version>/<filename>`.
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform (determines first directory component)
    /// * `app_id` - Application identifier
    /// * `version` - Version string
    /// * `filename` - Mapping file name (e.g., `"mapping.txt"`)
    ///
    /// # Returns
    ///
    /// Constructed `PathBuf`. Does not validate the path components or check
    /// if the file exists.
    ///
    /// # Warning
    ///
    /// This method does **not** validate path components. For safe file writing,
    /// use [`save_mapping()`](Self::save_mapping) which validates all inputs.
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

    /// Validate a path component for safe filesystem usage.
    ///
    /// Ensures the component cannot be used for directory traversal attacks.
    ///
    /// # Errors
    ///
    /// Returns `Err(SymbolicationError::InvalidPath)` if:
    /// - Component is empty
    /// - Component is exactly `"."` or `".."`
    /// - Component contains `..` (parent directory reference)
    /// - Component contains `/` or `\` (path separators)
    /// - Component starts with `/` or `\` (absolute path attempt)
    fn validate_path_component(component: &str, name: &str) -> Result<(), SymbolicationError> {
        if component.is_empty() {
            return Err(SymbolicationError::InvalidPath(format!(
                "{} cannot be empty",
                name
            )));
        }

        if component == "." || component == ".." {
            return Err(SymbolicationError::InvalidPath(format!(
                "{} cannot be '.' or '..'",
                name
            )));
        }

        if component.contains("..") {
            return Err(SymbolicationError::InvalidPath(format!(
                "{} cannot contain '..'",
                name
            )));
        }

        if component.contains('/') || component.contains('\\') {
            return Err(SymbolicationError::InvalidPath(format!(
                "{} cannot contain path separators",
                name
            )));
        }

        Ok(())
    }

    /// Save a mapping file to the store with path validation.
    ///
    /// Writes the mapping file content to the appropriate location in the
    /// directory hierarchy and adds it to the internal cache.
    ///
    /// # Arguments
    ///
    /// * `platform` - Platform for this mapping. `Platform::Unknown` is allowed
    ///   and uses the contained string as the directory name.
    /// * `app_id` - Application identifier (e.g., `"com.example.app"`).
    ///   Used as a directory name; must not contain path separators or `..`.
    /// * `version` - Version string (e.g., `"1.0.0"`).
    ///   Used as a directory name; must not contain path separators or `..`.
    /// * `filename` - Name of the mapping file (e.g., `"mapping.txt"`).
    ///   Must not contain path separators or `..`.
    /// * `content` - Raw bytes to write to the file.
    ///
    /// # Returns
    ///
    /// * `Ok(PathBuf)` - Path where the file was written
    /// * `Err(SymbolicationError::InvalidPath)` - A path component failed validation
    /// * `Err(SymbolicationError::IoError)` - Failed to create directories or write file
    ///
    /// # Security
    ///
    /// All path components are validated to prevent directory traversal attacks:
    /// - Rejects empty components
    /// - Rejects components containing `..`
    /// - Rejects components containing `/` or `\`
    ///
    /// # Side Effects
    ///
    /// - Creates parent directories if they don't exist
    /// - Overwrites existing file at the target path
    /// - Adds mapping to internal cache
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let path = store.save_mapping(
    ///     Platform::Android,
    ///     "com.myapp",
    ///     "1.0.0",
    ///     "mapping.txt",
    ///     mapping_content.as_bytes(),
    /// )?;
    /// println!("Saved mapping to: {:?}", path);
    ///
    /// // These will fail with InvalidPath error:
    /// store.save_mapping(Platform::Android, "../etc", "1.0", "passwd", b"")?;  // Error
    /// store.save_mapping(Platform::Android, "app", "1.0", "/etc/passwd", b"")?; // Error
    /// ```
    pub fn save_mapping(
        &mut self,
        platform: Platform,
        app_id: &str,
        version: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<PathBuf, SymbolicationError> {
        // Validate all path components to prevent directory traversal
        Self::validate_path_component(platform.as_str(), "platform")?;
        Self::validate_path_component(app_id, "app_id")?;
        Self::validate_path_component(version, "version")?;
        Self::validate_path_component(filename, "filename")?;

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

    #[test]
    fn test_validate_path_component_rejects_parent_traversal() {
        assert!(MappingStore::validate_path_component("..", "test").is_err());
        assert!(MappingStore::validate_path_component("../etc", "test").is_err());
        assert!(MappingStore::validate_path_component("foo/../bar", "test").is_err());
    }

    #[test]
    fn test_validate_path_component_rejects_path_separators() {
        assert!(MappingStore::validate_path_component("foo/bar", "test").is_err());
        assert!(MappingStore::validate_path_component("foo\\bar", "test").is_err());
        assert!(MappingStore::validate_path_component("/etc/passwd", "test").is_err());
    }

    #[test]
    fn test_validate_path_component_rejects_empty() {
        assert!(MappingStore::validate_path_component("", "test").is_err());
    }

    #[test]
    fn test_validate_path_component_rejects_dot() {
        assert!(MappingStore::validate_path_component(".", "test").is_err());
    }

    #[test]
    fn test_validate_path_component_allows_valid() {
        assert!(MappingStore::validate_path_component("com.example.app", "test").is_ok());
        assert!(MappingStore::validate_path_component("1.0.0", "test").is_ok());
        assert!(MappingStore::validate_path_component("mapping.txt", "test").is_ok());
        assert!(MappingStore::validate_path_component("my-app_v2", "test").is_ok());
    }

    #[test]
    fn test_save_mapping_validates_paths() {
        let dir = tempdir().unwrap();
        let mut store = MappingStore::new(dir.path());

        // Valid save should succeed
        let result = store.save_mapping(
            Platform::Android,
            "com.test.app",
            "1.0.0",
            "mapping.txt",
            b"# test",
        );
        assert!(result.is_ok());

        // Directory traversal in app_id should fail
        let result = store.save_mapping(
            Platform::Android,
            "../etc",
            "1.0.0",
            "passwd",
            b"malicious",
        );
        assert!(matches!(result, Err(SymbolicationError::InvalidPath(_))));

        // Path separator in filename should fail
        let result = store.save_mapping(
            Platform::Android,
            "com.test.app",
            "1.0.0",
            "/etc/passwd",
            b"malicious",
        );
        assert!(matches!(result, Err(SymbolicationError::InvalidPath(_))));

        // Empty version should fail
        let result = store.save_mapping(
            Platform::Android,
            "com.test.app",
            "",
            "mapping.txt",
            b"test",
        );
        assert!(matches!(result, Err(SymbolicationError::InvalidPath(_))));
    }
}
