//! Framework detection for reducing false positives.
//!
//! Detects common web frameworks to adjust scanning behavior and reduce
//! false positives from legitimate framework code using eval(), dynamic includes, etc.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Known web frameworks with their detection patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Framework {
    WordPress,
    Laravel,
    Symfony,
    Drupal,
    Composer,
    Unknown,
}

impl Framework {
    /// Get a human-readable name for the framework.
    pub fn name(&self) -> &'static str {
        match self {
            Framework::WordPress => "WordPress",
            Framework::Laravel => "Laravel",
            Framework::Symfony => "Symfony",
            Framework::Drupal => "Drupal",
            Framework::Composer => "Composer",
            Framework::Unknown => "Unknown",
        }
    }

    /// Check if this framework typically uses eval() legitimately.
    pub fn uses_eval_legitimately(&self) -> bool {
        matches!(
            self,
            Framework::WordPress | Framework::Drupal | Framework::Composer
        )
    }

    /// Check if this framework uses dynamic includes legitimately.
    pub fn uses_dynamic_includes(&self) -> bool {
        matches!(
            self,
            Framework::WordPress
                | Framework::Laravel
                | Framework::Symfony
                | Framework::Drupal
                | Framework::Composer
        )
    }
}

/// Framework detection with caching.
pub struct FrameworkDetector {
    /// Cache of detected frameworks by directory path.
    cache: RwLock<HashMap<PathBuf, Framework>>,
}

impl Default for FrameworkDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkDetector {
    /// Create a new framework detector.
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Detect framework from a file path by examining parent directories.
    pub fn detect_from_path(&self, path: &Path) -> Option<Framework> {
        // Check cache first
        if let Some(parent) = path.parent() {
            if let Ok(cache) = self.cache.read() {
                // Check for cached result in any parent directory
                let mut check_path = parent.to_path_buf();
                loop {
                    if let Some(framework) = cache.get(&check_path) {
                        return Some(*framework);
                    }
                    if !check_path.pop() {
                        break;
                    }
                }
            }
        }

        // Not in cache, detect and cache
        let framework = self.detect_framework_uncached(path);

        if let Some(framework) = framework {
            if let Some(root) = self.find_framework_root(path, framework) {
                if let Ok(mut cache) = self.cache.write() {
                    cache.insert(root, framework);
                }
            }
        }

        framework
    }

    /// Detect framework without using cache.
    fn detect_framework_uncached(&self, path: &Path) -> Option<Framework> {
        let mut current = path.parent()?;

        // Walk up the directory tree looking for framework markers
        for _ in 0..10 {
            // Limit search depth
            if let Some(framework) = self.check_directory_for_framework(current) {
                return Some(framework);
            }

            current = current.parent()?;
        }

        None
    }

    /// Check a single directory for framework markers.
    fn check_directory_for_framework(&self, dir: &Path) -> Option<Framework> {
        // WordPress detection
        if dir.join("wp-config.php").exists()
            || dir.join("wp-includes").is_dir()
            || dir.join("wp-content").is_dir()
        {
            return Some(Framework::WordPress);
        }

        // Laravel detection
        if dir.join("artisan").exists()
            && dir.join("app").is_dir()
            && dir.join("bootstrap").is_dir()
        {
            return Some(Framework::Laravel);
        }

        // Symfony detection
        if dir.join("symfony.lock").exists()
            || (dir.join("bin/console").exists() && dir.join("config/bundles.php").exists())
        {
            return Some(Framework::Symfony);
        }

        // Drupal detection
        if dir.join("core/lib/Drupal.php").exists()
            || (dir.join("sites").is_dir() && dir.join("modules").is_dir())
        {
            return Some(Framework::Drupal);
        }

        // Generic Composer project
        if dir.join("composer.json").exists() && dir.join("vendor").is_dir() {
            return Some(Framework::Composer);
        }

        None
    }

    /// Find the root directory of the detected framework.
    fn find_framework_root(&self, path: &Path, framework: Framework) -> Option<PathBuf> {
        let mut current = path.parent()?;

        for _ in 0..10 {
            if self.check_directory_for_framework(current) == Some(framework) {
                return Some(current.to_path_buf());
            }
            current = current.parent()?;
        }

        None
    }

    /// Check if a path is within a vendor directory.
    pub fn is_vendor_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        path_str.contains("/vendor/")
            || path_str.contains("/node_modules/")
            || path_str.contains("/bower_components/")
    }

    /// Check if a path is within a WordPress core or plugin directory.
    pub fn is_wordpress_core_or_plugin(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        path_str.contains("/wp-includes/")
            || path_str.contains("/wp-admin/")
            || path_str.contains("/wp-content/plugins/")
            || path_str.contains("/wp-content/themes/")
    }

    /// Check if a path appears to be in a cache or compiled directory.
    pub fn is_cache_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        path_str.contains("/cache/")
            || path_str.contains("/var/cache/")
            || path_str.contains("/storage/framework/")
            || path_str.contains("/bootstrap/cache/")
    }

    /// Clear the detection cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_is_vendor_path() {
        assert!(FrameworkDetector::is_vendor_path(Path::new(
            "/var/www/html/vendor/monolog/monolog/src/Handler.php"
        )));
        assert!(FrameworkDetector::is_vendor_path(Path::new(
            "/app/node_modules/lodash/index.js"
        )));
        assert!(!FrameworkDetector::is_vendor_path(Path::new(
            "/var/www/html/app/Controller.php"
        )));
    }

    #[test]
    fn test_is_wordpress_core_or_plugin() {
        assert!(FrameworkDetector::is_wordpress_core_or_plugin(Path::new(
            "/var/www/html/wp-includes/functions.php"
        )));
        assert!(FrameworkDetector::is_wordpress_core_or_plugin(Path::new(
            "/var/www/html/wp-content/plugins/akismet/akismet.php"
        )));
        assert!(!FrameworkDetector::is_wordpress_core_or_plugin(Path::new(
            "/var/www/html/custom.php"
        )));
    }

    #[test]
    fn test_is_cache_path() {
        assert!(FrameworkDetector::is_cache_path(Path::new(
            "/var/www/html/storage/framework/cache/data.php"
        )));
        assert!(FrameworkDetector::is_cache_path(Path::new(
            "/app/bootstrap/cache/packages.php"
        )));
        assert!(!FrameworkDetector::is_cache_path(Path::new(
            "/var/www/html/app/Controller.php"
        )));
    }

    #[test]
    fn test_detect_wordpress() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let wp_dir = temp_dir.path();

        // Create WordPress markers
        fs::create_dir_all(wp_dir.join("wp-includes"))?;
        fs::create_dir_all(wp_dir.join("wp-content"))?;
        fs::write(wp_dir.join("wp-config.php"), "<?php // config")?;

        let detector = FrameworkDetector::new();
        let test_file = wp_dir.join("wp-content/themes/theme/functions.php");
        fs::create_dir_all(test_file.parent().unwrap())?;
        fs::write(&test_file, "<?php // theme")?;

        let framework = detector.detect_from_path(&test_file);
        assert_eq!(framework, Some(Framework::WordPress));

        Ok(())
    }

    #[test]
    fn test_detect_laravel() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let laravel_dir = temp_dir.path();

        // Create Laravel markers
        fs::create_dir_all(laravel_dir.join("app"))?;
        fs::create_dir_all(laravel_dir.join("bootstrap"))?;
        fs::write(laravel_dir.join("artisan"), "#!/usr/bin/env php")?;

        let detector = FrameworkDetector::new();
        let test_file = laravel_dir.join("app/Http/Controllers/Controller.php");
        fs::create_dir_all(test_file.parent().unwrap())?;
        fs::write(&test_file, "<?php // controller")?;

        let framework = detector.detect_from_path(&test_file);
        assert_eq!(framework, Some(Framework::Laravel));

        Ok(())
    }

    #[test]
    fn test_detect_composer() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let project_dir = temp_dir.path();

        // Create Composer markers
        fs::create_dir_all(project_dir.join("vendor"))?;
        fs::write(
            project_dir.join("composer.json"),
            r#"{"name": "test/project"}"#,
        )?;

        let detector = FrameworkDetector::new();
        let test_file = project_dir.join("vendor/monolog/monolog/src/Logger.php");
        fs::create_dir_all(test_file.parent().unwrap())?;
        fs::write(&test_file, "<?php // logger")?;

        let framework = detector.detect_from_path(&test_file);
        assert_eq!(framework, Some(Framework::Composer));

        Ok(())
    }

    #[test]
    fn test_framework_uses_eval() {
        assert!(Framework::WordPress.uses_eval_legitimately());
        assert!(Framework::Drupal.uses_eval_legitimately());
        assert!(Framework::Composer.uses_eval_legitimately());
        assert!(!Framework::Laravel.uses_eval_legitimately());
        assert!(!Framework::Symfony.uses_eval_legitimately());
    }
}
