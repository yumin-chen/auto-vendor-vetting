//! Rust adapter configuration implementation
//! 
//! This module provides the main configuration structure
//! and related types for the Rust ecosystem adapter.

use crate::models::*;
use crate::error::{AdapterError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main configuration structure for Rust Adapter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RustAdapterConfig {
    /// Explicit TCS category overrides
    pub explicit_tcs_overrides: HashMap<String, TcsCategory>,
    /// Custom TCS classification patterns
    pub custom_tcs_patterns: Vec<TcsPattern>,
    /// Tool path configurations
    pub tool_paths: ToolPaths,
    /// Vendoring configuration
    pub vendor_config: VendorConfig,
    /// SBOM generation configuration
    pub sbom_config: SbomConfig,
    /// Audit configuration
    pub audit_config: AuditConfig,
    /// Classification configuration
    pub classification_config: ClassificationConfig,
    /// Logging configuration
    pub logging_config: LoggingConfig,
    /// Offline mode flag
    pub offline_mode: bool,
    /// Schema validation flag
    pub schema_validation: bool,
}

/// Tool path configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolPaths {
    /// Path to cargo executable
    pub cargo: PathBuf,
    /// Path to cargo-audit (optional)
    pub cargo_audit: Option<PathBuf>,
    /// Path to cargo-vet (optional)
    pub cargo_vet: Option<PathBuf>,
    /// Default timeout for tool execution (seconds)
    pub default_timeout: u64,
}

/// Vendoring configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VendorConfig {
    /// Default vendor directory path
    pub default_vendor_dir: PathBuf,
    /// Vendor timeout (seconds)
    pub vendor_timeout: u64,
    /// Whether to verify checksums by default
    pub verify_checksums: bool,
    /// Whether to scan for malware
    pub malware_scan: bool,
    /// Whether to compare with fresh downloads
    pub compare_fresh: bool,
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditConfig {
    /// Audit timeout (seconds)
    pub audit_timeout: u64,
    /// Whether to run cargo-audit
    pub run_cargo_audit: bool,
    /// Whether to run cargo-vet
    pub run_cargo_vet: bool,
    /// Whether to cache audit results
    pub cache_results: bool,
    /// Advisory database path (optional)
    pub advisory_db_path: Option<PathBuf>,
}

/// Classification configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassificationConfig {
    /// Whether to classify proc-macros as TCS
    pub classify_proc_macros: bool,
    /// Whether to classify build dependencies as TCS
    pub classify_build_deps: bool,
    /// Default category for unclassified packages
    pub default_category: MechanicalCategory,
    /// Classification confidence threshold
    pub confidence_threshold: f64,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Whether to enable structured logging
    pub structured: bool,
    /// Log file path (optional)
    pub log_file: Option<PathBuf>,
    /// Whether to include tool execution details
    pub include_tool_details: bool,
}

impl Default for RustAdapterConfig {
    fn default() -> Self {
        Self {
            explicit_tcs_overrides: HashMap::new(),
            custom_tcs_patterns: Vec::new(),
            tool_paths: ToolPaths::default(),
            vendor_config: VendorConfig::default(),
            sbom_config: SbomConfig::default(),
            audit_config: AuditConfig::default(),
            classification_config: ClassificationConfig::default(),
            logging_config: LoggingConfig::default(),
            offline_mode: false,
            schema_validation: true,
        }
    }
}

impl Default for ToolPaths {
    fn default() -> Self {
        Self {
            cargo: PathBuf::from("cargo"),
            cargo_audit: None,
            cargo_vet: None,
            default_timeout: 300, // 5 minutes
        }
    }
}

impl Default for VendorConfig {
    fn default() -> Self {
        Self {
            default_vendor_dir: PathBuf::from("vendor"),
            vendor_timeout: 600, // 10 minutes
            verify_checksums: true,
            malware_scan: false,
            compare_fresh: false,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            audit_timeout: 300, // 5 minutes
            run_cargo_audit: true,
            run_cargo_vet: true,
            cache_results: true,
            advisory_db_path: None,
        }
    }
}

impl Default for ClassificationConfig {
    fn default() -> Self {
        Self {
            classify_proc_macros: true,
            classify_build_deps: false,
            default_category: MechanicalCategory::Other("default".to_string()),
            confidence_threshold: 0.7,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            structured: false,
            log_file: None,
            include_tool_details: false,
        }
    }
}

impl RustAdapterConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let config_content = std::fs::read_to_string(path)
            .map_err(|e| AdapterError::file_not_found(path, "reading config file"))?;
        
        let config: RustAdapterConfig = toml::from_str(&config_content)
            .map_err(|e| AdapterError::ConfigurationInvalid {
                field: "config_file".to_string(),
                value: format!("{:?}", path),
                reason: format!("TOML parsing error: {}", e),
                source: anyhow::anyhow!("TOML parsing failed"),
            })?;
        
        // Validate configuration
        if config.schema_validation {
            config.validate()?;
        }
        
        Ok(config)
    }
    
    /// Load configuration with fallback to defaults
    pub fn load_with_defaults(path: Option<&PathBuf>) -> Result<Self> {
        match path {
            Some(p) => {
                match Self::load_from_file(p) {
                    Ok(config) => Ok(config),
                    Err(e) => {
                        eprintln!("Warning: Invalid config at {:?}: {}, using defaults", p, e);
                        Ok(Self::default())
                    }
                }
            },
            None => Ok(Self::default()),
        }
    }
    
    /// Validate configuration against schema
    pub fn validate(&self) -> Result<()> {
        // Basic validation
        if self.tool_paths.default_timeout == 0 {
            return Err(AdapterError::ConfigurationInvalid {
                field: "tool_paths.default_timeout".to_string(),
                value: self.tool_paths.default_timeout.to_string(),
                reason: "Timeout cannot be zero".to_string(),
                source: anyhow::anyhow!("Invalid timeout"),
            });
        }
        
        if !(0.0..=1.0).contains(&self.classification_config.confidence_threshold) {
            return Err(AdapterError::ConfigurationInvalid {
                field: "classification_config.confidence_threshold".to_string(),
                value: self.classification_config.confidence_threshold.to_string(),
                reason: "Confidence threshold must be between 0.0 and 1.0".to_string(),
                source: anyhow::anyhow!("Invalid confidence threshold"),
            });
        }
        
        // Validate log level
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.logging_config.level.as_str()) {
            return Err(AdapterError::ConfigurationInvalid {
                field: "logging_config.level".to_string(),
                value: self.logging_config.level.clone(),
                reason: format!("Invalid log level. Valid levels: {:?}", valid_log_levels),
                source: anyhow::anyhow!("Invalid log level"),
            });
        }
        
        Ok(())
    }
    
    /// Get effective tool path, checking environment and defaults
    pub fn get_tool_path(&self, tool: &str) -> Option<PathBuf> {
        match tool {
            "cargo" => Some(self.tool_paths.cargo.clone()),
            "cargo-audit" => self.tool_paths.cargo_audit.clone(),
            "cargo-vet" => self.tool_paths.cargo_vet.clone(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    
    #[test]
    fn test_default_config() {
        let config = RustAdapterConfig::default();
        
        assert!(config.offline_mode == false);
        assert!(config.schema_validation == true);
        assert!(config.classification_config.classify_proc_macros);
        assert!(config.audit_config.run_cargo_audit);
        assert!(config.vendor_config.verify_checksums);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = RustAdapterConfig::default();
        
        // Valid config should pass
        assert!(config.validate().is_ok());
        
        // Invalid confidence threshold should fail
        config.classification_config.confidence_threshold = 1.5;
        assert!(config.validate().is_err());
        
        // Zero timeout should fail
        config.classification_config.confidence_threshold = 0.7;
        config.tool_paths.default_timeout = 0;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_tool_path_resolution() {
        let config = RustAdapterConfig::default();
        
        assert_eq!(
            config.get_tool_path("cargo"),
            Some(PathBuf::from("cargo"))
        );
        assert_eq!(config.get_tool_path("nonexistent"), None);
    }
    
    #[test]
    fn test_load_with_defaults() {
        // Test with non-existent file
        let result = RustAdapterConfig::load_with_defaults(Some(&PathBuf::from("nonexistent.toml")));
        assert!(result.is_ok()); // Should fall back to defaults
        
        // Test with None path
        let result = RustAdapterConfig::load_with_defaults(None);
        assert!(result.is_ok()); // Should use defaults
    }
}
