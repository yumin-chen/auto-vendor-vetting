//! Configuration types for Rust Ecosystem Adapter
//! 
//! This module defines configuration structures for adapter behavior,
//! TCS classification rules, tool paths, and validation schemas.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use super::dependency_graph::*;
use super::cargo_types::*;

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

/// Configuration validation result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigValidationResult {
    /// Whether configuration is valid
    pub is_valid: bool,
    /// Validation errors found
    pub errors: Vec<ConfigValidationError>,
    /// Validation warnings found
    pub warnings: Vec<ConfigValidationWarning>,
}

/// Configuration validation error
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigValidationError {
    /// Field with error
    pub field: String,
    /// Error message
    pub message: String,
    /// Error severity
    pub severity: ConfigErrorSeverity,
}

/// Configuration validation warning
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigValidationWarning {
    /// Field with warning
    pub field: String,
    /// Warning message
    pub message: String,
    /// Suggested fix
    pub suggestion: Option<String>,
}

/// Configuration error severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfigErrorSeverity {
    /// Critical error preventing operation
    Critical,
    /// Error that may cause issues
    Error,
    /// Warning about potential issues
    Warning,
}

/// Configuration schema definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigSchema {
    /// Schema version
    pub version: String,
    /// Schema definitions
    pub definitions: HashMap<String, SchemaDefinition>,
    /// Root schema reference
    pub schema_ref: String,
}

/// Schema definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaDefinition {
    /// Type definition
    pub r#type: String,
    /// Whether field is required
    pub required: Option<bool>,
    /// Default value
    pub default: Option<serde_json::Value>,
    /// Description
    pub description: Option<String>,
    /// Enum values (if applicable)
    pub enum_values: Option<Vec<String>>,
    /// Pattern (for string validation)
    pub pattern: Option<String>,
    /// Minimum value (for numbers)
    pub minimum: Option<f64>,
    /// Maximum value (for numbers)
    pub maximum: Option<f64>,
    /// Minimum length (for strings/arrays)
    pub min_length: Option<usize>,
    /// Maximum length (for strings/arrays)
    pub max_length: Option<usize>,
}

/// Environment variable configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvConfig {
    /// Whether to load from environment variables
    pub enabled: bool,
    /// Environment variable prefix
    pub prefix: String,
    /// Environment variable mappings
    pub mappings: HashMap<String, String>,
}

/// Profile-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileConfig {
    /// Profile name
    pub name: String,
    /// Profile-specific overrides
    pub overrides: RustAdapterConfig,
    /// Profile inheritance
    pub inherits_from: Option<String>,
}

/// Configuration merge result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigMergeResult {
    /// Merged configuration
    pub merged_config: RustAdapterConfig,
    /// Conflicts detected during merge
    pub conflicts: Vec<ConfigConflict>,
    /// Applied defaults
    pub applied_defaults: Vec<String>,
}

/// Configuration conflict
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigConflict {
    /// Field with conflict
    pub field: String,
    /// Base value
    pub base_value: serde_json::Value,
    /// Override value
    pub override_value: serde_json::Value,
    /// Conflict resolution strategy used
    pub resolution: ConflictResolution,
}

/// Conflict resolution strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictResolution {
    /// Override wins
    Override,
    /// Base value wins
    Base,
    /// Combined value
    Combined,
    /// Manual resolution required
    Manual,
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
    pub fn load_from_file(path: &PathBuf) -> crate::Result<Self> {
        let config_content = std::fs::read_to_string(path)
            .map_err(|e| crate::AdapterError::file_not_found(path, "reading config file"))?;
        
        let config: RustAdapterConfig = toml::from_str(&config_content)
            .map_err(|e| crate::AdapterError::ConfigurationInvalid {
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
    pub fn load_with_defaults(path: Option<&PathBuf>) -> crate::Result<Self> {
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
    pub fn validate(&self) -> crate::Result<()> {
        let validation_result = self.validate_detailed();
        
        if !validation_result.is_valid {
            let error_messages: Vec<String> = validation_result.errors
                .iter()
                .map(|e| format!("{}: {}", e.field, e.message))
                .collect();
            
            return Err(crate::AdapterError::ConfigurationInvalid {
                field: "validation".to_string(),
                value: "multiple errors".to_string(),
                reason: error_messages.join("; "),
                source: anyhow::anyhow!("Configuration validation failed"),
            });
        }
        
        // Log warnings
        for warning in &validation_result.warnings {
            eprintln!("Config warning: {} - {}", warning.field, warning.message);
            if let Some(suggestion) = &warning.suggestion {
                eprintln!("  Suggestion: {}", suggestion);
            }
        }
        
        Ok(())
    }
    
    /// Detailed validation with specific errors and warnings
    pub fn validate_detailed(&self) -> ConfigValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        // Validate tool paths
        if !self.tool_paths.cargo.exists() {
            errors.push(ConfigValidationError {
                field: "tool_paths.cargo".to_string(),
                message: "Cargo executable not found".to_string(),
                severity: ConfigErrorSeverity::Critical,
            });
        }
        
        // Validate timeouts
        if self.tool_paths.default_timeout == 0 {
            errors.push(ConfigValidationError {
                field: "tool_paths.default_timeout".to_string(),
                message: "Timeout cannot be zero".to_string(),
                severity: ConfigErrorSeverity::Error,
            });
        }
        
        // Validate classification config
        if !(0.0..=1.0).contains(&self.classification_config.confidence_threshold) {
            errors.push(ConfigValidationError {
                field: "classification_config.confidence_threshold".to_string(),
                message: "Confidence threshold must be between 0.0 and 1.0".to_string(),
                severity: ConfigErrorSeverity::Error,
            });
        }
        
        // Validate logging config
        let valid_log_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_log_levels.contains(&self.logging_config.level.as_str()) {
            errors.push(ConfigValidationError {
                field: "logging_config.level".to_string(),
                message: format!("Invalid log level. Valid values: {:?}", valid_log_levels),
                severity: ConfigErrorSeverity::Error,
            });
        }
        
        // Warnings for optional tools
        if self.audit_config.run_cargo_audit && self.tool_paths.cargo_audit.is_none() {
            warnings.push(ConfigValidationWarning {
                field: "tool_paths.cargo_audit".to_string(),
                message: "cargo-audit is enabled but path not configured".to_string(),
                suggestion: Some("Install cargo-audit with: cargo install cargo-audit".to_string()),
            });
        }
        
        if self.audit_config.run_cargo_vet && self.tool_paths.cargo_vet.is_none() {
            warnings.push(ConfigValidationWarning {
                field: "tool_paths.cargo_vet".to_string(),
                message: "cargo-vet is enabled but path not configured".to_string(),
                suggestion: Some("Install cargo-vet with: cargo install cargo-vet".to_string()),
            });
        }
        
        ConfigValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        }
    }
    
    /// Merge with another configuration
    pub fn merge_with(&self, other: &RustAdapterConfig) -> ConfigMergeResult {
        let mut conflicts = Vec::new();
        let mut applied_defaults = Vec::new();
        
        // This is a simplified merge implementation
        // In a real implementation, you'd need more sophisticated merging logic
        let merged_config = RustAdapterConfig {
            explicit_tcs_overrides: {
                let mut overrides = self.explicit_tcs_overrides.clone();
                for (key, value) in &other.explicit_tcs_overrides {
                    if let Some(existing) = overrides.get(key) {
                        conflicts.push(ConfigConflict {
                            field: format!("explicit_tcs_overrides.{}", key),
                            base_value: serde_json::to_value(existing).unwrap_or_default(),
                            override_value: serde_json::to_value(value).unwrap_or_default(),
                            resolution: ConflictResolution::Override,
                        });
                    }
                    overrides.insert(key.clone(), value.clone());
                }
                overrides
            },
            custom_tcs_patterns: {
                let mut patterns = self.custom_tcs_patterns.clone();
                patterns.extend(other.custom_tcs_patterns.clone());
                patterns
            },
            tool_paths: other.tool_paths.clone(), // Tool paths typically override completely
            vendor_config: other.vendor_config.clone(),
            sbom_config: other.sbom_config.clone(),
            audit_config: other.audit_config.clone(),
            classification_config: other.classification_config.clone(),
            logging_config: other.logging_config.clone(),
            offline_mode: other.offline_mode,
            schema_validation: other.schema_validation,
        };
        
        ConfigMergeResult {
            merged_config,
            conflicts,
            applied_defaults,
        }
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

impl ConfigValidationResult {
    /// Check if validation passed
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty() && 
        !self.errors.iter().any(|e| matches!(e.severity, ConfigErrorSeverity::Critical))
    }
    
    /// Get critical errors
    pub fn critical_errors(&self) -> Vec<&ConfigValidationError> {
        self.errors.iter()
            .filter(|e| matches!(e.severity, ConfigErrorSeverity::Critical))
            .collect()
    }
    
    /// Get non-critical errors
    pub fn non_critical_errors(&self) -> Vec<&ConfigValidationError> {
        self.errors.iter()
            .filter(|e| !matches!(e.severity, ConfigErrorSeverity::Critical))
            .collect()
    }
}
