//! Comprehensive error handling for the Rust Ecosystem Adapter
//! 
//! This module defines structured error types with stable error codes,
//! actionable guidance, and context-specific information.

use std::{collections::HashMap, path::PathBuf, time::Duration};
use thiserror::Error;

/// Result type alias for the adapter
pub type Result<T> = std::result::Result<T, AdapterError>;

/// Error severity levels for categorizing impact
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Critical errors that invalidate epochs (e.g., checksum mismatches)
    Critical,
    /// High priority errors (e.g., TCS dependency issues)
    High,
    /// Medium priority errors (e.g., Mechanical dependency issues)
    Medium,
    /// Low priority warnings (e.g., configuration issues)
    Low,
}

/// Comprehensive error type for the Rust Ecosystem Adapter
#[derive(Error, Debug)]
pub enum AdapterError {
    /// Tool execution errors
    #[error("Tool not found: {tool}")]
    ToolNotFound { 
        tool: String, 
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Tool execution failed: {tool} (exit code: {exit_code})")]
    ToolExecutionFailed { 
        tool: String, 
        exit_code: i32, 
        stderr: String,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Tool timeout: {tool} after {timeout:?}")]
    ToolTimeout { 
        tool: String, 
        timeout: Duration,
        #[source] 
        source: anyhow::Error 
    },
    
    /// File system errors
    #[error("File not found: {path}")]
    FileNotFound { 
        path: PathBuf, 
        context: String,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Permission denied: {path} for operation '{operation}'")]
    PermissionDenied { 
        path: PathBuf, 
        operation: String,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Invalid path: {path} - {reason}")]
    InvalidPath { 
        path: String, 
        reason: String,
        #[source] 
        source: anyhow::Error 
    },
    
    /// Parsing errors
    #[error("Cargo.lock parse error at line {line}: {error}")]
    CargoLockParseError { 
        file: PathBuf, 
        line: usize, 
        error: String,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Cargo.toml parse error: {error}")]
    CargoTomlParseError { 
        file: PathBuf, 
        error: String,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Metadata parse error in field '{field}': {error}")]
    MetadataParseError { 
        field: String, 
        value: String,
        #[source] 
        source: anyhow::Error 
    },
    
    /// Network errors (should be prevented in offline mode)
    #[error("Network timeout during operation: {operation}")]
    NetworkTimeout { 
        operation: String,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Registry unavailable: {url}")]
    RegistryUnavailable { 
        url: String,
        #[source] 
        source: anyhow::Error 
    },
    
    /// Configuration errors
    #[error("Configuration invalid in field '{field}': {reason}")]
    ConfigurationInvalid { 
        field: String, 
        value: String, 
        reason: String,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Schema validation failed")]
    SchemaValidationFailed { 
        errors: Vec<String>,
        #[source] 
        source: anyhow::Error 
    },
    
    /// Integrity errors
    #[error("Checksum mismatch for package '{package}': expected {expected}, got {actual}")]
    ChecksumMismatch { 
        package: String, 
        expected: String, 
        actual: String,
        severity: ErrorSeverity,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Vendor verification failed: {reason}")]
    VendorVerificationFailed { 
        reason: String, 
        affected_packages: Vec<String>,
        #[source] 
        source: anyhow::Error 
    },
    
    #[error("Epoch invalidated: {epoch_id} - {reason}")]
    EpochInvalidated { 
        epoch_id: String, 
        reason: String,
        #[source] 
        source: anyhow::Error 
    },
    
    /// General errors
    #[error("Internal error: {message}")]
    Internal { 
        message: String,
        #[source] 
        source: anyhow::Error 
    },
}

impl AdapterError {
    /// Get the error severity
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::ChecksumMismatch { severity, .. } => severity.clone(),
            Self::EpochInvalidated { .. } => ErrorSeverity::Critical,
            Self::ToolNotFound { .. } => ErrorSeverity::High,
            Self::VendorVerificationFailed { .. } => ErrorSeverity::High,
            Self::ConfigurationInvalid { .. } => ErrorSeverity::Medium,
            Self::SchemaValidationFailed { .. } => ErrorSeverity::Medium,
            Self::CargoLockParseError { .. } => ErrorSeverity::High,
            Self::ToolExecutionFailed { .. } => ErrorSeverity::High,
            Self::ToolTimeout { .. } => ErrorSeverity::High,
            Self::NetworkTimeout { .. } => ErrorSeverity::Medium,
            Self::RegistryUnavailable { .. } => ErrorSeverity::Medium,
            _ => ErrorSeverity::Low,
        }
    }
    
    /// Get stable error code for programmatic handling
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ToolNotFound { .. } => "TOOL_NOT_FOUND",
            Self::ToolExecutionFailed { .. } => "TOOL_EXECUTION_FAILED",
            Self::ToolTimeout { .. } => "TOOL_TIMEOUT",
            Self::FileNotFound { .. } => "FILE_NOT_FOUND",
            Self::PermissionDenied { .. } => "PERMISSION_DENIED",
            Self::InvalidPath { .. } => "INVALID_PATH",
            Self::CargoLockParseError { .. } => "CARGO_LOCK_PARSE_ERROR",
            Self::CargoTomlParseError { .. } => "CARGO_TOML_PARSE_ERROR",
            Self::MetadataParseError { .. } => "METADATA_PARSE_ERROR",
            Self::NetworkTimeout { .. } => "NETWORK_TIMEOUT",
            Self::RegistryUnavailable { .. } => "REGISTRY_UNAVAILABLE",
            Self::ConfigurationInvalid { .. } => "CONFIGURATION_INVALID",
            Self::SchemaValidationFailed { .. } => "SCHEMA_VALIDATION_FAILED",
            Self::ChecksumMismatch { .. } => "CHECKSUM_MISMATCH",
            Self::VendorVerificationFailed { .. } => "VENDOR_VERIFICATION_FAILED",
            Self::EpochInvalidated { .. } => "EPOCH_INVALIDATED",
            Self::Internal { .. } => "INTERNAL_ERROR",
        }
    }
    
    /// Get actionable guidance for error recovery
    pub fn actionable_guidance(&self) -> Vec<String> {
        match self {
            Self::ToolNotFound { tool, .. } => vec![
                format!("Install {} with: cargo install {}", tool, tool),
                "Ensure the tool is in your PATH".to_string(),
                format!("Verify {} is compatible with your Rust version", tool),
            ],
            Self::FileNotFound { path, context, .. } => vec![
                format!("Check if the file exists: {}", path.display()),
                format!("Verify file permissions for {}", context),
                "Ensure the project directory is correct".to_string(),
            ],
            Self::PermissionDenied { path, operation, .. } => vec![
                format!("Check permissions for: {}", path.display()),
                format!("Try running with appropriate privileges for: {}", operation),
                "Consider using a different directory".to_string(),
            ],
            Self::CargoLockParseError { file, line, .. } => vec![
                format!("Check Cargo.lock syntax at line {} in {}", line, file.display()),
                "Try running 'cargo generate-lockfile' to regenerate".to_string(),
                "Ensure Cargo.lock is not corrupted".to_string(),
            ],
            Self::ChecksumMismatch { package, expected, actual, .. } => vec![
                format!("Potential supply chain attack detected for package: {}", package),
                format!("Expected checksum: {}", expected),
                format!("Actual checksum: {}", actual),
                "Do NOT update vendored copy. Investigate immediately.".to_string(),
                "Consider re-vendoring from a trusted network".to_string(),
            ],
            Self::NetworkTimeout { operation, .. } => vec![
                format!("Check network connectivity for operation: {}", operation),
                "Try increasing timeout in configuration".to_string(),
                "Consider using offline mode for reliable operation".to_string(),
            ],
            Self::ConfigurationInvalid { field, value, reason, .. } => vec![
                format!("Fix configuration field '{}': {}", field, reason),
                format!("Current invalid value: {}", value),
                "Refer to configuration documentation for valid values".to_string(),
            ],
            _ => vec![
                "Check error details for specific guidance".to_string(),
                "Refer to documentation for troubleshooting".to_string(),
            ],
        }
    }
    
    /// Get error context information
    pub fn context(&self) -> HashMap<String, String> {
        let mut context = HashMap::new();
        context.insert("error_code".to_string(), self.error_code().to_string());
        context.insert("severity".to_string(), format!("{:?}", self.severity()));
        
        match self {
            Self::ToolNotFound { tool, .. } => {
                context.insert("tool".to_string(), tool.clone());
            },
            Self::FileNotFound { path, context: ctx, .. } => {
                context.insert("path".to_string(), path.display().to_string());
                context.insert("context".to_string(), ctx.clone());
            },
            Self::CargoLockParseError { file, line, error, .. } => {
                context.insert("file".to_string(), file.display().to_string());
                context.insert("line".to_string(), line.to_string());
                context.insert("parse_error".to_string(), error.clone());
            },
            Self::ChecksumMismatch { package, expected, actual, .. } => {
                context.insert("package".to_string(), package.clone());
                context.insert("expected_checksum".to_string(), expected.clone());
                context.insert("actual_checksum".to_string(), actual.clone());
            },
            _ => {}
        }
        
        context
    }
}

/// Convenience constructors for common error types
impl AdapterError {
    pub fn tool_not_found(tool: &str) -> Self {
        Self::ToolNotFound {
            tool: tool.to_string(),
            source: anyhow::anyhow!("Tool '{}' not found in PATH", tool),
        }
    }
    
    pub fn file_not_found(path: &PathBuf, context: &str) -> Self {
        Self::FileNotFound {
            path: path.clone(),
            context: context.to_string(),
            source: anyhow::anyhow!("File not found: {}", path.display()),
        }
    }
    
    pub fn permission_denied(path: &PathBuf, operation: &str) -> Self {
        Self::PermissionDenied {
            path: path.clone(),
            operation: operation.to_string(),
            source: anyhow::anyhow!("Permission denied for {}", operation),
        }
    }
    
    pub fn cargo_lock_parse_error(file: &PathBuf, line: usize, error: &str) -> Self {
        Self::CargoLockParseError {
            file: file.clone(),
            line,
            error: error.to_string(),
            source: anyhow::anyhow!("Parse error at line {}: {}", line, error),
        }
    }
    
    pub fn checksum_mismatch(package: &str, expected: &str, actual: &str) -> Self {
        Self::ChecksumMismatch {
            package: package.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
            severity: ErrorSeverity::Critical,
            source: anyhow::anyhow!("Checksum mismatch detected"),
        }
    }
}