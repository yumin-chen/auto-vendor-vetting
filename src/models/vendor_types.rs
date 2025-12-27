//! Vendor management types and structures
//! 
//! This module defines types for dependency vendoring operations,
//! including vendor information, verification reports, and strategies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use super::dependency_graph::*;

/// Vendor operation information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VendorInfo {
    /// Path to vendor directory
    pub vendor_path: PathBuf,
    /// Total number of packages vendored
    pub total_packages: usize,
    /// Cryptographic digest of vendor directory
    pub vendor_digest: String,
    /// Whether vendor is ready for offline builds
    pub offline_ready: bool,
    /// Vendoring operation metadata
    pub metadata: VendorMetadata,
    /// Package-specific information
    pub packages: HashMap<String, VendorPackageInfo>,
}

/// Vendor operation metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VendorMetadata {
    /// Operation timestamp
    pub timestamp: String,
    /// Tool versions used
    pub tool_versions: HashMap<String, String>,
    /// Vendoring strategy used
    pub strategy: VendorStrategy,
    /// Whether operation was in offline mode
    pub offline_mode: bool,
    /// Total size of vendor directory in bytes
    pub total_size_bytes: u64,
    /// Checksums file path
    pub checksums_file: PathBuf,
    /// Cargo config file path
    pub cargo_config_file: PathBuf,
}

/// Information about a specific vendored package
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VendorPackageInfo {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package source
    pub source: PackageSource,
    /// Package checksum
    pub checksum: String,
    /// Path to vendored package
    pub path: PathBuf,
    /// Size of vendored package in bytes
    pub size_bytes: u64,
    /// Whether package was successfully verified
    pub verified: bool,
    /// Verification timestamp
    pub verified_at: Option<String>,
}

/// Vendor verification report
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationReport {
    /// Overall verification result
    pub result: VerificationResult,
    /// Vendor directory structure validation
    pub structure_valid: bool,
    /// Checksum mismatches found
    pub checksum_mismatches: Vec<ChecksumMismatch>,
    /// Missing dependencies
    pub missing_dependencies: Vec<String>,
    /// Cargo config validation
    pub config_valid: bool,
    /// Whether epoch is still valid
    pub epoch_valid: bool,
    /// Verification timestamp
    pub verified_at: String,
    /// Verification duration in milliseconds
    pub verification_duration_ms: u64,
    /// Additional verification details
    pub details: HashMap<String, serde_json::Value>,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationResult {
    /// All checks passed
    Success,
    /// Some checks failed but are recoverable
    Warning,
    /// Critical verification failures
    Failed,
    /// Verification not completed
    Incomplete,
}

/// Checksum mismatch information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChecksumMismatch {
    /// Package name
    pub package_name: String,
    /// Expected checksum
    pub expected_checksum: String,
    /// Actual checksum found
    pub actual_checksum: String,
    /// Severity of mismatch
    pub severity: ErrorSeverity,
    /// Additional details
    pub details: Option<String>,
}

/// Vendor strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VendorStrategy {
    /// Vendoring mode
    pub mode: VendorMode,
    /// Storage configuration
    pub storage: VendorStorage,
    /// Verification settings
    pub verification: VendorVerification,
}

/// Vendoring mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VendorMode {
    /// Vendor all dependencies
    Full,
    /// Vendor only TCS dependencies
    TcsOnly,
    /// Don't vendor anything (just validate checksums)
    None,
}

/// Vendor storage configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum VendorStorage {
    /// Local directory storage
    Local { 
        /// Directory path
        path: PathBuf 
    },
    /// Git submodule storage
    GitSubmodule { 
        /// Submodule path
        path: PathBuf 
    },
    /// Separate Git repository
    SeparateRepo { 
        /// Repository URL
        url: String 
    },
    /// Artifact registry
    ArtifactRegistry { 
        /// Registry URL
        url: String 
    },
}

/// Vendor verification configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VendorVerification {
    /// Verify checksums match lockfile
    pub verify_checksums: bool,
    /// Scan vendored source for malware
    pub malware_scan: bool,
    /// Compare vendored to fresh download
    pub compare_fresh: bool,
    /// Verify Git dependencies exactly
    pub verify_git_deps: bool,
    /// Verify local dependencies exist
    pub verify_local_deps: bool,
}

/// Vendor snapshot for epoch tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VendorSnapshot {
    /// Unique snapshot identifier
    pub id: String,
    /// Associated epoch ID
    pub epoch_id: String,
    /// Storage path
    pub storage_path: PathBuf,
    /// Total packages in snapshot
    pub total_packages: usize,
    /// Total size in bytes
    pub total_size_bytes: u64,
    /// Checksums file path
    pub checksums_file: PathBuf,
    /// Snapshot creation timestamp
    pub created_at: String,
    /// Last verification timestamp
    pub verified_at: Option<String>,
    /// Snapshot metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Cargo configuration for vendor operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoVendorConfig {
    /// Source replacement configuration
    pub source_replacements: HashMap<String, CargoSourceReplacement>,
    /// Net retry configuration
    pub net_retry: u32,
    /// Git timeout configuration
    pub git_timeout: u64,
    /// Offline mode flag
    pub offline: bool,
}

/// Source replacement for Cargo
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoSourceReplacement {
    /// Registry name to replace
    pub registry: String,
    /// Replacement type
    pub replace_with: String,
    /// Replacement value
    pub value: String,
}

/// Error severity for vendor operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorSeverity {
    /// Critical error that invalidates epoch
    Critical,
    /// High priority error
    High,
    /// Medium priority error
    Medium,
    /// Low priority warning
    Low,
}

impl VendorInfo {
    /// Create new vendor info
    pub fn new(vendor_path: PathBuf) -> Self {
        Self {
            vendor_path,
            total_packages: 0,
            vendor_digest: String::new(),
            offline_ready: false,
            metadata: VendorMetadata::default(),
            packages: HashMap::new(),
        }
    }
    
    /// Add package information
    pub fn add_package(&mut self, package_info: VendorPackageInfo) {
        self.total_packages += 1;
        self.packages.insert(package_info.name.clone(), package_info);
    }
    
    /// Get package information by name
    pub fn get_package(&self, name: &str) -> Option<&VendorPackageInfo> {
        self.packages.get(name)
    }
    
    /// Check if all packages are verified
    pub fn all_packages_verified(&self) -> bool {
        self.packages.values().all(|p| p.verified)
    }
    
    /// Get total vendor directory size
    pub fn total_size_bytes(&self) -> u64 {
        self.packages.values().map(|p| p.size_bytes).sum()
    }
}

impl Default for VendorMetadata {
    fn default() -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool_versions: HashMap::new(),
            strategy: VendorStrategy::default(),
            offline_mode: false,
            total_size_bytes: 0,
            checksums_file: PathBuf::from("checksums.txt"),
            cargo_config_file: PathBuf::from(".cargo/config.toml"),
        }
    }
}

impl VerificationReport {
    /// Create new verification report
    pub fn new() -> Self {
        Self {
            result: VerificationResult::Incomplete,
            structure_valid: false,
            checksum_mismatches: Vec::new(),
            missing_dependencies: Vec::new(),
            config_valid: false,
            epoch_valid: false,
            verified_at: chrono::Utc::now().to_rfc3339(),
            verification_duration_ms: 0,
            details: HashMap::new(),
        }
    }
    
    /// Add checksum mismatch
    pub fn add_checksum_mismatch(&mut self, mismatch: ChecksumMismatch) {
        self.checksum_mismatches.push(mismatch);
    }
    
    /// Add missing dependency
    pub fn add_missing_dependency(&mut self, dependency: String) {
        self.missing_dependencies.push(dependency);
    }
    
    /// Check if verification passed
    pub fn is_success(&self) -> bool {
        matches!(self.result, VerificationResult::Success)
    }
    
    /// Check if there are critical issues
    pub fn has_critical_issues(&self) -> bool {
        !self.checksum_mismatches.is_empty() ||
        !self.missing_dependencies.is_empty() ||
        !self.structure_valid ||
        !self.config_valid
    }
    
    /// Determine verification result based on findings
    pub fn determine_result(&mut self) {
        self.result = if self.has_critical_issues() {
            VerificationResult::Failed
        } else if self.checksum_mismatches.iter().any(|m| matches!(m.severity, ErrorSeverity::High)) {
            VerificationResult::Warning
        } else {
            VerificationResult::Success
        };
    }
}

impl ChecksumMismatch {
    /// Create new checksum mismatch
    pub fn new(
        package_name: String,
        expected_checksum: String,
        actual_checksum: String,
    ) -> Self {
        Self {
            package_name,
            expected_checksum,
            actual_checksum,
            severity: ErrorSeverity::Critical, // Default to critical
            details: None,
        }
    }
    
    /// Set severity
    pub fn with_severity(mut self, severity: ErrorSeverity) -> Self {
        self.severity = severity;
        self
    }
    
    /// Add details
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
}

impl Default for VendorStrategy {
    fn default() -> Self {
        Self {
            mode: VendorMode::Full,
            storage: VendorStorage::Local { 
                path: PathBuf::from("vendor") 
            },
            verification: VendorVerification::default(),
        }
    }
}

impl Default for VendorVerification {
    fn default() -> Self {
        Self {
            verify_checksums: true,
            malware_scan: false,
            compare_fresh: false,
            verify_git_deps: true,
            verify_local_deps: true,
        }
    }
}

impl VendorPackageInfo {
    /// Create new vendor package info
    pub fn new(
        name: String,
        version: String,
        source: PackageSource,
        checksum: String,
        path: PathBuf,
    ) -> Self {
        Self {
            name,
            version,
            source,
            checksum,
            path,
            size_bytes: 0,
            verified: false,
            verified_at: None,
        }
    }
    
    /// Mark package as verified
    pub fn mark_verified(&mut self) {
        self.verified = true;
        self.verified_at = Some(chrono::Utc::now().to_rfc3339());
    }
    
    /// Set package size
    pub fn with_size(mut self, size_bytes: u64) -> Self {
        self.size_bytes = size_bytes;
        self
    }
}

impl VendorSnapshot {
    /// Create new vendor snapshot
    pub fn new(epoch_id: String, storage_path: PathBuf) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            epoch_id,
            storage_path,
            total_packages: 0,
            total_size_bytes: 0,
            checksums_file: PathBuf::from("checksums.txt"),
            created_at: chrono::Utc::now().to_rfc3339(),
            verified_at: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Mark snapshot as verified
    pub fn mark_verified(&mut self) {
        self.verified_at = Some(chrono::Utc::now().to_rfc3339());
    }
    
    /// Check if snapshot is verified
    pub fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }
}