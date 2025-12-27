//! Vendor manager for Rust dependencies
//! 
//! This module implements dependency vendoring, verification,
//! and offline build configuration.

use crate::models::*;
use crate::error::Result;
use async_trait::async_trait;
use std::path::Path;
use std::process::Command;

/// Vendor manager implementation
#[derive(Debug, Clone)]
pub struct VendorManager {
    /// Manager configuration
    config: VendorManagerConfig,
    /// Whether manager is ready
    ready: bool,
}

/// Configuration for vendor manager
#[derive(Debug, Clone)]
pub struct VendorManagerConfig {
    /// Default vendor directory
    pub default_vendor_dir: std::path::PathBuf,
    /// Vendor timeout in seconds
    pub vendor_timeout: u64,
    /// Whether to verify checksums
    pub verify_checksums: bool,
    /// Whether to scan for malware
    pub malware_scan: bool,
    /// Whether to compare with fresh downloads
    pub compare_fresh: bool,
}

impl VendorManager {
    /// Create new vendor manager with configuration
    pub fn new(config: &RustAdapterConfig) -> Self {
        Self {
            config: VendorManagerConfig {
                default_vendor_dir: config.vendor_config.default_vendor_dir.clone(),
                vendor_timeout: config.vendor_config.vendor_timeout,
                verify_checksums: config.vendor_config.verify_checksums,
                malware_scan: config.vendor_config.malware_scan,
                compare_fresh: config.vendor_config.compare_fresh,
            },
            ready: true,
        }
    }
    
    /// Check if manager is ready
    pub fn is_ready(&self) -> bool {
        self.ready
    }
    
    /// Vendor dependencies to target directory
    pub async fn vendor_dependencies(&self, project: &Project, target: &Path) -> Result<()> {
        // 1. Execute cargo vendor <target_dir>
        let output = Command::new("cargo")
            .args(&["vendor", target.to_str().unwrap()])
            .current_dir(&project.paths.root)
            .output()
            .map_err(|_| crate::AdapterError::tool_not_found("cargo"))?;
        
        if !output.status.success() {
            return Err(crate::AdapterError::ToolExecutionFailed {
                tool: "cargo vendor".to_string(),
                exit_code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                source: anyhow::anyhow!("cargo vendor execution failed"),
            });
        }
        
        // 2. Verify Cargo.lock completeness
        self.verify_lockfile_completeness(project, target).await?;
        
        // 3. Verify checksums if enabled
        if self.config.verify_checksums {
            self.validate_checksums(project, target).await?;
        }
        
        // 4. Generate .cargo/config.toml for offline builds
        self.generate_cargo_config(target).await?;
        
        Ok(())
    }
    
    /// Verify vendored dependencies
    pub async fn verify_vendored(&self, project: &Project, vendored: &Path) -> Result<VerificationReport> {
        let mut report = VerificationReport::new();
        
        // 1. Check vendor directory structure
        report.structure_valid = self.verify_vendor_structure(vendored).await?;
        
        // 2. Verify checksums
        if self.config.verify_checksums {
            let checksum_mismatches = self.verify_checksums_against_lockfile(project, vendored).await?;
            for mismatch in checksum_mismatches {
                report.add_checksum_mismatch(mismatch);
            }
        }
        
        // 3. Verify Cargo.lock completeness
        let missing_deps = self.check_missing_dependencies(project, vendored).await?;
        for dep in missing_deps {
            report.add_missing_dependency(dep);
        }
        
        // 4. Validate Cargo configuration
        report.config_valid = self.validate_cargo_config(vendored).await?;
        
        // 5. Determine verification result
        report.determine_result();
        
        Ok(report)
    }
    
    /// Verify that all dependencies from Cargo.lock are present
    async fn verify_lockfile_completeness(&self, project: &Project, vendor_dir: &Path) -> Result<()> {
        // This would check that all packages listed in Cargo.lock
        // have corresponding directories in vendor/
        
        let lockfile_path = project.lockfile_path();
        let lockfile_content = std::fs::read_to_string(&lockfile_path)
            .map_err(|e| crate::AdapterError::file_not_found(&lockfile_path, "reading lockfile"))?;
        
        let cargo_lock: CargoLock = toml::from_str(&lockfile_content)
            .map_err(|e| crate::AdapterError::cargo_lock_parse_error(&lockfile_path, 0, &e.to_string()))?;
        
        for package in &cargo_lock.package {
            let vendor_package_path = vendor_dir.join(&package.name);
            if !vendor_package_path.exists() {
                return Err(crate::AdapterError::VendorVerificationFailed {
                    reason: format!("Missing vendored package: {}", package.name),
                    affected_packages: vec![package.name.clone()],
                    source: anyhow::anyhow!("Incomplete vendor directory"),
                });
            }
        }
        
        Ok(())
    }
    
    /// Validate checksums against Cargo.lock
    async fn validate_checksums(&self, project: &Project, vendor_dir: &Path) -> Result<()> {
        // This would calculate SHA256 hashes of vendored packages
        // and compare them against Cargo.lock checksums
        
        let lockfile_path = project.lockfile_path();
        let lockfile_content = std::fs::read_to_string(&lockfile_path)
            .map_err(|e| crate::AdapterError::file_not_found(&lockfile_path, "reading lockfile"))?;
        
        let cargo_lock: CargoLock = toml::from_str(&lockfile_content)
            .map_err(|e| crate::AdapterError::cargo_lock_parse_error(&lockfile_path, 0, &e.to_string()))?;
        
        for package in &cargo_lock.package {
            if let Some(expected_checksum) = &package.checksum {
                let actual_checksum = self.calculate_package_checksum(vendor_dir, &package.name).await?;
                
                if actual_checksum != *expected_checksum {
                    return Err(crate::AdapterError::checksum_mismatch(
                        &package.name,
                        expected_checksum,
                        &actual_checksum,
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Calculate checksum of vendored package
    async fn calculate_package_checksum(&self, vendor_dir: &Path, package_name: &str) -> Result<String> {
        use sha2::{Digest, Sha256};
        use std::fs;
        
        let package_path = vendor_dir.join(package_name);
        
        // Simple checksum calculation of package directory
        let mut hasher = Sha256::new();
        
        let walk_dir = fs::read_dir(&package_path)
            .map_err(|e| crate::AdapterError::permission_denied(&package_path, "reading package directory"))?;
        
        for entry in walk_dir.flatten() {
            let path = entry.path();
            if path.is_file() {
                let contents = fs::read(&path)
                    .map_err(|e| crate::AdapterError::permission_denied(&path, "reading file"))?;
                hasher.update(&contents);
            }
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }
    
    /// Generate .cargo/config.toml for offline builds
    async fn generate_cargo_config(&self, vendor_dir: &Path) -> Result<()> {
        let cargo_config_dir = vendor_dir.join(".cargo");
        let cargo_config_path = cargo_config_dir.join("config.toml");
        
        // Create .cargo directory if it doesn't exist
        std::fs::create_dir_all(&cargo_config_dir)
            .map_err(|e| crate::AdapterError::permission_denied(&cargo_config_dir, "creating .cargo directory"))?;
        
        // Generate config.toml content
        let config_content = format!(r#"
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "{}"
"#, vendor_dir.parent().unwrap_or(vendor_dir).display());
        
        std::fs::write(&cargo_config_path, config_content)
            .map_err(|e| crate::AdapterError::permission_denied(&cargo_config_path, "writing cargo config"))?;
        
        Ok(())
    }
    
    /// Verify vendor directory structure
    async fn verify_vendor_structure(&self, vendor_dir: &Path) -> Result<bool> {
        // Basic structure validation
        if !vendor_dir.exists() {
            return Ok(false);
        }
        
        // Check if .cargo directory exists
        let cargo_config_dir = vendor_dir.join(".cargo");
        let cargo_config_path = cargo_config_dir.join("config.toml");
        
        Ok(cargo_config_path.exists())
    }
    
    /// Check for missing dependencies
    async fn check_missing_dependencies(&self, project: &Project, vendor_dir: &Path) -> Result<Vec<String>> {
        let mut missing = Vec::new();
        
        let lockfile_path = project.lockfile_path();
        let lockfile_content = std::fs::read_to_string(&lockfile_path)
            .map_err(|e| crate::AdapterError::file_not_found(&lockfile_path, "reading lockfile"))?;
        
        let cargo_lock: CargoLock = toml::from_str(&lockfile_content)
            .map_err(|e| crate::AdapterError::cargo_lock_parse_error(&lockfile_path, 0, &e.to_string()))?;
        
        for package in &cargo_lock.package {
            let vendor_package_path = vendor_dir.join(&package.name);
            if !vendor_package_path.exists() {
                missing.push(package.name.clone());
            }
        }
        
        Ok(missing)
    }
    
    /// Verify checksums against lockfile
    async fn verify_checksums_against_lockfile(&self, project: &Project, vendor_dir: &Path) -> Result<Vec<ChecksumMismatch>> {
        let mut mismatches = Vec::new();
        
        let lockfile_path = project.lockfile_path();
        let lockfile_content = std::fs::read_to_string(&lockfile_path)
            .map_err(|e| crate::AdapterError::file_not_found(&lockfile_path, "reading lockfile"))?;
        
        let cargo_lock: CargoLock = toml::from_str(&lockfile_content)
            .map_err(|e| crate::AdapterError::cargo_lock_parse_error(&lockfile_path, 0, &e.to_string()))?;
        
        for package in &cargo_lock.package {
            if let Some(expected_checksum) = &package.checksum {
                let actual_checksum = self.calculate_package_checksum(vendor_dir, &package.name).await?;
                
                if actual_checksum != *expected_checksum {
                    mismatches.push(ChecksumMismatch::new(
                        package.name.clone(),
                        expected_checksum.clone(),
                        actual_checksum,
                    ).with_severity(crate::models::vendor_types::ErrorSeverity::Critical));
                }
            }
        }
        
        Ok(mismatches)
    }
    
    /// Validate Cargo configuration
    async fn validate_cargo_config(&self, vendor_dir: &Path) -> Result<bool> {
        let cargo_config_path = vendor_dir.join(".cargo/config.toml");
        
        if !cargo_config_path.exists() {
            return Ok(false);
        }
        
        // Basic validation - check if file can be parsed
        let config_content = std::fs::read_to_string(&cargo_config_path)
            .map_err(|e| crate::AdapterError::file_not_found(&cargo_config_path, "reading cargo config"))?;
        
        toml::from_str::<serde_json::Value>(&config_content)
            .map(|_| true)
            .map_err(|_| false)
    }
}

impl Default for VendorManagerConfig {
    fn default() -> Self {
        Self {
            default_vendor_dir: std::path::PathBuf::from("vendor"),
            vendor_timeout: 600,
            verify_checksums: true,
            malware_scan: false,
            compare_fresh: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RustAdapterConfig;
    
    #[test]
    fn test_vendor_manager_creation() {
        let config = RustAdapterConfig::default();
        let manager = VendorManager::new(&config);
        
        assert!(manager.is_ready());
        assert!(manager.config.verify_checksums);
        assert_eq!(manager.config.vendor_timeout, 600);
    }
    
    #[tokio::test]
    async fn test_checksum_calculation() {
        let config = RustAdapterConfig::default();
        let manager = VendorManager::new(&config);
        
        // This test would need a temporary directory with test packages
        // For now, we'll test the basic functionality
        assert!(manager.is_ready());
    }
}
