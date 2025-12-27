//! Drift detector for Rust dependency changes
//! 
//! This module implements drift detection between approved epochs
//! and actual dependency states, with priority-based analysis.

use crate::models::*;
use crate::error::Result;
use async_trait::async_trait;
use std::collections::HashMap;

/// Drift detector implementation
#[derive(Debug, Clone)]
pub struct DriftDetector {
    /// Detector configuration
    config: DriftDetectorConfig,
    /// Whether detector is ready
    ready: bool,
}

/// Configuration for drift detector
#[derive(Debug, Clone)]
pub struct DriftDetectorConfig {
    /// Whether to ignore version updates for Mechanical components
    pub ignore_mechanical_version_updates: bool,
    /// Whether to flag source changes as high risk by default
    pub flag_source_changes_high_risk: bool,
    /// Priority overrides for specific packages
    pub priority_overrides: HashMap<String, Priority>,
    /// Whether to include dev dependencies in drift detection
    pub include_dev_dependencies: bool,
    /// Whether to include build dependencies in drift detection
    pub include_build_dependencies: bool,
}

impl DriftDetector {
    /// Create new drift detector with configuration
    pub fn new(config: &RustAdapterConfig) -> Self {
        Self {
            config: DriftDetectorConfig {
                ignore_mechanical_version_updates: config.classification_config.classify_build_deps,
                flag_source_changes_high_risk: true,
                priority_overrides: HashMap::new(),
                include_dev_dependencies: false,
                include_build_dependencies: true,
            },
            ready: true,
        }
    }
    
    /// Check if detector is ready
    pub fn is_ready(&self) -> bool {
        self.ready
    }
    
    /// Detect drift between expected epoch and actual dependency graph
    pub async fn detect_drift(&self, expected: &Epoch, actual: &DependencyGraph) -> Result<DriftReport> {
        let mut drift_report = DriftReport::new(expected.id.clone());
        
        // 1. Detect additions
        self.detect_additions(expected, actual, &mut drift_report).await?;
        
        // 2. Detect removals
        self.detect_removals(expected, actual, &mut drift_report).await?;
        
        // 3. Detect version changes
        self.detect_version_changes(expected, actual, &mut drift_report).await?;
        
        // 4. Detect source changes
        self.detect_source_changes(expected, actual, &mut drift_report).await?;
        
        // 5. Calculate summary statistics
        drift_report.calculate_summary();
        
        // 6. Assess impact
        drift_report.assess_impact();
        
        Ok(drift_report)
    }
    
    /// Detect added dependencies
    async fn detect_additions(&self, expected: &Epoch, actual: &DependencyGraph, report: &mut DriftReport) -> Result<()> {
        for package in &actual.root_packages {
            // Skip if not included in drift detection
            if !self.should_include_package(package) {
                continue;
            }
            
            // Check if package exists in expected epoch
            if !self.package_exists_in_epoch(expected, &package.name, &package.version) {
                let priority = self.calculate_package_priority(package);
                let drift = DriftItem::new(
                    package.name.clone(),
                    ChangeType::Addition,
                    priority
                ).with_versions(None, Some(package.version.clone()))
                .with_classification(package.classification.clone());
                
                report.add_drift(drift);
            }
        }
        
        Ok(())
    }
    
    /// Detect removed dependencies
    async fn detect_removals(&self, expected: &Epoch, actual: &DependencyGraph, report: &mut DriftReport) -> Result<()> {
        // Get expected packages from epoch
        let expected_packages = self.get_expected_packages(expected).await?;
        
        for (name, version) in expected_packages {
            // Check if package still exists in actual graph
            if actual.find_package(name, version).is_none() {
                let classification = self.get_expected_classification(expected, name).await?;
                let priority = self.calculate_classification_priority(&classification);
                let drift = DriftItem::new(
                    name.clone(),
                    ChangeType::Removal,
                    priority
                ).with_versions(Some(version), None)
                .with_classification(classification);
                
                report.add_drift(drift);
            }
        }
        
        Ok(())
    }
    
    /// Detect version changes
    async fn detect_version_changes(&self, expected: &Epoch, actual: &DependencyGraph, report: &mut DriftReport) -> Result<()> {
        for package in &actual.root_packages {
            // Skip if not included in drift detection
            if !self.should_include_package(package) {
                continue;
            }
            
            // Check if package exists with different version in expected epoch
            if let Some(expected_version) = self.get_package_version_in_epoch(expected, &package.name).await? {
                if expected_version != package.version {
                    // Skip mechanical version updates if configured
                    if self.config.ignore_mechanical_version_updates {
                        if let Classification::Mechanical { .. } = &package.classification {
                            continue;
                        }
                    }
                    
                    let priority = self.calculate_package_priority(package);
                    let drift = DriftItem::new(
                        package.name.clone(),
                        ChangeType::VersionChange,
                        priority
                    ).with_versions(Some(expected_version), Some(package.version.clone()))
                    .with_classification(package.classification.clone());
                    
                    report.add_drift(drift);
                }
            }
        }
        
        Ok(())
    }
    
    /// Detect source changes
    async fn detect_source_changes(&self, expected: &Epoch, actual: &DependencyGraph, report: &mut DriftReport) -> Result<()> {
        for package in &actual.root_packages {
            // Skip if not included in drift detection
            if !self.should_include_package(package) {
                continue;
            }
            
            // Check if package source changed
            if let Some(expected_source) = self.get_package_source_in_epoch(expected, &package.name).await? {
                if expected_source != package.source {
                    let priority = self.calculate_source_change_priority(&package.source, &expected_source);
                    let is_high_risk = self.is_high_risk_source_change(&package.source, &expected_source);
                    let drift = DriftItem::new(
                        package.name.clone(),
                        ChangeType::SourceChange,
                        priority
                    ).with_sources(Some(expected_source), Some(package.source.clone()))
                    .with_classification(package.classification.clone())
                    .as_high_risk_source_change(is_high_risk);
                    
                    report.add_drift(drift);
                }
            }
        }
        
        Ok(())
    }
    
    /// Determine if package should be included in drift detection
    fn should_include_package(&self, package: &PackageNode) -> bool {
        for annotation in &package.annotations {
            if annotation.key == RustAnnotation::keys::DEPENDENCY_KIND {
                if let Some(kind_str) = annotation.value.as_str() {
                    match kind_str {
                        "dev" if !self.config.include_dev_dependencies => return false,
                        "build" if !self.config.include_build_dependencies => return false,
                        _ => {}
                    }
                }
            }
        }
        
        true
    }
    
    /// Check if package exists in expected epoch
    fn package_exists_in_epoch(&self, expected: &Epoch, name: &str, version: &str) -> bool {
        // This would check if package exists in epoch
        // For now, return false (assume no packages in epoch)
        false
    }
    
    /// Get expected packages from epoch
    async fn get_expected_packages(&self, expected: &Epoch) -> Result<HashMap<String, String>> {
        // This would extract package name-version pairs from epoch
        // For now, return empty map
        Ok(HashMap::new())
    }
    
    /// Get expected classification for package
    async fn get_expected_classification(&self, expected: &Epoch, name: &str) -> Result<Classification> {
        // This would get classification from epoch
        // For now, return Unknown
        Ok(Classification::Unknown)
    }
    
    /// Get package version in expected epoch
    async fn get_package_version_in_epoch(&self, expected: &Epoch, name: &str) -> Result<Option<String>> {
        // This would get package version from epoch
        // For now, return None
        Ok(None)
    }
    
    /// Get package source in expected epoch
    async fn get_package_source_in_epoch(&self, expected: &Epoch, name: &str) -> Result<Option<PackageSource>> {
        // This would get package source from epoch
        // For now, return None
        Ok(None)
    }
    
    /// Calculate priority for a package
    fn calculate_package_priority(&self, package: &PackageNode) -> Priority {
        // Check for explicit overrides
        if let Some(priority) = self.config.priority_overrides.get(&package.name) {
            return priority.clone();
        }
        
        // Calculate based on classification
        self.calculate_classification_priority(&package.classification)
    }
    
    /// Calculate priority based on classification
    fn calculate_classification_priority(&self, classification: &Classification) -> Priority {
        match classification {
            Classification::TCS { .. } => Priority::Critical,
            Classification::Mechanical { .. } => Priority::Medium,
            Classification::Unknown => Priority::Low,
        }
    }
    
    /// Calculate priority for source changes
    fn calculate_source_change_priority(&self, actual: &PackageSource, expected: &PackageSource) -> Priority {
        // Registry to Git is high risk
        match (expected, actual) {
            (PackageSource::Registry { .. }, PackageSource::Git { .. }) => Priority::Critical,
            (PackageSource::Git { .. }, PackageSource::Registry { .. }) => Priority::Medium,
            _ => Priority::Low,
        }
    }
    
    /// Check if this is a high-risk source change
    fn is_high_risk_source_change(&self, actual: &PackageSource, expected: &PackageSource) -> bool {
        match (expected, actual) {
            (PackageSource::Registry { .. }, PackageSource::Git { .. }) => true,
            (PackageSource::Local { .. }, PackageSource::Git { .. }) => true,
            _ => false,
        }
    }
}

impl Default for DriftDetectorConfig {
    fn default() -> Self {
        Self {
            ignore_mechanical_version_updates: false,
            flag_source_changes_high_risk: true,
            priority_overrides: HashMap::new(),
            include_dev_dependencies: false,
            include_build_dependencies: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RustAdapterConfig;
    use crate::models::project_types::*;
    use std::path::PathBuf;
    
    #[test]
    fn test_drift_detector_creation() {
        let config = RustAdapterConfig::default();
        let detector = DriftDetector::new(&config);
        
        assert!(detector.is_ready());
        assert!(detector.config.flag_source_changes_high_risk);
    }
    
    #[tokio::test]
    async fn test_addition_detection() {
        let config = RustAdapterConfig::default();
        let detector = DriftDetector::new(&config);
        
        let project = Project::new(
            "test".to_string(),
            "Test Project".to_string(),
            "rust".to_string(),
            PathBuf::from("/test"),
        );
        
        let mut actual_graph = DependencyGraph::new("test".to_string(), "rust".to_string());
        
        let package = PackageNode {
            id: uuid::Uuid::new_v4(),
            name: "new-package".to_string(),
            version: "1.0.0".to_string(),
            source: PackageSource::Registry {
                url: "https://crates.io".to_string(),
                checksum: "test-checksum".to_string(),
            },
            checksum: "test-checksum".to_string(),
            classification: Classification::Mechanical(MechanicalCategory::Other("test".to_string())),
            audit_status: AuditStatus::Unaudited,
            annotations: vec![],
        };
        
        actual_graph.add_package(package);
        
        let expected_epoch = Epoch {
            id: "test-epoch".to_string(),
            project_id: "test".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            metadata: EpochMetadata::default(),
            dependencies: EpochDependencies::default(),
            security: EpochSecurity::default(),
            governance: EpochGovernance::default(),
        };
        
        let result = detector.detect_drift(&expected_epoch, &actual_graph).await.unwrap();
        assert_eq!(result.summary.additions, 1);
        assert_eq!(result.drifts[0].package_name, "new-package");
        assert_eq!(result.drifts[0].change_type, ChangeType::Addition);
    }
    
    #[tokio::test]
    async fn test_high_risk_source_change() {
        let config = RustAdapterConfig::default();
        let detector = DriftDetector::new(&config);
        
        // Test registry to Git change
        let registry_source = PackageSource::Registry {
            url: "https://crates.io".to_string(),
            checksum: "test-checksum".to_string(),
        };
        
        let git_source = PackageSource::Git {
            url: "https://github.com/example/crate.git".to_string(),
            rev: "abc123".to_string(),
            checksum: "git-checksum".to_string(),
        };
        
        let priority = detector.calculate_source_change_priority(&git_source, &registry_source);
        assert_eq!(priority, Priority::Critical);
        
        let is_high_risk = detector.is_high_risk_source_change(&git_source, &registry_source);
        assert!(is_high_risk);
    }
    
    #[tokio::test]
    async fn test_classification_priority() {
        let config = RustAdapterConfig::default();
        let detector = DriftDetector::new(&config);
        
        let tcs_classification = Classification::TCS {
            category: TcsCategory::Cryptography,
            rationale: "Crypto package".to_string(),
        };
        
        let mechanical_classification = Classification::Mechanical(MechanicalCategory::Other("test".to_string()));
        
        let tcs_priority = detector.calculate_classification_priority(&tcs_classification);
        let mechanical_priority = detector.calculate_classification_priority(&mechanical_classification);
        
        assert_eq!(tcs_priority, Priority::Critical);
        assert_eq!(mechanical_priority, Priority::Medium);
    }
}
