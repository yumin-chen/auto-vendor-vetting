//! Main Rust Ecosystem Adapter implementation
//! 
//! This module implements the EcosystemAdapter trait for Rust projects,
//! providing comprehensive dependency analysis, TCS classification,
//! security auditing, vendoring, SBOM generation, and drift detection.

use crate::models::*;
use crate::config::RustAdapterConfig;
use crate::error::{AdapterError, Result};
use async_trait::async_trait;
use std::path::Path;

/// Main Rust adapter implementing the EcosystemAdapter trait
#[derive(Debug, Clone)]
pub struct RustAdapter {
    /// Adapter configuration
    config: RustAdapterConfig,
    /// Component implementations
    dependency_parser: dependency_parser::DependencyParser,
    tcs_classifier: tcs_classifier::TcsClassifier,
    audit_runner: audit_runner::AuditRunner,
    vendor_manager: vendor_manager::VendorManager,
    sbom_generator: sbom_generator::SbomGenerator,
    drift_detector: drift_detector::DriftDetector,
}

impl RustAdapter {
    /// Create a new Rust adapter with the given configuration
    pub fn new(config: RustAdapterConfig) -> Self {
        Self {
            dependency_parser: dependency_parser::DependencyParser::new(&config),
            tcs_classifier: tcs_classifier::TcsClassifier::new(&config),
            audit_runner: audit_runner::AuditRunner::new(&config),
            vendor_manager: vendor_manager::VendorManager::new(&config),
            sbom_generator: sbom_generator::SbomGenerator::new(&config),
            drift_detector: drift_detector::DriftDetector::new(&config),
            config,
        }
    }
    
    /// Get a reference to the adapter configuration
    pub fn config(&self) -> &RustAdapterConfig {
        &self.config
    }
    
    /// Get a reference to the dependency parser
    pub fn dependency_parser(&self) -> &dependency_parser::DependencyParser {
        &self.dependency_parser
    }
    
    /// Get a reference to the TCS classifier
    pub fn tcs_classifier(&self) -> &tcs_classifier::TcsClassifier {
        &self.tcs_classifier
    }
    
    /// Get a reference to the audit runner
    pub fn audit_runner(&self) -> &audit_runner::AuditRunner {
        &self.audit_runner
    }
    
    /// Get a reference to the vendor manager
    pub fn vendor_manager(&self) -> &vendor_manager::VendorManager {
        &self.vendor_manager
    }
    
    /// Get a reference to the SBOM generator
    pub fn sbom_generator(&self) -> &sbom_generator::SbomGenerator {
        &self.sbom_generator
    }
    
    /// Get a reference to the drift detector
    pub fn drift_detector(&self) -> &drift_detector::DriftDetector {
        &self.drift_detector
    }
}

#[async_trait]
impl EcosystemAdapter for RustAdapter {
    /// Get the ecosystem name
    fn ecosystem_name(&self) -> &str {
        "rust"
    }
    
    /// Get supported lockfile formats
    fn supported_lockfile_formats(&self) -> Vec<&str> {
        vec!["Cargo.lock"]
    }
    
    /// Parse dependencies from a Rust project
    async fn parse_dependencies(&self, project: &Project) -> Result<DependencyGraph> {
        // 1. Parse Cargo.lock as authoritative source
        let mut dependency_graph = self.dependency_parser.parse_dependencies(project).await?;
        
        // 2. Apply TCS classification to all packages
        for package in &mut dependency_graph.root_packages {
            let classification_result = self.tcs_classifier.classify_package(package).await?;
            package.classification = match classification_result.role {
                ToolchainRole::TCS(category) => Classification::TCS {
                    category,
                    rationale: classification_result.signals.iter()
                        .map(|s| s.description())
                        .collect::<Vec<_>>()
                        .join("; "),
                },
                ToolchainRole::Mechanical(category) => Classification::Mechanical { category },
            };
        }
        
        // 3. Validate the graph
        dependency_graph.validate().map_err(|msg| {
            AdapterError::Internal {
                message: format!("Dependency graph validation failed: {}", msg),
                source: anyhow::anyhow!("Graph validation error"),
            }
        })?;
        
        Ok(dependency_graph)
    }
    
    /// Classify dependencies as TCS or Mechanical
    async fn classify_tcs(&self, graph: &DependencyGraph) -> Result<TcsClassification> {
        let mut classification = TcsClassification::new();
        
        // Classify each package in the graph
        for package in &graph.root_packages {
            let package_classification = match &package.classification {
                Classification::TCS { category, .. } => {
                    TcsPackageClassification {
                        package_name: package.name.clone(),
                        package_version: package.version.clone(),
                        tcs_category: Some(category.clone()),
                        rationale: None, // Extract from classification if needed
                        signals: Vec::new(),
                    }
                },
                Classification::Mechanical { category } => {
                    TcsPackageClassification {
                        package_name: package.name.clone(),
                        package_version: package.version.clone(),
                        tcs_category: None,
                        rationale: None,
                        signals: Vec::new(),
                    }
                },
                Classification::Unknown => {
                    TcsPackageClassification {
                        package_name: package.name.clone(),
                        package_version: package.version.clone(),
                        tcs_category: None,
                        rationale: None,
                        signals: Vec::new(),
                    }
                },
            };
            
            classification.add_package_classification(package_classification);
        }
        
        Ok(classification)
    }
    
    /// Detect drift between expected epoch and actual dependency graph
    async fn detect_drift(&self, expected: &Epoch, actual: &DependencyGraph) -> Result<DriftReport> {
        self.drift_detector.detect_drift(expected, actual).await
    }
    
    /// Run comprehensive security audit
    async fn run_audit(&self, project: &Project) -> Result<AuditReport> {
        self.audit_runner.run_comprehensive_audit(project).await
    }
    
    /// Check supply chain security status
    async fn check_supply_chain(&self, project: &Project) -> Result<SupplyChainReport> {
        // 1. Parse dependencies
        let dependency_graph = self.parse_dependencies(project).await?;
        
        // 2. Run audit
        let audit_report = self.run_audit(project).await?;
        
        // 3. Generate supply chain report
        let mut supply_chain_report = SupplyChainReport::new();
        
        // Add audit findings
        for finding in audit_report.findings {
            supply_chain_report.add_audit_finding(finding);
        }
        
        // Add audit proofs
        for package in &dependency_graph.root_packages {
            if let Classification::TCS { .. } = &package.classification {
                if let AuditStatus::Audited { method, auditor, date } = &package.audit_status {
                    let proof = AuditProof {
                        method: method.clone(),
                        auditor: auditor.clone(),
                        date: date.clone(),
                        signature: None,
                        criteria: None,
                        notes: None,
                    };
                    supply_chain_report.add_audit_proof(package.id.to_string(), proof);
                } else {
                    supply_chain_report.add_unaudited_tcs(package.name.clone());
                }
            }
        }
        
        // Determine overall status
        supply_chain_report.determine_status();
        
        Ok(supply_chain_report)
    }
    
    /// Vendor dependencies to target directory
    async fn vendor_dependencies(&self, project: &Project, target: &Path) -> Result<()> {
        self.vendor_manager.vendor_dependencies(project, target).await
    }
    
    /// Verify vendored dependencies
    async fn verify_vendored(&self, project: &Project, vendored: &Path) -> Result<()> {
        let verification_report = self.vendor_manager.verify_vendored(project, vendored).await?;
        
        if !verification_report.epoch_valid {
            return Err(AdapterError::EpochInvalidated {
                epoch_id: "current".to_string(),
                reason: "Vendor verification failed".to_string(),
                source: anyhow::anyhow!("Verification failure"),
            });
        }
        
        Ok(())
    }
    
    /// Generate SBOM in specified format
    async fn generate_sbom(&self, project: &Project) -> Result<Sbom> {
        // 1. Parse dependencies to get current graph
        let dependency_graph = self.parse_dependencies(project).await?;
        
        // 2. Generate SBOM using configured format
        self.sbom_generator.generate_sbom(project, &dependency_graph).await
    }
}

/// Trait for ecosystem adapters (defined elsewhere but included for completeness)
#[async_trait]
pub trait EcosystemAdapter {
    /// Get ecosystem name
    fn ecosystem_name(&self) -> &str;
    
    /// Get supported lockfile formats
    fn supported_lockfile_formats(&self) -> Vec<&str>;
    
    /// Parse dependencies from project
    async fn parse_dependencies(&self, project: &Project) -> Result<DependencyGraph>;
    
    /// Classify dependencies as TCS or Mechanical
    async fn classify_tcs(&self, graph: &DependencyGraph) -> Result<TcsClassification>;
    
    /// Detect drift between expected and actual
    async fn detect_drift(&self, expected: &Epoch, actual: &DependencyGraph) -> Result<DriftReport>;
    
    /// Run security audit
    async fn run_audit(&self, project: &Project) -> Result<AuditReport>;
    
    /// Check supply chain security
    async fn check_supply_chain(&self, project: &Project) -> Result<SupplyChainReport>;
    
    /// Vendor dependencies
    async fn vendor_dependencies(&self, project: &Project, target: &Path) -> Result<()>;
    
    /// Verify vendored dependencies
    async fn verify_vendored(&self, project: &Project, vendored: &Path) -> Result<()>;
    
    /// Generate SBOM
    async fn generate_sbom(&self, project: &Project) -> Result<Sbom>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::project_types::*;
    use std::path::PathBuf;
    
    #[test]
    fn test_ecosystem_name() {
        let config = RustAdapterConfig::default();
        let adapter = RustAdapter::new(config);
        
        assert_eq!(adapter.ecosystem_name(), "rust");
    }
    
    #[test]
    fn test_supported_lockfile_formats() {
        let config = RustAdapterConfig::default();
        let adapter = RustAdapter::new(config);
        
        let formats = adapter.supported_lockfile_formats();
        assert_eq!(formats, vec!["Cargo.lock"]);
    }
    
    #[tokio::test]
    async fn test_adapter_creation() {
        let config = RustAdapterConfig::default();
        let adapter = RustAdapter::new(config);
        
        // Verify all components are created
        assert!(adapter.config().offline_mode == false);
        assert!(adapter.dependency_parser().is_ready());
        assert!(adapter.tcs_classifier().is_ready());
        assert!(adapter.audit_runner().is_ready());
        assert!(adapter.vendor_manager().is_ready());
        assert!(adapter.sbom_generator().is_ready());
        assert!(adapter.drift_detector().is_ready());
    }
}