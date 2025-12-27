//! SBOM (Software Bill of Materials) generator for Rust projects
//! 
//! This module implements standard SBOM generation in SPDX and CycloneDX formats,
//! ensuring policy neutrality by not including vulnerability scoring.

use crate::models::*;
use crate::error::Result;
use async_trait::async_trait;
use std::path::Path;

/// SBOM generator implementation
#[derive(Debug, Clone)]
pub struct SbomGenerator {
    /// Generator configuration
    config: SbomGeneratorConfig,
    /// Whether generator is ready
    ready: bool,
}

/// Configuration for SBOM generator
#[derive(Debug, Clone)]
pub struct SbomGeneratorConfig {
    /// SBOM format
    pub format: SbomFormat,
    /// Whether to include development dependencies
    pub include_dev_dependencies: bool,
    /// Whether to include build dependencies
    pub include_build_dependencies: bool,
    /// Whether to include license information
    pub include_licenses: bool,
    /// Document author
    pub author: String,
}

impl SbomGenerator {
    /// Create new SBOM generator with configuration
    pub fn new(config: &RustAdapterConfig) -> Self {
        Self {
            config: SbomGeneratorConfig {
                format: config.sbom_config.format.clone(),
                include_dev_dependencies: config.sbom_config.include_dev_dependencies,
                include_build_dependencies: config.sbom_config.include_build_dependencies,
                include_licenses: config.sbom_config.include_licenses,
                author: config.sbom_config.author.clone(),
            },
            ready: true,
        }
    }
    
    /// Check if generator is ready
    pub fn is_ready(&self) -> bool {
        self.ready
    }
    
    /// Generate SBOM in configured format
    pub async fn generate_sbom(&self, project: &Project, dependency_graph: &DependencyGraph) -> Result<Sbom> {
        match self.config.format {
            SbomFormat::SpdxJson => {
                let spdx_doc = self.generate_spdx(project, dependency_graph).await?;
                Ok(Sbom::Spdx(spdx_doc))
            },
            SbomFormat::CycloneDxJson => {
                let cyclonedx_doc = self.generate_cyclonedx(project, dependency_graph).await?;
                Ok(Sbom::CycloneDx(cyclonedx_doc))
            },
        }
    }
    
    /// Generate SPDX 2.3 document
    pub async fn generate_spdx(&self, project: &Project, dependency_graph: &DependencyGraph) -> Result<SpdxDocument> {
        let namespace = format!("https://example.com/{}", project.id);
        let mut spdx_doc = SpdxDocument::new(project.name.clone(), namespace);
        
        // Add packages to SPDX document
        for package in &dependency_graph.root_packages {
            // Skip dev dependencies if not included
            if !self.should_include_package(package) {
                continue;
            }
            
            let spdx_package = self.create_spdx_package(project, package).await?;
            spdx_doc.add_package(spdx_package);
        }
        
        // Add relationships between packages
        self.add_spdx_relationships(&mut spdx_doc, dependency_graph);
        
        Ok(spdx_doc)
    }
    
    /// Generate CycloneDX 1.4 document
    pub async fn generate_cyclonedx(&self, project: &Project, dependency_graph: &DependencyGraph) -> Result<CycloneDxDocument> {
        let mut cyclonedx_doc = CycloneDxDocument::new();
        
        // Add components to CycloneDX document
        for package in &dependency_graph.root_packages {
            // Skip dev dependencies if not included
            if !self.should_include_package(package) {
                continue;
            }
            
            let cyclonedx_component = self.create_cyclonedx_component(project, package).await?;
            cyclonedx_doc.add_component(cyclonedx_component);
        }
        
        // Add dependencies
        self.add_cyclonedx_dependencies(&mut cyclonedx_doc, dependency_graph);
        
        Ok(cyclonedx_doc)
    }
    
    /// Determine if package should be included in SBOM
    fn should_include_package(&self, package: &PackageNode) -> bool {
        // Check annotations for dependency kind
        for annotation in &package.annotations {
            if annotation.key == RustAnnotation::keys::DEPENDENCY_KIND {
                if let Some(kind_str) = annotation.value.as_str() {
                    if kind_str == "dev" && !self.config.include_dev_dependencies {
                        return false;
                    }
                    if kind_str == "build" && !self.config.include_build_dependencies {
                        return false;
                    }
                }
            }
        }
        
        true
    }
    
    /// Create SPDX package from dependency graph node
    async fn create_spdx_package(&self, project: &Project, package: &PackageNode) -> Result<SpdxPackage> {
        let mut spdx_package = SpdxPackage::new(package.name.clone(), package.version.clone());
        
        // Set download location
        let download_location = match &package.source {
            PackageSource::Registry { url, .. } => url.clone(),
            PackageSource::Git { url, .. } => url.clone(),
            PackageSource::Local { path } => format!("file://{}", path),
        };
        spdx_package = spdx_package.with_download_location(download_location);
        
        // Add checksums
        spdx_package = spdx_package.add_checksum("SHA256", package.checksum.clone());
        
        // Add license information if enabled
        if self.config.include_licenses {
            // This would extract license information from Cargo.toml
            // For now, add placeholder
            spdx_package = spdx_package.with_license("MIT OR Apache-2.0".to_string());
        }
        
        // Add external references
        if let PackageSource::Git { url, rev, .. } = &package.source {
            let git_ref = SpdxExternalReference {
                reference_category: "VCS".to_string(),
                reference_type: "git".to_string(),
                reference_locator: url.clone(),
                comment: Some(format!("Commit: {}", rev)),
            };
            spdx_package = spdx_package.add_external_reference(git_ref);
        }
        
        Ok(spdx_package)
    }
    
    /// Create CycloneDX component from dependency graph node
    async fn create_cyclonedx_component(&self, project: &Project, package: &PackageNode) -> Result<CycloneDxComponent> {
        let mut component = CycloneDxComponent::new(package.name.clone(), package.version.clone());
        
        // Add hashes
        component = component.add_hash("SHA-256", package.checksum.clone());
        
        // Add scope based on dependency kind
        let scope = self.get_component_scope(package);
        component = component.with_scope(scope);
        
        // Add license information if enabled
        if self.config.include_licenses {
            let license_choice = CycloneDxLicenseChoice::Expression("MIT OR Apache-2.0".to_string());
            component = component.with_license(license_choice);
        }
        
        // Add external references
        if let PackageSource::Git { url, .. } = &package.source {
            let external_ref = CycloneDxExternalReference {
                r#type: "vcs".to_string(),
                url: url.clone(),
                comment: Some("Git repository".to_string()),
            };
            if component.external_references.is_none() {
                component.external_references = Some(vec![external_ref]);
            } else {
                component.external_references.as_mut().unwrap().push(external_ref);
            }
        }
        
        // Add Rust-specific properties
        component = component.add_property(
            "rust:package_source".to_string(),
            format!("{:?}", package.source)
        );
        
        component = component.add_property(
            "rust:classification".to_string(),
            format!("{:?}", package.classification)
        );
        
        Ok(component)
    }
    
    /// Get component scope based on dependency kind
    fn get_component_scope(&self, package: &PackageNode) -> Option<String> {
        for annotation in &package.annotations {
            if annotation.key == RustAnnotation::keys::DEPENDENCY_KIND {
                if let Some(kind_str) = annotation.value.as_str() {
                    match kind_str {
                        "dev" => return Some("development".to_string()),
                        "build" => return Some("build".to_string()),
                        "normal" => return Some("runtime".to_string()),
                        _ => {}
                    }
                }
            }
        }
        
        // Default to required scope
        Some("required".to_string())
    }
    
    /// Add SPDX relationships between packages
    fn add_spdx_relationships(&self, spdx_doc: &mut SpdxDocument, dependency_graph: &DependencyGraph) {
        for edge in &dependency_graph.edges {
            let from_package_id = format!("SPDXRef-{}", edge.from);
            let to_package_id = format!("SPDXRef-{}", edge.to);
            
            let relationship = SpdxRelationship {
                spdx_element_id: from_package_id,
                related_spdx_element: to_package_id,
                relationship_type: "DEPENDS_ON".to_string(),
                comment: Some(format!("Dependency kind: {:?}", edge.kind)),
            };
            
            spdx_doc.add_relationship(relationship);
        }
    }
    
    /// Add CycloneDX dependencies
    fn add_cyclonedx_dependencies(&self, cyclonedx_doc: &mut CycloneDxDocument, dependency_graph: &DependencyGraph) {
        for edge in &dependency_graph.edges {
            let from_ref = format!("pkg:{}", edge.from);
            let to_ref = format!("pkg:{}", edge.to);
            
            let dependency = CycloneDxDependency {
                ref: from_ref,
                depends_on: vec![to_ref],
            };
            
            cyclonedx_doc.add_dependency(dependency);
        }
    }
}

/// SBOM wrapper enum
#[derive(Debug, Clone, PartialEq)]
pub enum Sbom {
    /// SPDX document
    Spdx(SpdxDocument),
    /// CycloneDX document
    CycloneDx(CycloneDxDocument),
}

impl Default for SbomGeneratorConfig {
    fn default() -> Self {
        Self {
            format: SbomFormat::SpdxJson,
            include_dev_dependencies: false,
            include_build_dependencies: true,
            include_licenses: true,
            author: "Rust Ecosystem Adapter".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RustAdapterConfig;
    use crate::models::project_types::*;
    
    #[test]
    fn test_sbom_generator_creation() {
        let config = RustAdapterConfig::default();
        let generator = SbomGenerator::new(&config);
        
        assert!(generator.is_ready());
        assert!(matches!(generator.config.format, SbomFormat::SpdxJson));
    }
    
    #[tokio::test]
    async fn test_spdx_generation() {
        let config = RustAdapterConfig::default();
        let generator = SbomGenerator::new(&config);
        
        let project = Project::new(
            "test".to_string(),
            "Test Project".to_string(),
            "rust".to_string(),
            std::path::PathBuf::from("/test"),
        );
        
        let mut dependency_graph = DependencyGraph::new("test".to_string(), "rust".to_string());
        
        let package = PackageNode {
            id: uuid::Uuid::new_v4(),
            name: "test-package".to_string(),
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
        
        dependency_graph.add_package(package);
        
        let result = generator.generate_spdx(&project, &dependency_graph).await;
        assert!(result.is_ok());
        
        let spdx_doc = result.unwrap();
        assert_eq!(spdx_doc.name, "Test Project");
        assert_eq!(spdx_doc.packages.len(), 1);
        assert_eq!(spdx_doc.packages[0].name, "test-package");
        assert_eq!(spdx_doc.packages[0].version, "1.0.0");
    }
    
    #[tokio::test]
    async fn test_cyclonedx_generation() {
        let config = RustAdapterConfig::default();
        let generator = SbomGenerator::new(&config);
        
        let project = Project::new(
            "test".to_string(),
            "Test Project".to_string(),
            "rust".to_string(),
            std::path::PathBuf::from("/test"),
        );
        
        let mut dependency_graph = DependencyGraph::new("test".to_string(), "rust".to_string());
        
        let package = PackageNode {
            id: uuid::Uuid::new_v4(),
            name: "test-package".to_string(),
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
        
        dependency_graph.add_package(package);
        
        let result = generator.generate_cyclonedx(&project, &dependency_graph).await;
        assert!(result.is_ok());
        
        let cyclonedx_doc = result.unwrap();
        assert_eq!(cyclonedx_doc.components.len(), 1);
        assert_eq!(cyclonedx_doc.components[0].name, "test-package");
        assert_eq!(cyclonedx_doc.components[0].version, "1.0.0");
    }
}
