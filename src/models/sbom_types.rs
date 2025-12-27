//! SBOM (Software Bill of Materials) types and structures
//! 
//! This module defines types for generating SBOM in SPDX and CycloneDX formats,
//! ensuring compliance with standards while maintaining policy neutrality.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::dependency_graph::*;

/// SBOM format options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SbomFormat {
    /// SPDX 2.3 JSON format
    SpdxJson,
    /// CycloneDX 1.4 JSON format
    CycloneDxJson,
}

/// SBOM generation configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SbomConfig {
    /// SBOM format
    pub format: SbomFormat,
    /// Include development dependencies
    pub include_dev_dependencies: bool,
    /// Include build dependencies
    pub include_build_dependencies: bool,
    /// Include license information
    pub include_licenses: bool,
    /// Include vulnerability information (policy-neutral - should be false)
    pub include_vulnerabilities: bool,
    /// SBOM document namespace
    pub namespace: Option<String>,
    /// Document author
    pub author: String,
    /// Document creation timestamp
    pub created_at: String,
}

/// SPDX document structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpdxDocument {
    /// SPDX version
    pub spdx_version: String,
    /// Data license
    pub data_license: String,
    /// SPDX identifier
    pub spdx_id: String,
    /// Document name
    pub name: String,
    /// Document namespace
    pub document_namespace: String,
    /// Creation information
    pub creation_info: SpdxCreationInfo,
    /// Package information
    pub packages: Vec<SpdxPackage>,
    /// Relationship information
    pub relationships: Vec<SpdxRelationship>,
}

/// SPDX creation information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpdxCreationInfo {
    /// Creation timestamp
    pub created: String,
    /// Creators
    pub creators: Vec<String>,
    /// License list version
    pub license_list_version: String,
}

/// SPDX package information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpdxPackage {
    /// SPDX identifier
    pub spdx_id: String,
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package download location
    pub download_location: Option<String>,
    /// Files analyzed flag
    pub files_analyzed: bool,
    /// License conclusions
    pub license_concluded: Option<String>,
    /// License declared
    pub license_declared: Option<String>,
    /// License comments
    pub license_comments: Option<String>,
    /// Copyright text
    pub copyright_text: Option<String>,
    /// Package summary
    pub summary: Option<String>,
    /// Package description
    pub description: Option<String>,
    /// Source information
    pub source_info: Option<String>,
    /// Package checksums
    pub checksums: Vec<SpdxChecksum>,
    /// External references
    pub external_refs: Vec<SpdxExternalReference>,
}

/// SPDX checksum information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpdxChecksum {
    /// Checksum algorithm
    pub algorithm: String,
    /// Checksum value
    pub checksum_value: String,
}

/// SPDX external reference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpdxExternalReference {
    /// Reference category
    pub reference_category: String,
    /// Reference type
    pub reference_type: String,
    /// Reference locator
    pub reference_locator: String,
    /// Reference comments
    pub comment: Option<String>,
}

/// SPDX relationship
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpdxRelationship {
    /// SPDX element ID
    pub spdx_element_id: String,
    /// Related SPDX element
    pub related_spdx_element: String,
    /// Relationship type
    pub relationship_type: String,
    /// Relationship comment
    pub comment: Option<String>,
}

/// CycloneDX document structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxDocument {
    /// BOM format version
    pub bom_format: String,
    /// BOM specification version
    pub spec_version: String,
    /// Serial number
    pub serial_number: String,
    /// BOM metadata
    pub metadata: CycloneDxMetadata,
    /// Component list
    pub components: Vec<CycloneDxComponent>,
    /// Dependencies
    pub dependencies: Vec<CycloneDxDependency>,
}

/// CycloneDX metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxMetadata {
    /// Component information
    pub component: Option<CycloneDxComponent>,
    /// BOM timestamp
    pub timestamp: String,
    /// Tools used
    pub tools: Option<Vec<CycloneDxTool>>,
    /// Authors
    pub authors: Option<Vec<CycloneDxAuthor>>,
}

/// CycloneDX component
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxComponent {
    /// Component type
    pub r#type: String,
    /// Component name
    pub name: String,
    /// Component version
    pub version: String,
    /// Component scope
    pub scope: Option<String>,
    /// Component hashes
    pub hashes: Vec<CycloneDxHash>,
    /// Component licenses
    pub licenses: Option<Vec<CycloneDxLicenseChoice>>,
    /// Component external references
    pub external_references: Option<Vec<CycloneDxExternalReference>>,
    /// Component properties
    pub properties: Option<Vec<CycloneDxProperty>>,
}

/// CycloneDX hash
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxHash {
    /// Hash algorithm
    pub alg: String,
    /// Hash content
    pub content: String,
}

/// CycloneDX license choice
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum CycloneDxLicenseChoice {
    /// License expression
    Expression(String),
    /// License with ID
    License { license: CycloneDxLicense },
}

/// CycloneDX license
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxLicense {
    /// License ID
    pub id: Option<String>,
    /// License name
    pub name: Option<String>,
    /// License text
    pub text: Option<String>,
    /// License URL
    pub url: Option<String>,
}

/// CycloneDX external reference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxExternalReference {
    /// Reference type
    pub r#type: String,
    /// Reference URL
    pub url: String,
    /// Reference comment
    pub comment: Option<String>,
}

/// CycloneDX property
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxProperty {
    /// Property name
    pub name: String,
    /// Property value
    pub value: String,
}

/// CycloneDX dependency
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxDependency {
    /// Dependency reference
    pub ref: String,
    /// Dependency depends on
    pub depends_on: Vec<String>,
}

/// CycloneDX tool information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxTool {
    /// Tool vendor
    pub vendor: Option<String>,
    /// Tool name
    pub name: String,
    /// Tool version
    pub version: String,
    /// Tool hashes
    pub hashes: Option<Vec<CycloneDxHash>>,
}

/// CycloneDX author information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycloneDxAuthor {
    /// Author name
    pub name: String,
    /// Author email
    pub email: Option<String>,
}

/// License information extracted from Cargo.toml
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LicenseInfo {
    /// License identifier
    pub license_id: Option<String>,
    /// License name
    pub name: Option<String>,
    /// License expression (for multiple licenses)
    pub license_expression: Option<String>,
    /// License file path
    pub license_file: Option<String>,
}

impl Default for SbomConfig {
    fn default() -> Self {
        Self {
            format: SbomFormat::SpdxJson,
            include_dev_dependencies: false,
            include_build_dependencies: true,
            include_licenses: true,
            include_vulnerabilities: false, // Policy neutral - no vulnerability scoring
            namespace: None,
            author: "Rust Ecosystem Adapter".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl SpdxDocument {
    /// Create new SPDX document
    pub fn new(name: String, namespace: String) -> Self {
        Self {
            spdx_version: "SPDX-2.3".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name,
            document_namespace: namespace,
            creation_info: SpdxCreationInfo::default(),
            packages: Vec::new(),
            relationships: Vec::new(),
        }
    }
    
    /// Add package to SPDX document
    pub fn add_package(&mut self, package: SpdxPackage) {
        self.packages.push(package);
    }
    
    /// Add relationship to SPDX document
    pub fn add_relationship(&mut self, relationship: SpdxRelationship) {
        self.relationships.push(relationship);
    }
}

impl Default for SpdxCreationInfo {
    fn default() -> Self {
        Self {
            created: chrono::Utc::now().to_rfc3339(),
            creators: vec![
                "Tool: rust-ecosystem-adapter".to_string(),
            ],
            license_list_version: "3.20".to_string(),
        }
    }
}

impl SpdxPackage {
    /// Create new SPDX package
    pub fn new(name: String, version: String) -> Self {
        Self {
            spdx_id: format!("SPDXRef-{}-{}", name.replace("-", "_"), version.replace(".", "_")),
            name,
            version,
            download_location: None,
            files_analyzed: false,
            license_concluded: None,
            license_declared: None,
            license_comments: None,
            copyright_text: None,
            summary: None,
            description: None,
            source_info: None,
            checksums: Vec::new(),
            external_refs: Vec::new(),
        }
    }
    
    /// Add checksum to package
    pub fn add_checksum(mut self, algorithm: String, checksum: String) -> Self {
        self.checksums.push(SpdxChecksum {
            algorithm,
            checksum_value: checksum,
        });
        self
    }
    
    /// Add external reference
    pub fn add_external_reference(mut self, external_ref: SpdxExternalReference) -> Self {
        self.external_refs.push(external_ref);
        self
    }
    
    /// Set license information
    pub fn with_license(mut self, license_declared: String) -> Self {
        self.license_declared = Some(license_declared);
        self.license_concluded = Some(license_declared);
        self
    }
    
    /// Set download location
    pub fn with_download_location(mut self, location: String) -> Self {
        self.download_location = Some(location);
        self
    }
}

impl CycloneDxDocument {
    /// Create new CycloneDX document
    pub fn new() -> Self {
        Self {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.4".to_string(),
            serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            metadata: CycloneDxMetadata::default(),
            components: Vec::new(),
            dependencies: Vec::new(),
        }
    }
    
    /// Add component to CycloneDX document
    pub fn add_component(&mut self, component: CycloneDxComponent) {
        self.components.push(component);
    }
    
    /// Add dependency to CycloneDX document
    pub fn add_dependency(&mut self, dependency: CycloneDxDependency) {
        self.dependencies.push(dependency);
    }
}

impl Default for CycloneDxMetadata {
    fn default() -> Self {
        Self {
            component: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            tools: Some(vec![CycloneDxTool::default()]),
            authors: None,
        }
    }
}

impl CycloneDxComponent {
    /// Create new CycloneDX component
    pub fn new(name: String, version: String) -> Self {
        Self {
            r#type: "library".to_string(),
            name,
            version,
            scope: None,
            hashes: Vec::new(),
            licenses: None,
            external_references: None,
            properties: None,
        }
    }
    
    /// Set component scope
    pub fn with_scope(mut self, scope: String) -> Self {
        self.scope = Some(scope);
        self
    }
    
    /// Add hash to component
    pub fn add_hash(mut self, algorithm: String, content: String) -> Self {
        self.hashes.push(CycloneDxHash {
            alg: algorithm,
            content,
        });
        self
    }
    
    /// Add license to component
    pub fn with_license(mut self, license: CycloneDxLicenseChoice) -> Self {
        self.licenses = Some(vec![license]);
        self
    }
    
    /// Add property to component
    pub fn add_property(mut self, name: String, value: String) -> Self {
        if self.properties.is_none() {
            self.properties = Some(Vec::new());
        }
        if let Some(ref mut props) = self.properties {
            props.push(CycloneDxProperty { name, value });
        }
        self
    }
}

impl Default for CycloneDxTool {
    fn default() -> Self {
        Self {
            vendor: Some("rust-ecosystem-adapter".to_string()),
            name: "rust-ecosystem-adapter".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            hashes: None,
        }
    }
}

impl LicenseInfo {
    /// Create new license info
    pub fn new() -> Self {
        Self {
            license_id: None,
            name: None,
            license_expression: None,
            license_file: None,
        }
    }
    
    /// Set license identifier
    pub fn with_id(mut self, id: String) -> Self {
        self.license_id = Some(id);
        self
    }
    
    /// Set license name
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }
    
    /// Set license expression
    pub fn with_expression(mut self, expression: String) -> Self {
        self.license_expression = Some(expression);
        self
    }
    
    /// Set license file
    pub fn with_file(mut self, file: String) -> Self {
        self.license_file = Some(file);
        self
    }
    
    /// Check if license info is empty
    pub fn is_empty(&self) -> bool {
        self.license_id.is_none() && 
        self.name.is_none() && 
        self.license_expression.is_none() && 
        self.license_file.is_none()
    }
}