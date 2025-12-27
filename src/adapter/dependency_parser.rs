//! Dependency parser for Cargo.lock files
//! 
//! This module implements Cargo.lock parsing and dependency graph building,
//! treating Cargo.lock as the authoritative source of dependency state.

use crate::models::*;
use crate::error::{AdapterError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Cargo.lock file structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoLock {
    /// Cargo.lock version
    pub version: u32,
    /// Package list
    pub package: Vec<CargoLockPackage>,
}

/// Package in Cargo.lock
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoLockPackage {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package source
    pub source: Option<CargoLockSource>,
    /// Package dependencies
    pub dependencies: Vec<CargoLockDependency>,
    /// Package checksum
    pub checksum: Option<String>,
}

/// Source information in Cargo.lock
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum CargoLockSource {
    /// Registry source
    Registry {
        /// Registry name
        registry: String,
        /// Package checksum
        checksum: String,
    },
    /// Git source
    Git {
        /// Repository URL
        url: String,
        /// Commit hash
        rev: String,
        /// Package checksum
        checksum: String,
    },
    /// Local path source
    Local {
        /// Local path
        path: String,
    },
}

/// Dependency in Cargo.lock
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoLockDependency {
    /// Dependency name
    pub name: String,
    /// Version requirement
    pub version: Option<String>,
    /// Source information
    pub source: Option<CargoLockSource>,
    /// Kind of dependency
    pub kind: Option<String>,
    /// Target-specific information
    pub target: Option<String>,
}

/// Dependency parser implementation
#[derive(Debug, Clone)]
pub struct DependencyParser {
    /// Parser configuration
    config: DependencyParserConfig,
    /// Whether parser is ready
    ready: bool,
}

/// Configuration for dependency parser
#[derive(Debug, Clone)]
pub struct DependencyParserConfig {
    /// Whether to use cargo metadata for enhancement
    pub use_metadata_enhancement: bool,
    /// Maximum depth for dependency analysis
    pub max_depth: Option<usize>,
    /// Whether to validate checksums
    pub validate_checksums: bool,
}

impl DependencyParser {
    /// Create new dependency parser with configuration
    pub fn new(config: &RustAdapterConfig) -> Self {
        Self {
            config: DependencyParserConfig {
                use_metadata_enhancement: true,
                max_depth: config.classification_config.confidence_threshold > 0.5,
                validate_checksums: true,
            },
            ready: true,
        }
    }
    
    /// Check if parser is ready
    pub fn is_ready(&self) -> bool {
        self.ready
    }
    
    /// Parse dependencies from Cargo.lock (authoritative source)
    pub async fn parse_dependencies(&self, project: &Project) -> Result<DependencyGraph> {
        // 1. Load and parse Cargo.lock as authoritative source
        let lockfile_path = project.lockfile_path();
        let lockfile_content = std::fs::read_to_string(&lockfile_path)
            .map_err(|e| AdapterError::file_not_found(&lockfile_path, "reading Cargo.lock"))?;
        
        let cargo_lock: CargoLock = toml::from_str(&lockfile_content)
            .map_err(|e| AdapterError::cargo_lock_parse_error(&lockfile_path, 0, &e.to_string()))?;
        
        // 2. Build base dependency graph from Cargo.lock only
        let mut dependency_graph = self.build_base_graph(project, cargo_lock)?;
        
        // 3. Optionally enhance with cargo metadata (advisory only)
        if self.config.use_metadata_enhancement {
            if let Ok(enhanced_graph) = self.enhance_with_metadata(project, &mut dependency_graph).await {
                dependency_graph = enhanced_graph;
            }
        }
        
        // 4. Validate UGDG schema compliance
        self.validate_ugdg_schema(&dependency_graph)?;
        
        Ok(dependency_graph)
    }
    
    /// Build base dependency graph from Cargo.lock
    fn build_base_graph(&self, project: &Project, cargo_lock: CargoLock) -> Result<DependencyGraph> {
        let mut dependency_graph = DependencyGraph::new(project.id.clone(), project.ecosystem.clone());
        
        // Create package nodes from Cargo.lock entries
        let mut package_map: HashMap<String, PackageId> = HashMap::new();
        
        for cargo_pkg in &cargo_lock.package {
            let package_id = uuid::Uuid::new_v4();
            
            // Convert Cargo.lock source to universal PackageSource
            let package_source = match &cargo_pkg.source {
                Some(CargoLockSource::Registry { registry, checksum }) => {
                    PackageSource::Registry {
                        url: format!("https://{}", registry),
                        checksum: checksum.clone(),
                    }
                },
                Some(CargoLockSource::Git { url, rev, checksum }) => {
                    PackageSource::Git {
                        url: url.clone(),
                        rev: rev.clone(),
                        checksum: checksum.clone(),
                    }
                },
                Some(CargoLockSource::Local { path }) => {
                    PackageSource::Local {
                        path: path.clone(),
                    }
                },
                None => {
                    // Default to crates.io registry
                    PackageSource::Registry {
                        url: "https://crates.io".to_string(),
                        checksum: cargo_pkg.checksum.clone().unwrap_or_default(),
                    }
                },
            };
            
            let package_node = PackageNode {
                id: package_id,
                name: cargo_pkg.name.clone(),
                version: cargo_pkg.version.clone(),
                source: package_source,
                checksum: cargo_pkg.checksum.clone().unwrap_or_default(),
                classification: Classification::Unknown, // Will be set by classifier
                audit_status: AuditStatus::Unaudited, // Will be set by audit runner
                annotations: vec![
                    RustAnnotation::new(
                        RustAnnotation::keys::DEPENDENCY_KIND.to_string(),
                        serde_json::Value::String(cargo_pkg.dependencies.iter()
                            .find(|d| d.kind.as_ref().map(|k| k == "normal").unwrap_or(false))
                            .map(|d| d.kind.clone().unwrap_or_else(|| "normal".to_string()))
                            .unwrap_or_else(|| "normal".to_string()))
                    ),
                ],
            };
            
            dependency_graph.add_package(package_node);
            package_map.insert(cargo_pkg.name.clone(), package_id);
        }
        
        // Create dependency edges
        for cargo_pkg in &cargo_lock.package {
            if let Some(from_id) = package_map.get(&cargo_pkg.name) {
                for dep in &cargo_pkg.dependencies {
                    if let Some(to_id) = package_map.get(&dep.name) {
                        let dependency_kind = match dep.kind.as_deref() {
                            Some("build") => DependencyKind::Build,
                            Some("dev") => DependencyKind::Dev,
                            _ => DependencyKind::Normal,
                        };
                        
                        let edge = DependencyEdge {
                            from: *from_id,
                            to: *to_id,
                            kind: dependency_kind,
                            target: dep.target.clone(),
                            optional: false, // Cargo.lock doesn't track optional status
                            features: Vec::new(), // Features not tracked in Cargo.lock
                        };
                        
                        dependency_graph.add_edge(edge);
                    }
                }
            }
        }
        
        Ok(dependency_graph)
    }
    
    /// Enhance graph with cargo metadata (advisory only)
    async fn enhance_with_metadata(&self, project: &Project, graph: &mut DependencyGraph) -> Result<DependencyGraph> {
        // This would run `cargo metadata` in non-offline mode
        // For now, return unmodified graph as Cargo.lock is authoritative
        
        // Update graph metadata to indicate enhancement attempt
        graph.metadata.tool_versions.insert("cargo".to_string(), "1.0.0".to_string());
        graph.metadata.offline_mode = project.requires_strict_security();
        
        Ok(graph.clone())
    }
    
    /// Validate UGDG schema compliance
    fn validate_ugdg_schema(&self, graph: &DependencyGraph) -> Result<()> {
        // Basic schema validation
        if graph.root_packages.is_empty() {
            return Err(AdapterError::Internal {
                message: "Dependency graph has no packages".to_string(),
                source: anyhow::anyhow!("Empty graph"),
            });
        }
        
        // Validate package nodes
        for package in &graph.root_packages {
            if package.name.is_empty() {
                return Err(AdapterError::MetadataParseError {
                    field: "package.name".to_string(),
                    value: package.name.clone(),
                    source: anyhow::anyhow!("Empty package name"),
                });
            }
            
            if package.version.is_empty() {
                return Err(AdapterError::MetadataParseError {
                    field: "package.version".to_string(),
                    value: package.version.clone(),
                    source: anyhow::anyhow!("Empty package version"),
                });
            }
        }
        
        Ok(())
    }
    
    /// Extract Git dependency information
    pub fn extract_git_info(&self, package: &CargoLockPackage) -> Option<GitInfo> {
        match &package.source {
            Some(CargoLockSource::Git { url, rev, checksum: _ }) => {
                Some(GitInfo {
                    repository_url: url.clone(),
                    commit_hash: rev.clone(),
                    branch: None, // Cargo.lock doesn't track branch
                })
            },
            _ => None,
        }
    }
}

/// Git dependency information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitInfo {
    /// Repository URL
    pub repository_url: String,
    /// Commit hash
    pub commit_hash: String,
    /// Branch name (if known)
    pub branch: Option<String>,
}

impl Default for DependencyParserConfig {
    fn default() -> Self {
        Self {
            use_metadata_enhancement: true,
            max_depth: Some(10),
            validate_checksums: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::project_types::*;
    use std::path::PathBuf;
    
    #[test]
    fn test_cargo_lock_parsing() {
        let lockfile_content = r#"
[[package]]
name = "serde"
version = "1.0.130"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f6ed5d4a5a6f0f8c6e3d5641c8e4f7a1b2d5f5f2b6c2c9e9e0c5d4b6e7d5f6e7d"
dependencies = []

[[package]]
name = "serde_json"
version = "1.0.72"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a2c6e6c6f6c6e6c6f6c6e6c6f6c6e6c6f6c6e6c6f6c6e6c6f"
dependencies = [
    { name = "serde", version = "1.0.130" }
]
"#;
        
        let cargo_lock: CargoLock = toml::from_str(lockfile_content).unwrap();
        assert_eq!(cargo_lock.version, 3);
        assert_eq!(cargo_lock.package.len(), 2);
        assert_eq!(cargo_lock.package[0].name, "serde");
        assert_eq!(cargo_lock.package[1].name, "serde_json");
    }
    
    #[test]
    fn test_dependency_parser_creation() {
        let config = RustAdapterConfig::default();
        let parser = DependencyParser::new(&config);
        
        assert!(parser.is_ready());
        assert!(parser.config.use_metadata_enhancement);
        assert!(parser.config.validate_checksums);
    }
    
    #[tokio::test]
    async fn test_build_base_graph() {
        let project = Project::new(
            "test".to_string(),
            "Test Project".to_string(),
            "rust".to_string(),
            PathBuf::from("/test"),
        );
        
        let cargo_lock = CargoLock {
            version: 3,
            package: vec![
                CargoLockPackage {
                    name: "serde".to_string(),
                    version: "1.0.130".to_string(),
                    source: Some(CargoLockSource::Registry {
                        registry: "crates.io".to_string(),
                        checksum: "test-checksum".to_string(),
                    }),
                    dependencies: vec![],
                    checksum: Some("test-checksum".to_string()),
                },
            ],
        };
        
        let parser = DependencyParser::new(&RustAdapterConfig::default());
        let graph = parser.build_base_graph(&project, cargo_lock).unwrap();
        
        assert_eq!(graph.project_id, "test");
        assert_eq!(graph.ecosystem, "rust");
        assert_eq!(graph.root_packages.len(), 1);
        assert_eq!(graph.root_packages[0].name, "serde");
        assert_eq!(graph.root_packages[0].version, "1.0.130");
    }
}
