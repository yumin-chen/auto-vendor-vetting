//! Universal Dependency Graph (UDG) models
//! 
//! This module defines the core data structures for representing
//! dependency graphs in a language-agnostic way, with support
//! for Rust-specific annotations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Unique identifier for a package
pub type PackageId = Uuid;

/// Unique identifier for a project
pub type ProjectId = String;

/// Universal dependency graph that remains language-agnostic
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DependencyGraph {
    /// Unique identifier for the project
    pub project_id: ProjectId,
    /// Ecosystem identifier (e.g., "rust", "go", "nodejs")
    pub ecosystem: String,
    /// Root packages in the dependency graph
    pub root_packages: Vec<PackageNode>,
    /// Dependency relationships between packages
    pub edges: Vec<DependencyEdge>,
    /// Graph metadata
    pub metadata: GraphMetadata,
}

/// Node representing a package in the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackageNode {
    /// Unique identifier for the package
    pub id: PackageId,
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package source (registry, git, local)
    pub source: PackageSource,
    /// Package checksum for integrity verification
    pub checksum: String,
    /// Package classification (TCS or Mechanical)
    pub classification: Classification,
    /// Current audit status
    pub audit_status: AuditStatus,
    /// Rust-specific annotations (namespace="rust")
    pub annotations: Vec<RustAnnotation>,
}

/// Edge representing a dependency relationship
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DependencyEdge {
    /// Source package (dependent)
    pub from: PackageId,
    /// Target package (dependency)
    pub to: PackageId,
    /// Dependency kind (normal, build, dev)
    pub kind: DependencyKind,
    /// Target-specific dependency (if applicable)
    pub target: Option<String>,
    /// Whether this dependency is optional
    pub optional: bool,
    /// Feature requirements for this dependency
    pub features: Vec<String>,
}

/// Package source information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum PackageSource {
    /// Registry source (e.g., crates.io)
    Registry { 
        /// Registry URL
        url: String, 
        /// Package checksum
        checksum: String 
    },
    /// Git repository source
    Git { 
        /// Repository URL
        url: String, 
        /// Commit hash
        rev: String, 
        /// Package checksum
        checksum: String 
    },
    /// Local path source
    Local { 
        /// Local path
        path: String 
    },
}

/// Package classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Classification {
    /// Trust-Critical Software classification
    TCS { 
        /// TCS category
        category: TcsCategory, 
        /// Classification rationale
        rationale: String 
    },
    /// Mechanical component classification
    Mechanical { 
        /// Mechanical category
        category: MechanicalCategory 
    },
    /// Unknown classification (requires classification)
    Unknown,
}

/// Trust-Critical Software categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TcsCategory {
    /// Cryptographic operations
    Cryptography,
    /// Authentication and authorization
    Authentication,
    /// Serialization and deserialization
    Serialization,
    /// Network transport and protocols
    Transport,
    /// Database operations
    Database,
    /// Random number generation
    Random,
    /// Build-time execution (proc-macros, build.rs)
    BuildTimeExecution,
    /// Custom TCS category
    Custom(String),
}

/// Mechanical component categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MechanicalCategory {
    /// Utility functions
    Utility,
    /// Data structures
    DataStructures,
    /// Testing utilities
    Testing,
    /// Development tools
    Development,
    /// Documentation
    Documentation,
    /// Other mechanical components
    Other(String),
}

/// Package audit status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditStatus {
    /// Package has been audited
    Audited { 
        /// Audit method used
        method: AuditMethod, 
        /// Auditor identity
        auditor: String, 
        /// Audit date
        date: String 
    },
    /// Package is exempt from audit
    Exempted { 
        /// Exemption reason
        reason: String, 
        /// Expiration date
        expires: Option<String> 
    },
    /// Package requires audit
    Unaudited,
}

/// Audit method used
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditMethod {
    /// Cargo-vet audit
    CargoVet { 
        /// Audit criteria
        criteria: String 
    },
    /// Manual audit with ADR reference
    Manual { 
        /// ADR reference number
        adr_reference: u32 
    },
    /// Imported audit from external source
    Imported { 
        /// Source of imported audit
        source: String 
    },
    /// Temporary exemption
    Exemption { 
        /// Exemption reason
        reason: String, 
        /// Expiration date
        expires: String 
    },
}

/// Dependency kind
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DependencyKind {
    /// Normal dependency
    Normal,
    /// Build dependency
    Build,
    /// Development dependency
    Dev,
}

/// Rust-specific annotation for UGDG compatibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RustAnnotation {
    /// Always "rust" for namespace
    pub namespace: String,
    /// Annotation key
    pub key: String,
    /// Annotation value
    pub value: serde_json::Value,
}

/// Graph metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphMetadata {
    /// Graph generation timestamp
    pub generated_at: String,
    /// Tool version information
    pub tool_versions: HashMap<String, String>,
    /// Graph schema version
    pub schema_version: String,
    /// Whether this graph was generated in offline mode
    pub offline_mode: bool,
    /// Additional metadata
    pub properties: HashMap<String, serde_json::Value>,
}

impl DependencyGraph {
    /// Create a new dependency graph
    pub fn new(project_id: ProjectId, ecosystem: String) -> Self {
        Self {
            project_id,
            ecosystem,
            root_packages: Vec::new(),
            edges: Vec::new(),
            metadata: GraphMetadata::default(),
        }
    }
    
    /// Add a package node to the graph
    pub fn add_package(&mut self, package: PackageNode) {
        self.root_packages.push(package);
    }
    
    /// Add a dependency edge to the graph
    pub fn add_edge(&mut self, edge: DependencyEdge) {
        self.edges.push(edge);
    }
    
    /// Find a package by name and version
    pub fn find_package(&self, name: &str, version: &str) -> Option<&PackageNode> {
        self.root_packages.iter().find(|p| p.name == name && p.version == version)
    }
    
    /// Find a package by ID
    pub fn find_package_by_id(&self, id: &PackageId) -> Option<&PackageNode> {
        self.root_packages.iter().find(|p| p.id == *id)
    }
    
    /// Get all dependencies of a package
    pub fn get_dependencies(&self, package_id: &PackageId) -> Vec<&DependencyEdge> {
        self.edges.iter().filter(|e| e.from == *package_id).collect()
    }
    
    /// Get all dependents of a package
    pub fn get_dependents(&self, package_id: &PackageId) -> Vec<&DependencyEdge> {
        self.edges.iter().filter(|e| e.to == *package_id).collect()
    }
    
    /// Validate the graph for basic consistency
    pub fn validate(&self) -> Result<(), String> {
        // Check that all edge references exist
        for edge in &self.edges {
            if self.find_package_by_id(&edge.from).is_none() {
                return Err(format!("Edge references non-existent package: {:?}", edge.from));
            }
            if self.find_package_by_id(&edge.to).is_none() {
                return Err(format!("Edge references non-existent package: {:?}", edge.to));
            }
        }
        
        // Check for duplicate package IDs
        let mut seen_ids = std::collections::HashSet::new();
        for package in &self.root_packages {
            if !seen_ids.insert(&package.id) {
                return Err(format!("Duplicate package ID: {:?}", package.id));
            }
        }
        
        Ok(())
    }
}

impl Default for GraphMetadata {
    fn default() -> Self {
        Self {
            generated_at: chrono::Utc::now().to_rfc3339(),
            tool_versions: HashMap::new(),
            schema_version: "1.0.0".to_string(),
            offline_mode: false,
            properties: HashMap::new(),
        }
    }
}

impl RustAnnotation {
    /// Create a new Rust annotation
    pub fn new(key: String, value: serde_json::Value) -> Self {
        Self {
            namespace: "rust".to_string(),
            key,
            value,
        }
    }
    
    /// Common annotation keys
    pub mod keys {
        pub const FEATURES: &str = "features";
        pub const DEPENDENCY_KIND: &str = "dependency_kind";
        pub const TARGET_SPECIFIC: &str = "target_specific";
        pub const PROC_MACRO: &str = "proc_macro";
        pub const CATEGORIES: &str = "categories";
        pub const KEYWORDS: &str = "keywords";
        pub const EDITION: &str = "edition";
        pub const RUST_VERSION: &str = "rust_version";
    }
}