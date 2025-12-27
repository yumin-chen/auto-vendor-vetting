//! Cargo-specific type definitions and conversions
//! 
//! This module defines types specific to the Rust/Cargo ecosystem
//! and provides conversion functions to universal types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::dependency_graph::*;

/// Cargo package information extracted from Cargo.lock
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoPackage {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package source information
    pub source: CargoSource,
    /// Checksum for integrity verification
    pub checksum: String,
    /// Package dependencies
    pub dependencies: Vec<CargoDependency>,
    /// Whether this is a proc-macro
    pub proc_macro: bool,
    /// Package features
    pub features: Vec<String>,
    /// Target-specific dependencies
    pub target_dependencies: HashMap<String, Vec<CargoDependency>>,
}

/// Cargo-specific source information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum CargoSource {
    /// Registry source (e.g., crates.io)
    Registry { 
        /// Registry name
        registry: String,
        /// Package checksum
        checksum: String 
    },
    /// Git repository source
    Git { 
        /// Repository URL
        url: String, 
        /// Commit hash
        rev: String, 
        /// Optional branch or tag
        branch: Option<String>,
        /// Package checksum
        checksum: String 
    },
    /// Local path source
    Local { 
        /// Local path
        path: String 
    },
}

/// Cargo dependency information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoDependency {
    /// Dependency name
    pub name: String,
    /// Version requirement
    pub version_req: String,
    /// Dependency kind (normal, build, dev)
    pub kind: CargoDependencyKind,
    /// Whether this dependency is optional
    pub optional: bool,
    /// Target-specific information
    pub target: Option<String>,
    /// Required features
    pub features: Vec<String>,
}

/// Cargo dependency kinds
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CargoDependencyKind {
    /// Normal runtime dependency
    Normal,
    /// Build-time dependency
    Build,
    /// Development dependency
    Dev,
}

/// Cargo metadata extracted from cargo metadata command
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoMetadata {
    /// Package metadata
    pub packages: Vec<CargoMetadataPackage>,
    /// Workspace members
    pub workspace_members: Vec<String>,
    /// Target directory
    pub target_directory: String,
    /// Workspace root
    pub workspace_root: String,
}

/// Package metadata from cargo metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoMetadataPackage {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package ID
    pub id: String,
    /// Package license
    pub license: Option<String>,
    /// Package license file
    pub license_file: Option<String>,
    /// Package description
    pub description: Option<String>,
    /// Package categories
    pub categories: Vec<String>,
    /// Package keywords
    pub keywords: Vec<String>,
    /// Rust edition
    pub edition: Option<String>,
    /// Required Rust version
    pub rust_version: Option<String>,
    /// Package repository
    pub repository: Option<String>,
    /// Package homepage
    pub homepage: Option<String>,
    /// Package dependencies
    pub dependencies: Vec<CargoMetadataDependency>,
    /// Package targets
    pub targets: Vec<CargoMetadataTarget>,
}

/// Dependency information from cargo metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoMetadataDependency {
    /// Dependency name
    pub name: String,
    /// Version requirement
    pub req: String,
    /// Dependency kind
    pub kind: Option<CargoDependencyKind>,
    /// Whether this dependency is optional
    pub optional: bool,
    /// Required features
    pub features: Vec<String>,
    /// Target information
    pub target: Option<String>,
}

/// Target information from cargo metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoMetadataTarget {
    /// Target name
    pub name: String,
    /// Target kind (e.g., "proc-macro")
    pub kind: Vec<String>,
    /// crate types
    pub crate_types: Vec<String>,
    /// Target source path
    pub src_path: String,
    /// Edition for this target
    pub edition: Option<String>,
}

/// Cargo.lock file structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoLock {
    /// Cargo.lock version
    pub version: u32,
    /// Package list
    pub package: Vec<CargoPackage>,
}

/// Classification signal for TCS classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClassificationSignal {
    /// Explicit override configuration
    ExplicitOverride(String),
    /// Dependency kind indicates TCS
    DependencyKind(CargoDependencyKind),
    /// Build script usage detected
    BuildScriptUsage,
    /// Proc-macro usage detected
    ProcMacroUsage,
    /// Name pattern match
    NamePattern(String),
    /// Cargo category match
    CargoCategory(String),
    /// Cargo keyword match
    CargoKeyword(String),
}

/// Result of TCS classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassificationResult {
    /// Toolchain role
    pub role: ToolchainRole,
    /// Classification signals
    pub signals: Vec<ClassificationSignal>,
}

/// Toolchain role (TCS vs Mechanical)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ToolchainRole {
    /// Trust-Critical Software
    TCS(TcsCategory),
    /// Mechanical component
    Mechanical(MechanicalCategory),
}

/// TCS pattern configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TcsPattern {
    /// Pattern name
    pub name: String,
    /// Regular expression for matching
    pub regex: String,
    /// TCS category
    pub category: TcsCategory,
    /// Pattern description
    pub description: String,
    /// Pattern priority (higher = more priority)
    pub priority: u32,
}

impl CargoSource {
    /// Convert to universal PackageSource
    pub fn to_universal(&self) -> PackageSource {
        match self {
            CargoSource::Registry { registry, checksum } => {
                PackageSource::Registry {
                    url: format!("https://{}", registry),
                    checksum: checksum.clone(),
                }
            },
            CargoSource::Git { url, rev, checksum, .. } => {
                PackageSource::Git {
                    url: url.clone(),
                    rev: rev.clone(),
                    checksum: checksum.clone(),
                }
            },
            CargoSource::Local { path } => {
                PackageSource::Local {
                    path: path.clone(),
                }
            },
        }
    }
    
    /// Get checksum string
    pub fn checksum(&self) -> &str {
        match self {
            CargoSource::Registry { checksum, .. } => checksum,
            CargoSource::Git { checksum, .. } => checksum,
            CargoSource::Local { .. } => "",
        }
    }
}

impl CargoDependencyKind {
    /// Convert to universal DependencyKind
    pub fn to_universal(&self) -> DependencyKind {
        match self {
            CargoDependencyKind::Normal => DependencyKind::Normal,
            CargoDependencyKind::Build => DependencyKind::Build,
            CargoDependencyKind::Dev => DependencyKind::Dev,
        }
    }
}

impl CargoPackage {
    /// Check if package is a proc-macro
    pub fn is_proc_macro(&self) -> bool {
        self.proc_macro
    }
    
    /// Get dependency by name
    pub fn get_dependency(&self, name: &str) -> Option<&CargoDependency> {
        self.dependencies.iter().find(|d| d.name == name)
    }
    
    /// Get all dependencies of a specific kind
    pub fn get_dependencies_by_kind(&self, kind: CargoDependencyKind) -> Vec<&CargoDependency> {
        self.dependencies.iter()
            .filter(|d| d.kind == kind)
            .collect()
    }
}

impl CargoMetadataPackage {
    /// Check if package has proc-macro target
    pub fn has_proc_macro_target(&self) -> bool {
        self.targets.iter()
            .any(|t| t.kind.contains(&"proc-macro".to_string()))
    }
    
    /// Get license information
    pub fn get_license_expression(&self) -> Option<String> {
        self.license.clone().or_else(|| {
            self.license_file.as_ref().map(|_| "NOASSERTION".to_string())
        })
    }
}

impl ClassificationSignal {
    /// Get signal description
    pub fn description(&self) -> String {
        match self {
            ClassificationSignal::ExplicitOverride(name) => {
                format!("Explicit override configuration for package: {}", name)
            },
            ClassificationSignal::DependencyKind(kind) => {
                format!("Dependency kind indicates TCS: {:?}", kind)
            },
            ClassificationSignal::BuildScriptUsage => {
                "Build script usage detected".to_string()
            },
            ClassificationSignal::ProcMacroUsage => {
                "Proc-macro usage detected".to_string()
            },
            ClassificationSignal::NamePattern(pattern) => {
                format!("Name pattern match: {}", pattern)
            },
            ClassificationSignal::CargoCategory(category) => {
                format!("Cargo category match: {}", category)
            },
            ClassificationSignal::CargoKeyword(keyword) => {
                format!("Cargo keyword match: {}", keyword)
            },
        }
    }
}

impl ClassificationResult {
    /// Create new TCS classification result
    pub fn tcs(category: TcsCategory, signals: Vec<ClassificationSignal>) -> Self {
        Self {
            role: ToolchainRole::TCS(category),
            signals,
        }
    }
    
    /// Create new mechanical classification result
    pub fn mechanical(signals: Vec<ClassificationSignal>) -> Self {
        Self {
            role: ToolchainRole::Mechanical(MechanicalCategory::Other("default".to_string())),
            signals,
        }
    }
    
    /// Check if classification is TCS
    pub fn is_tcs(&self) -> bool {
        matches!(self.role, ToolchainRole::TCS(_))
    }
    
    /// Get TCS category if applicable
    pub fn tcs_category(&self) -> Option<TcsCategory> {
        match &self.role {
            ToolchainRole::TCS(category) => Some(category.clone()),
            _ => None,
        }
    }
}

impl TcsPattern {
    /// Create new TCS pattern
    pub fn new(name: String, regex: String, category: TcsCategory, description: String) -> Self {
        Self {
            name,
            regex,
            category,
            description,
            priority: 100,
        }
    }
    
    /// Set pattern priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
    
    /// Check if pattern matches a package name
    pub fn matches(&self, package_name: &str) -> bool {
        regex::Regex::new(&self.regex)
            .map(|re| re.is_match(package_name))
            .unwrap_or(false)
    }
}