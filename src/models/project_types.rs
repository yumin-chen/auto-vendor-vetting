//! Project-related types and structures
//! 
//! This module defines types for representing projects,
//! project configuration, and project-specific settings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Project representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Project {
    /// Unique project identifier
    pub id: String,
    /// Project name
    pub name: String,
    /// Project repository URL
    pub repository: Option<String>,
    /// Ecosystem (e.g., "rust", "go", "nodejs")
    pub ecosystem: String,
    /// Project owner email
    pub owner_email: Option<String>,
    /// Project paths configuration
    pub paths: ProjectPaths,
    /// Project security configuration
    pub security: ProjectSecurity,
    /// Project TCS configuration
    pub tcs: ProjectTcs,
    /// Project policy configuration
    pub policy: ProjectPolicy,
    /// Project alerting configuration
    pub alerting: ProjectAlerting,
    /// Project metadata
    pub metadata: ProjectMetadata,
}

/// Project paths configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectPaths {
    /// Project root directory
    pub root: PathBuf,
    /// Lock file path (relative to root)
    pub lockfile: PathBuf,
    /// Manifest file path (relative to root)
    pub manifest: PathBuf,
    /// Epochs directory path (relative to root)
    pub epochs: PathBuf,
    /// SBOMs directory path (relative to root)
    pub sboms: PathBuf,
    /// ADRs directory path (relative to root)
    pub adrs: PathBuf,
    /// Vendor directory path (relative to root)
    pub vendor: PathBuf,
    /// Config file path (relative to root)
    pub config: PathBuf,
}

/// Project security configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectSecurity {
    /// Threat level for this project
    pub threat_level: ThreatLevel,
    /// Compliance requirements
    pub compliance: Vec<String>,
    /// Current epoch identifier
    pub current_epoch: Option<String>,
    /// Security team contact
    pub security_team: Option<String>,
}

/// Project TCS configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectTcs {
    /// Cryptographic components
    pub crypto: Vec<String>,
    /// Authentication components
    pub auth: Vec<String>,
    /// Serialization components
    pub serialization: Vec<String>,
    /// Transport components
    pub transport: Vec<String>,
    /// Database components
    pub database: Vec<String>,
    /// Random number generation components
    pub random: Vec<String>,
    /// Build-time execution components
    pub build_time_execution: Vec<String>,
    /// Custom TCS components
    pub custom: HashMap<String, Vec<String>>,
}

/// Project policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectPolicy {
    /// Whether TCS components require audit
    pub tcs_requires_audit: bool,
    /// Whether mechanical components require scan
    pub mechanical_requires_scan: bool,
    /// Whether git dependencies are allowed
    pub allow_git_dependencies: bool,
    /// Maximum transitive dependency depth
    pub max_transitive_depth: Option<usize>,
    /// Update policy for dependencies
    pub update_policy: UpdatePolicy,
    /// Drift detection policy
    pub drift_policy: DriftPolicy,
}

/// Project alerting configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectAlerting {
    /// Critical CVE alert recipients
    pub critical_cve_to: Vec<String>,
    /// High CVE alert recipients
    pub high_cve_to: Vec<String>,
    /// Medium CVE alert recipients
    pub medium_cve_to: Vec<String>,
    /// Low CVE alert recipients
    pub low_cve_to: Vec<String>,
    /// Drift detected alert recipients
    pub drift_detected_to: Vec<String>,
    /// Audit failure alert recipients
    pub audit_failure_to: Vec<String>,
    /// Verification failure alert recipients
    pub verification_failure_to: Vec<String>,
}

/// Project metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectMetadata {
    /// Project description
    pub description: Option<String>,
    /// Project version
    pub version: Option<String>,
    /// Project homepage
    pub homepage: Option<String>,
    /// Project documentation URL
    pub documentation: Option<String>,
    /// Project tags
    pub tags: Vec<String>,
    /// Project language
    pub language: Option<String>,
    /// Project license
    pub license: Option<String>,
    /// Additional properties
    pub properties: HashMap<String, serde_json::Value>,
}

/// Threat level for projects
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLevel {
    /// Critical threat level
    Critical,
    /// High threat level
    High,
    /// Medium threat level
    Medium,
    /// Low threat level
    Low,
}

/// Update policy for dependencies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdatePolicy {
    /// Automatic updates allowed
    Automatic,
    /// Manual approval required
    Manual,
    /// Scheduled updates only
    Scheduled { schedule: String },
    /// No updates allowed
    Locked,
}

/// Drift detection policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DriftPolicy {
    /// Alert on any drift
    AlertOnAny,
    /// Alert only on TCS drift
    AlertOnTcs,
    /// Alert only on high-priority drift
    AlertOnHighPriority,
    /// No alerts for drift
    None,
}

/// Project configuration file format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectConfigFile {
    /// Project configuration
    pub project: Project,
    /// Configuration file metadata
    pub metadata: ConfigFileMetadata,
}

/// Configuration file metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigFileMetadata {
    /// Configuration file version
    pub version: String,
    /// Configuration file format
    pub format: String,
    /// Creation timestamp
    pub created_at: String,
    /// Last modified timestamp
    pub modified_at: String,
    /// Configuration schema URL
    pub schema_url: Option<String>,
}

/// Project analysis result
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectAnalysis {
    /// Project information
    pub project: Project,
    /// Analysis timestamp
    pub analyzed_at: String,
    /// Total dependencies found
    pub total_dependencies: usize,
    /// TCS dependencies found
    pub tcs_dependencies: usize,
    /// Mechanical dependencies found
    pub mechanical_dependencies: usize,
    /// Git dependencies found
    pub git_dependencies: usize,
    /// Local dependencies found
    pub local_dependencies: usize,
    /// Analysis metadata
    pub metadata: AnalysisMetadata,
}

/// Analysis metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisMetadata {
    /// Tool versions used
    pub tool_versions: HashMap<String, String>,
    /// Analysis duration in milliseconds
    pub analysis_duration_ms: u64,
    /// Whether analysis was in offline mode
    pub offline_mode: bool,
    /// Analysis warnings
    pub warnings: Vec<AnalysisWarning>,
}

/// Analysis warning
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisWarning {
    /// Warning type
    pub warning_type: String,
    /// Warning message
    pub message: String,
    /// Warning severity
    pub severity: WarningSeverity,
    /// Affected component (if applicable)
    pub component: Option<String>,
}

/// Warning severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarningSeverity {
    /// Critical warning
    Critical,
    /// High warning
    High,
    /// Medium warning
    Medium,
    /// Low warning
    Low,
    /// Informational warning
    Info,
}

impl Project {
    /// Create new project with basic information
    pub fn new(id: String, name: String, ecosystem: String, root: PathBuf) -> Self {
        Self {
            id,
            name,
            repository: None,
            ecosystem,
            owner_email: None,
            paths: ProjectPaths::from_root(root),
            security: ProjectSecurity::default(),
            tcs: ProjectTcs::default(),
            policy: ProjectPolicy::default(),
            alerting: ProjectAlerting::default(),
            metadata: ProjectMetadata::default(),
        }
    }
    
    /// Get absolute path to lockfile
    pub fn lockfile_path(&self) -> PathBuf {
        self.paths.root.join(&self.paths.lockfile)
    }
    
    /// Get absolute path to manifest
    pub fn manifest_path(&self) -> PathBuf {
        self.paths.root.join(&self.paths.manifest)
    }
    
    /// Get absolute path to epochs directory
    pub fn epochs_path(&self) -> PathBuf {
        self.paths.root.join(&self.paths.epochs)
    }
    
    /// Get absolute path to SBOMs directory
    pub fn sboms_path(&self) -> PathBuf {
        self.paths.root.join(&self.paths.sboms)
    }
    
    /// Get absolute path to ADRs directory
    pub fn adrs_path(&self) -> PathBuf {
        self.paths.root.join(&self.paths.adrs)
    }
    
    /// Get absolute path to vendor directory
    pub fn vendor_path(&self) -> PathBuf {
        self.paths.root.join(&self.paths.vendor)
    }
    
    /// Get absolute path to config file
    pub fn config_path(&self) -> PathBuf {
        self.paths.root.join(&self.paths.config)
    }
    
    /// Check if project requires strict security
    pub fn requires_strict_security(&self) -> bool {
        matches!(self.security.threat_level, ThreatLevel::Critical | ThreatLevel::High)
    }
    
    /// Get allowed dependency depth
    pub fn max_dependency_depth(&self) -> usize {
        self.policy.max_transitive_depth.unwrap_or(10)
    }
    
    /// Check if git dependencies are allowed
    pub fn allows_git_dependencies(&self) -> bool {
        self.policy.allow_git_dependencies
    }
}

impl ProjectPaths {
    /// Create project paths from root directory
    pub fn from_root(root: PathBuf) -> Self {
        Self {
            root,
            lockfile: PathBuf::from("Cargo.lock"),
            manifest: PathBuf::from("Cargo.toml"),
            epochs: PathBuf::from("security/epochs"),
            sboms: PathBuf::from("security/sboms"),
            adrs: PathBuf::from("security/adrs"),
            vendor: PathBuf::from("vendor"),
            config: PathBuf::from("project.toml"),
        }
    }
    
    /// Validate that all paths are properly configured
    pub fn validate(&self) -> Result<(), String> {
        if !self.root.exists() {
            return Err(format!("Project root does not exist: {:?}", self.root));
        }
        
        if self.lockfile.as_os_str().is_empty() {
            return Err("Lockfile path cannot be empty".to_string());
        }
        
        if self.manifest.as_os_str().is_empty() {
            return Err("Manifest path cannot be empty".to_string());
        }
        
        Ok(())
    }
}

impl Default for ProjectSecurity {
    fn default() -> Self {
        Self {
            threat_level: ThreatLevel::Medium,
            compliance: Vec::new(),
            current_epoch: None,
            security_team: None,
        }
    }
}

impl Default for ProjectTcs {
    fn default() -> Self {
        Self {
            crypto: Vec::new(),
            auth: Vec::new(),
            serialization: Vec::new(),
            transport: Vec::new(),
            database: Vec::new(),
            random: Vec::new(),
            build_time_execution: Vec::new(),
            custom: HashMap::new(),
        }
    }
}

impl Default for ProjectPolicy {
    fn default() -> Self {
        Self {
            tcs_requires_audit: true,
            mechanical_requires_scan: true,
            allow_git_dependencies: false,
            max_transitive_depth: Some(10),
            update_policy: UpdatePolicy::Manual,
            drift_policy: DriftPolicy::AlertOnTcs,
        }
    }
}

impl Default for ProjectAlerting {
    fn default() -> Self {
        Self {
            critical_cve_to: Vec::new(),
            high_cve_to: Vec::new(),
            medium_cve_to: Vec::new(),
            low_cve_to: Vec::new(),
            drift_detected_to: Vec::new(),
            audit_failure_to: Vec::new(),
            verification_failure_to: Vec::new(),
        }
    }
}

impl Default for ProjectMetadata {
    fn default() -> Self {
        Self {
            description: None,
            version: None,
            homepage: None,
            documentation: None,
            tags: Vec::new(),
            language: None,
            license: None,
            properties: HashMap::new(),
        }
    }
}

impl ProjectAnalysis {
    /// Create new project analysis
    pub fn new(project: Project) -> Self {
        Self {
            project,
            analyzed_at: chrono::Utc::now().to_rfc3339(),
            total_dependencies: 0,
            tcs_dependencies: 0,
            mechanical_dependencies: 0,
            git_dependencies: 0,
            local_dependencies: 0,
            metadata: AnalysisMetadata::default(),
        }
    }
    
    /// Get dependency statistics
    pub fn dependency_stats(&self) -> DependencyStats {
        DependencyStats {
            total: self.total_dependencies,
            tcs: self.tcs_dependencies,
            mechanical: self.mechanical_dependencies,
            git: self.git_dependencies,
            local: self.local_dependencies,
        }
    }
    
    /// Add warning to analysis
    pub fn add_warning(&mut self, warning: AnalysisWarning) {
        self.metadata.warnings.push(warning);
    }
    
    /// Get critical warnings
    pub fn critical_warnings(&self) -> Vec<&AnalysisWarning> {
        self.metadata.warnings.iter()
            .filter(|w| w.severity == WarningSeverity::Critical)
            .collect()
    }
}

impl Default for ConfigFileMetadata {
    fn default() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            version: "1.0".to_string(),
            format: "toml".to_string(),
            created_at: now.clone(),
            modified_at: now,
            schema_url: Some("https://schemas.example.com/project-config/v1".to_string()),
        }
    }
}

impl Default for AnalysisMetadata {
    fn default() -> Self {
        Self {
            tool_versions: HashMap::new(),
            analysis_duration_ms: 0,
            offline_mode: false,
            warnings: Vec::new(),
        }
    }
}

impl AnalysisWarning {
    /// Create new analysis warning
    pub fn new(warning_type: String, message: String, severity: WarningSeverity) -> Self {
        Self {
            warning_type,
            message,
            severity,
            component: None,
        }
    }
    
    /// Create warning with component
    pub fn with_component(mut self, component: String) -> Self {
        self.component = Some(component);
        self
    }
}

/// Dependency statistics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DependencyStats {
    /// Total dependencies
    pub total: usize,
    /// TCS dependencies
    pub tcs: usize,
    /// Mechanical dependencies
    pub mechanical: usize,
    /// Git dependencies
    pub git: usize,
    /// Local dependencies
    pub local: usize,
}

impl DependencyStats {
    /// Get TCS percentage
    pub fn tcs_percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.tcs as f64 / self.total as f64) * 100.0
        }
    }
    
    /// Get mechanical percentage
    pub fn mechanical_percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.mechanical as f64 / self.total as f64) * 100.0
        }
    }
    
    /// Get git dependency percentage
    pub fn git_percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.git as f64 / self.total as f64) * 100.0
        }
    }
}
