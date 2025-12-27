//! Audit-related types and structures
//! 
//! This module defines types for security audit operations,
//! including results from cargo-audit and cargo-vet tools.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::dependency_graph::*;

/// Comprehensive audit report from security tools
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditReport {
    /// Raw output from cargo-audit (if available)
    pub raw_cargo_audit: Option<String>,
    /// Raw output from cargo-vet (if available)
    pub raw_cargo_vet: Option<String>,
    /// Execution metadata
    pub execution_metadata: AuditExecutionMetadata,
    /// Whether audit was run in offline mode
    pub offline_mode: bool,
    /// Processed audit findings
    pub findings: Vec<AuditFinding>,
}

/// Audit execution metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditExecutionMetadata {
    /// Audit timestamp
    pub timestamp: String,
    /// Tool versions used
    pub tool_versions: HashMap<String, String>,
    /// Execution duration
    pub execution_duration: u64, // in milliseconds
    /// Exit codes from tools
    pub exit_codes: HashMap<String, i32>,
    /// Whether offline mode was used
    pub offline_mode: bool,
}

/// Individual audit finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditFinding {
    /// Finding identifier (CVE, RUSTSEC, GHSA)
    pub id: String,
    /// Package name affected
    pub package_name: String,
    /// Affected versions
    pub affected_versions: String,
    /// Patched versions
    pub patched_versions: Vec<String>,
    /// Severity level
    pub severity: Severity,
    /// CVSS score (if available)
    pub cvss_score: Option<f64>,
    /// Finding description
    pub description: String,
    /// Reference URLs
    pub references: Vec<String>,
    /// Finding source (cargo-audit, cargo-vet, etc.)
    pub source: String,
    /// Whether this affects TCS components
    pub affects_tcs: bool,
}

/// Severity levels for security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Critical severity
    Critical,
    /// High severity
    High,
    /// Medium severity
    Medium,
    /// Low severity
    Low,
    /// Informational
    Info,
}

/// Audit proof for cargo-vet
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditProof {
    /// Audit method used
    pub method: AuditMethod,
    /// Auditor identity
    pub auditor: String,
    /// Audit date
    pub date: String,
    /// Audit signature (if available)
    pub signature: Option<String>,
    /// Audit criteria
    pub criteria: Option<String>,
    /// Additional notes
    pub notes: Option<String>,
}

/// Audit record that can be shared across projects
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    /// Package name
    pub package_name: String,
    /// Package version
    pub package_version: String,
    /// Ecosystem
    pub ecosystem: String,
    /// Audit method
    pub method: AuditMethod,
    /// Audit criteria
    pub criteria: String,
    /// Auditor identity
    pub auditor: String,
    /// Audit date
    pub audit_date: String,
    /// Additional notes
    pub notes: Option<String>,
    /// Auditor signature
    pub signature: Option<String>,
    /// Source project that created this audit
    pub source_project: Option<String>,
}

/// Supply chain report
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SupplyChainReport {
    /// Overall supply chain status
    pub status: SupplyChainStatus,
    /// Audit findings
    pub audit_findings: Vec<AuditFinding>,
    /// Audit proofs
    pub audit_proofs: HashMap<String, AuditProof>,
    /// Unaudited TCS components
    pub unaudited_tcs: Vec<String>,
    /// Report generation timestamp
    pub generated_at: String,
    /// Report metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Supply chain status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SupplyChainStatus {
    /// All components audited and secure
    Secure,
    /// Some components have issues but are acceptable
    Warning,
    /// Critical issues found
    Critical,
    /// Insufficient audit coverage
    Insufficient,
    /// Unknown status
    Unknown,
}

/// Cargo-audit advisory structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoAuditAdvisory {
    /// Advisory ID
    pub id: String,
    /// Package name
    pub package: CargoAuditPackage,
    /// Advisory metadata
    pub metadata: CargoAuditMetadata,
    /// Affected versions
    pub versions: CargoAuditVersions,
    /// Advisory description
    pub description: String,
    /// Unaffected versions
    pub unaffected: Vec<String>,
    /// Patched versions
    pub patched: Vec<String>,
    /// Related URLs
    pub url: Option<String>,
}

/// Package information in cargo-audit
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoAuditPackage {
    /// Package name
    pub name: String,
    /// Repository URL
    pub repo: Option<String>,
}

/// Advisory metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoAuditMetadata {
    /// Date published
    pub date: String,
    /// Advisory categories
    pub categories: Vec<String>,
    /// Keywords
    pub keywords: Vec<String>,
    /// CVSS score
    pub cvss: Option<String>,
}

/// Version information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoAuditVersions {
    /// Range of affected versions
    pub range: String,
}

/// Cargo-vet audit data structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoVetAudit {
    /// Audit definitions
    pub audits: HashMap<String, CargoVetAuditEntry>,
    /// Import sources
    pub imports: Vec<CargoVetImport>,
    /// Audit configuration
    pub criteria: HashMap<String, CargoVetCriteria>,
}

/// Individual cargo-vet audit entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoVetAuditEntry {
    /// Audit criteria
    pub criteria: Vec<String>,
    /// Auditor information
    pub who: String,
    /// Audit date range
    pub start: String,
    /// End date (if applicable)
    pub end: Option<String>,
    /// Notes
    pub notes: Option<String>,
}

/// Cargo-vet import definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoVetImport {
    /// URL of import source
    pub url: String,
    /// Required criteria for imports
    pub required_criteria: Vec<String>,
    /// Audit configuration for imports
    pub criteria: HashMap<String, CargoVetCriteria>,
}

/// Cargo-vet criteria definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CargoVetCriteria {
    /// Criteria description
    pub description: String,
    /// Whether this is a safe-to-deploy criteria
    pub safe_to_deploy: bool,
}

impl AuditReport {
    /// Create new empty audit report
    pub fn new() -> Self {
        Self {
            raw_cargo_audit: None,
            raw_cargo_vet: None,
            execution_metadata: AuditExecutionMetadata::default(),
            offline_mode: false,
            findings: Vec::new(),
        }
    }
    
    /// Add audit finding
    pub fn add_finding(&mut self, finding: AuditFinding) {
        self.findings.push(finding);
    }
    
    /// Get findings by severity
    pub fn findings_by_severity(&self, severity: Severity) -> Vec<&AuditFinding> {
        self.findings.iter()
            .filter(|f| f.severity == severity)
            .collect()
    }
    
    /// Get findings that affect TCS components
    pub fn tcs_findings(&self) -> Vec<&AuditFinding> {
        self.findings.iter()
            .filter(|f| f.affects_tcs)
            .collect()
    }
    
    /// Get critical findings
    pub fn critical_findings(&self) -> Vec<&AuditFinding> {
        self.findings_by_severity(Severity::Critical)
    }
    
    /// Check if audit has critical findings
    pub fn has_critical_findings(&self) -> bool {
        !self.critical_findings().is_empty()
    }
    
    /// Get overall severity level
    pub fn overall_severity(&self) -> Severity {
        if self.has_critical_findings() {
            return Severity::Critical;
        }
        
        if !self.findings_by_severity(Severity::High).is_empty() {
            return Severity::High;
        }
        
        if !self.findings_by_severity(Severity::Medium).is_empty() {
            return Severity::Medium;
        }
        
        if !self.findings_by_severity(Severity::Low).is_empty() {
            return Severity::Low;
        }
        
        Severity::Info
    }
}

impl Default for AuditExecutionMetadata {
    fn default() -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool_versions: HashMap::new(),
            execution_duration: 0,
            exit_codes: HashMap::new(),
            offline_mode: false,
        }
    }
}

impl AuditFinding {
    /// Create new audit finding
    pub fn new(
        id: String,
        package_name: String,
        affected_versions: String,
        severity: Severity,
        description: String,
    ) -> Self {
        Self {
            id,
            package_name,
            affected_versions,
            patched_versions: Vec::new(),
            severity,
            cvss_score: None,
            description,
            references: Vec::new(),
            source: "unknown".to_string(),
            affects_tcs: false,
        }
    }
    
    /// Set TCS impact
    pub fn affects_tcs(mut self, affects_tcs: bool) -> Self {
        self.affects_tcs = affects_tcs;
        self
    }
    
    /// Set source
    pub fn with_source(mut self, source: String) -> Self {
        self.source = source;
        self
    }
    
    /// Add patched version
    pub fn add_patched_version(mut self, version: String) -> Self {
        self.patched_versions.push(version);
        self
    }
    
    /// Set CVSS score
    pub fn with_cvss_score(mut self, score: f64) -> Self {
        self.cvss_score = Some(score);
        self
    }
    
    /// Add reference URL
    pub fn add_reference(mut self, url: String) -> Self {
        self.references.push(url);
        self
    }
}

impl Severity {
    /// Convert severity to numeric value for comparison
    pub fn to_numeric(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }
    
    /// Get severity color for display
    pub fn color(&self) -> &str {
        match self {
            Severity::Critical => "red",
            Severity::High => "orange",
            Severity::Medium => "yellow",
            Severity::Low => "blue",
            Severity::Info => "gray",
        }
    }
}

impl SupplyChainReport {
    /// Create new supply chain report
    pub fn new() -> Self {
        Self {
            status: SupplyChainStatus::Unknown,
            audit_findings: Vec::new(),
            audit_proofs: HashMap::new(),
            unaudited_tcs: Vec::new(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            metadata: HashMap::new(),
        }
    }
    
    /// Determine overall status based on findings
    pub fn determine_status(&mut self) {
        self.status = if self.audit_findings.iter().any(|f| f.severity == Severity::Critical) {
            SupplyChainStatus::Critical
        } else if !self.unaudited_tcs.is_empty() {
            SupplyChainStatus::Insufficient
        } else if self.audit_findings.iter().any(|f| f.severity == Severity::High) {
            SupplyChainStatus::Warning
        } else {
            SupplyChainStatus::Secure
        };
    }
    
    /// Add audit proof
    pub fn add_audit_proof(&mut self, package_id: String, proof: AuditProof) {
        self.audit_proofs.insert(package_id, proof);
    }
    
    /// Add unaudited TCS component
    pub fn add_unaudited_tcs(&mut self, package_name: String) {
        self.unaudited_tcs.push(package_name);
    }
}

impl AuditRecord {
    /// Create new audit record
    pub fn new(
        package_name: String,
        package_version: String,
        ecosystem: String,
        method: AuditMethod,
        criteria: String,
        auditor: String,
    ) -> Self {
        Self {
            package_name,
            package_version,
            ecosystem,
            method,
            criteria,
            auditor,
            audit_date: chrono::Utc::now().to_rfc3339(),
            notes: None,
            signature: None,
            source_project: None,
        }
    }
    
    /// Set notes
    pub fn with_notes(mut self, notes: String) -> Self {
        self.notes = Some(notes);
        self
    }
    
    /// Set signature
    pub fn with_signature(mut self, signature: String) -> Self {
        self.signature = Some(signature);
        self
    }
    
    /// Set source project
    pub fn with_source_project(mut self, source_project: String) -> Self {
        self.source_project = Some(source_project);
        self
    }
}