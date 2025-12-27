//! Drift detection types and structures
//! 
//! This module defines types for detecting and reporting dependency drift
//! between epochs, including change classification and priority levels.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::dependency_graph::*;

/// Comprehensive drift detection report
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftReport {
    /// Epoch being compared against
    pub expected_epoch_id: String,
    /// Current analysis timestamp
    pub analysis_timestamp: String,
    /// Detected drift items
    pub drifts: Vec<DriftItem>,
    /// Drift summary statistics
    pub summary: DriftSummary,
    /// Impact assessment
    pub impact: DriftImpact,
}

/// Individual drift item detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftItem {
    /// Package name
    pub package_name: String,
    /// Previous version (if applicable)
    pub previous_version: Option<String>,
    /// Current version (if applicable)
    pub current_version: Option<String>,
    /// Previous source (if applicable)
    pub previous_source: Option<PackageSource>,
    /// Current source (if applicable)
    pub current_source: Option<PackageSource>,
    /// Type of change
    pub change_type: ChangeType,
    /// Drift priority based on classification
    pub priority: Priority,
    /// Package classification (TCS or Mechanical)
    pub classification: Classification,
    /// Whether this is a high-risk source change
    pub is_high_risk_source_change: bool,
    /// Additional details about the drift
    pub details: Option<String>,
}

/// Type of change detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChangeType {
    /// New dependency added
    Addition,
    /// Existing dependency removed
    Removal,
    /// Dependency version changed
    VersionChange,
    /// Dependency source changed (e.g., registry → git)
    SourceChange,
    /// Multiple changes occurred
    MultipleChanges,
}

/// Priority level for drift items
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Critical priority (TCS dependencies, source changes)
    Critical,
    /// High priority (important changes)
    High,
    /// Medium priority (routine changes)
    Medium,
    /// Low priority (minor changes)
    Low,
}

/// Drift summary statistics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftSummary {
    /// Total number of drift items
    pub total_drifts: usize,
    /// Number of additions
    pub additions: usize,
    /// Number of removals
    pub removals: usize,
    /// Number of version changes
    pub version_changes: usize,
    /// Number of source changes
    pub source_changes: usize,
    /// Critical priority drifts
    pub critical_priority: usize,
    /// High priority drifts
    pub high_priority: usize,
    /// TCS component drifts
    pub tcs_drifts: usize,
    /// Mechanical component drifts
    pub mechanical_drifts: usize,
}

/// Impact assessment for detected drift
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftImpact {
    /// Overall impact level
    pub overall_impact: ImpactLevel,
    /// Security impact assessment
    pub security_impact: SecurityImpact,
    /// Operational impact assessment
    pub operational_impact: OperationalImpact,
    /// Compliance impact assessment
    pub compliance_impact: ComplianceImpact,
    /// Recommended actions
    pub recommendations: Vec<String>,
    /// Timeline for addressing drift
    pub recommended_timeline: RecommendedTimeline,
}

/// Overall impact level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImpactLevel {
    /// No significant impact
    Minimal,
    /// Minor impact that should be addressed
    Minor,
    /// Moderate impact requiring attention
    Moderate,
    /// Major impact requiring immediate attention
    Major,
    /// Critical impact requiring immediate action
    Critical,
}

/// Security impact assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityImpact {
    /// Whether security posture is affected
    pub affected: bool,
    /// Number of TCS components affected
    pub tcs_components_affected: usize,
    /// High-risk source changes detected
    pub high_risk_source_changes: usize,
    /// Potential attack vectors introduced
    pub attack_vectors: Vec<String>,
    /// Security recommendations
    pub security_recommendations: Vec<String>,
}

/// Operational impact assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OperationalImpact {
    /// Whether build process is affected
    pub build_affected: bool,
    /// Whether runtime behavior is affected
    pub runtime_affected: bool,
    /// Whether compatibility is affected
    pub compatibility_affected: bool,
    /// Performance impact assessment
    pub performance_impact: PerformanceImpact,
    /// Operational recommendations
    pub operational_recommendations: Vec<String>,
}

/// Performance impact assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PerformanceImpact {
    /// No performance impact expected
    None,
    /// Minor performance changes possible
    Minor,
    /// Moderate performance changes expected
    Moderate,
    /// Significant performance impact expected
    Significant,
    /// Performance degradation expected
    Degradation,
}

/// Compliance impact assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceImpact {
    /// Whether compliance requirements are affected
    pub compliance_affected: bool,
    /// Affected compliance frameworks
    pub affected_frameworks: Vec<String>,
    /// License compliance issues
    pub license_issues: Vec<String>,
    /// Audit trail implications
    pub audit_implications: Vec<String>,
    /// Compliance recommendations
    pub compliance_recommendations: Vec<String>,
}

/// Recommended timeline for addressing drift
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecommendedTimeline {
    /// Address immediately (critical issues)
    Immediate,
    /// Address within 24 hours (high priority)
    Within24Hours,
    /// Address within week (medium priority)
    WithinWeek,
    /// Address within month (low priority)
    WithinMonth,
    /// Address in next planning cycle
    NextPlanningCycle,
}

/// Epoch comparison configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftDetectionConfig {
    /// Whether to ignore version updates for Mechanical components
    pub ignore_mechanical_version_updates: bool,
    /// Whether to flag source changes as high risk by default
    pub flag_source_changes_high_risk: bool,
    /// Custom priority overrides for specific packages
    pub priority_overrides: HashMap<String, Priority>,
    /// Whether to include dev dependencies in drift detection
    pub include_dev_dependencies: bool,
    /// Whether to include build dependencies in drift detection
    pub include_build_dependencies: bool,
    /// Maximum transitive depth to analyze
    pub max_transitive_depth: Option<usize>,
}

/// Drift detection context
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftDetectionContext {
    /// Project being analyzed
    pub project_id: String,
    /// Expected epoch
    pub expected_epoch: String,
    /// Current analysis timestamp
    pub analysis_timestamp: String,
    /// Detection configuration used
    pub config: DriftDetectionConfig,
    /// Analysis metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl DriftReport {
    /// Create new drift report
    pub fn new(expected_epoch_id: String) -> Self {
        Self {
            expected_epoch_id,
            analysis_timestamp: chrono::Utc::now().to_rfc3339(),
            drifts: Vec::new(),
            summary: DriftSummary::default(),
            impact: DriftImpact::default(),
        }
    }
    
    /// Add drift item to report
    pub fn add_drift(&mut self, drift: DriftItem) {
        self.drifts.push(drift);
    }
    
    /// Calculate summary statistics
    pub fn calculate_summary(&mut self) {
        let mut summary = DriftSummary::default();
        
        for drift in &self.drifts {
            summary.total_drifts += 1;
            
            match drift.change_type {
                ChangeType::Addition => summary.additions += 1,
                ChangeType::Removal => summary.removals += 1,
                ChangeType::VersionChange => summary.version_changes += 1,
                ChangeType::SourceChange => summary.source_changes += 1,
                ChangeType::MultipleChanges => {
                    summary.version_changes += 1;
                    summary.source_changes += 1;
                },
            }
            
            match drift.priority {
                Priority::Critical => summary.critical_priority += 1,
                Priority::High => summary.high_priority += 1,
                _ => {}
            }
            
            match drift.classification {
                Classification::TCS { .. } => summary.tcs_drifts += 1,
                Classification::Mechanical { .. } | Classification::Unknown => summary.mechanical_drifts += 1,
            }
        }
        
        self.summary = summary;
    }
    
    /// Assess impact of detected drift
    pub fn assess_impact(&mut self) {
        self.impact = DriftImpact::from_drifts(&self.drifts, &self.summary);
    }
    
    /// Get critical drift items
    pub fn critical_drifts(&self) -> Vec<&DriftItem> {
        self.drifts.iter()
            .filter(|d| d.priority == Priority::Critical)
            .collect()
    }
    
    /// Get TCS drift items
    pub fn tcs_drifts(&self) -> Vec<&DriftItem> {
        self.drifts.iter()
            .filter(|d| matches!(d.classification, Classification::TCS { .. }))
            .collect()
    }
    
    /// Get source change drifts
    pub fn source_change_drifts(&self) -> Vec<&DriftItem> {
        self.drifts.iter()
            .filter(|d| matches!(d.change_type, ChangeType::SourceChange | ChangeType::MultipleChanges))
            .collect()
    }
    
    /// Check if report has critical issues
    pub fn has_critical_issues(&self) -> bool {
        !self.critical_drifts().is_empty() ||
        self.impact.overall_impact == ImpactLevel::Critical
    }
}

impl Default for DriftSummary {
    fn default() -> Self {
        Self {
            total_drifts: 0,
            additions: 0,
            removals: 0,
            version_changes: 0,
            source_changes: 0,
            critical_priority: 0,
            high_priority: 0,
            tcs_drifts: 0,
            mechanical_drifts: 0,
        }
    }
}

impl Default for DriftImpact {
    fn default() -> Self {
        Self {
            overall_impact: ImpactLevel::Minimal,
            security_impact: SecurityImpact::default(),
            operational_impact: OperationalImpact::default(),
            compliance_impact: ComplianceImpact::default(),
            recommendations: Vec::new(),
            recommended_timeline: RecommendedTimeline::NextPlanningCycle,
        }
    }
}

impl DriftItem {
    /// Create new drift item
    pub fn new(package_name: String, change_type: ChangeType, priority: Priority) -> Self {
        Self {
            package_name,
            previous_version: None,
            current_version: None,
            previous_source: None,
            current_source: None,
            change_type,
            priority,
            classification: Classification::Unknown,
            is_high_risk_source_change: false,
            details: None,
        }
    }
    
    /// Set version information
    pub fn with_versions(mut self, previous: Option<String>, current: Option<String>) -> Self {
        self.previous_version = previous;
        self.current_version = current;
        self
    }
    
    /// Set source information
    pub fn with_sources(mut self, previous: Option<PackageSource>, current: Option<PackageSource>) -> Self {
        self.previous_source = previous;
        self.current_source = current;
        self
    }
    
    /// Set classification
    pub fn with_classification(mut self, classification: Classification) -> Self {
        self.classification = classification;
        self
    }
    
    /// Mark as high-risk source change
    pub fn as_high_risk_source_change(mut self) -> Self {
        self.is_high_risk_source_change = true;
        self
    }
    
    /// Add details
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
    
    /// Check if this is a TCS drift
    pub fn is_tcs_drift(&self) -> bool {
        matches!(self.classification, Classification::TCS { .. })
    }
    
    /// Check if this affects security
    pub fn affects_security(&self) -> bool {
        self.is_tcs_drift() || self.is_high_risk_source_change
    }
}

impl DriftImpact {
    /// Create impact assessment from drift items
    pub fn from_drifts(drifts: &[DriftItem], summary: &DriftSummary) -> Self {
        let overall_impact = Self::assess_overall_impact(summary);
        let security_impact = SecurityImpact::from_drifts(drifts);
        let operational_impact = OperationalImpact::from_drifts(drifts);
        let compliance_impact = ComplianceImpact::from_drifts(drifts);
        let recommended_timeline = Self::recommend_timeline(&overall_impact, &security_impact);
        let recommendations = Self::generate_recommendations(&overall_impact, &security_impact, &operational_impact);
        
        Self {
            overall_impact,
            security_impact,
            operational_impact,
            compliance_impact,
            recommendations,
            recommended_timeline,
        }
    }
    
    /// Assess overall impact level
    fn assess_overall_impact(summary: &DriftSummary) -> ImpactLevel {
        if summary.critical_priority > 0 {
            return ImpactLevel::Critical;
        }
        
        if summary.high_priority > 0 || summary.source_changes > 0 {
            return ImpactLevel::Major;
        }
        
        if summary.tcs_drifts > 0 {
            return ImpactLevel::Moderate;
        }
        
        if summary.total_drifts > 10 {
            return ImpactLevel::Minor;
        }
        
        ImpactLevel::Minimal
    }
    
    /// Recommend timeline based on impact
    fn recommend_timeline(overall_impact: &ImpactLevel, security_impact: &SecurityImpact) -> RecommendedTimeline {
        match overall_impact {
            ImpactLevel::Critical => RecommendedTimeline::Immediate,
            ImpactLevel::Major => {
                if security_impact.affected {
                    RecommendedTimeline::Within24Hours
                } else {
                    RecommendedTimeline::WithinWeek
                }
            },
            ImpactLevel::Moderate => RecommendedTimeline::WithinWeek,
            ImpactLevel::Minor => RecommendedTimeline::WithinMonth,
            ImpactLevel::Minimal => RecommendedTimeline::NextPlanningCycle,
        }
    }
    
    /// Generate recommendations based on impacts
    fn generate_recommendations(
        overall_impact: &ImpactLevel,
        security_impact: &SecurityImpact,
        operational_impact: &OperationalImpact,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if overall_impact == &ImpactLevel::Critical || overall_impact == &ImpactLevel::Major {
            recommendations.push("Immediate review and approval required".to_string());
        }
        
        if security_impact.affected {
            recommendations.extend(security_impact.security_recommendations.clone());
        }
        
        if operational_impact.build_affected {
            recommendations.push("Test build process thoroughly".to_string());
        }
        
        if operational_impact.runtime_affected {
            recommendations.push("Perform comprehensive runtime testing".to_string());
        }
        
        recommendations
    }
}

impl Default for SecurityImpact {
    fn default() -> Self {
        Self {
            affected: false,
            tcs_components_affected: 0,
            high_risk_source_changes: 0,
            attack_vectors: Vec::new(),
            security_recommendations: Vec::new(),
        }
    }
}

impl SecurityImpact {
    /// Create security impact from drift items
    pub fn from_drifts(drifts: &[DriftItem]) -> Self {
        let tcs_components_affected = drifts.iter()
            .filter(|d| d.is_tcs_drift())
            .count();
        
        let high_risk_source_changes = drifts.iter()
            .filter(|d| d.is_high_risk_source_change)
            .count();
        
        let affected = tcs_components_affected > 0 || high_risk_source_changes > 0;
        
        let mut attack_vectors = Vec::new();
        if high_risk_source_changes > 0 {
            attack_vectors.push("Supply chain compromise".to_string());
        }
        if tcs_components_affected > 0 {
            attack_vectors.push("TCS component integrity".to_string());
        }
        
        let mut security_recommendations = Vec::new();
        if tcs_components_affected > 0 {
            security_recommendations.push("Audit all TCS component changes".to_string());
            security_recommendations.push("Verify TCS component integrity".to_string());
        }
        if high_risk_source_changes > 0 {
            security_recommendations.push("Investigate source changes for potential compromise".to_string());
            security_recommendations.push("Consider rollback to previous version".to_string());
        }
        
        Self {
            affected,
            tcs_components_affected,
            high_risk_source_changes,
            attack_vectors,
            security_recommendations,
        }
    }
}

impl Default for OperationalImpact {
    fn default() -> Self {
        Self {
            build_affected: false,
            runtime_affected: false,
            compatibility_affected: false,
            performance_impact: PerformanceImpact::None,
            operational_recommendations: Vec::new(),
        }
    }
}

impl OperationalImpact {
    /// Create operational impact from drift items
    pub fn from_drifts(drifts: &[DriftItem]) -> Self {
        let version_changes = drifts.iter().any(|d| 
            matches!(d.change_type, ChangeType::VersionChange | ChangeType::MultipleChanges)
        );
        
        let source_changes = drifts.iter().any(|d| 
            matches!(d.change_type, ChangeType::SourceChange | ChangeType::MultipleChanges)
        );
        
        let build_affected = version_changes || source_changes;
        let runtime_affected = version_changes;
        let compatibility_affected = version_changes;
        
        let performance_impact = if drifts.len() > 20 {
            PerformanceImpact::Significant
        } else if drifts.len() > 10 {
            PerformanceImpact::Moderate
        } else if drifts.len() > 5 {
            PerformanceImpact::Minor
        } else {
            PerformanceImpact::None
        };
        
        let mut operational_recommendations = Vec::new();
        if build_affected {
            operational_recommendations.push("Update build configurations if needed".to_string());
        }
        if runtime_affected {
            operational_recommendations.push("Test compatibility with existing systems".to_string());
        }
        if compatibility_affected {
            operational_recommendations.push("Perform integration testing".to_string());
        }
        
        Self {
            build_affected,
            runtime_affected,
            compatibility_affected,
            performance_impact,
            operational_recommendations,
        }
    }
}

impl Default for ComplianceImpact {
    fn default() -> Self {
        Self {
            compliance_affected: false,
            affected_frameworks: Vec::new(),
            license_issues: Vec::new(),
            audit_implications: Vec::new(),
            compliance_recommendations: Vec::new(),
        }
    }
}

impl ComplianceImpact {
    /// Create compliance impact from drift items
    pub fn from_drifts(_drifts: &[DriftItem]) -> Self {
        // This would be implemented based on specific compliance requirements
        // For now, return default implementation
        Self {
            compliance_affected: false,
            affected_frameworks: Vec::new(),
            license_issues: Vec::new(),
            audit_implications: Vec::new(),
            compliance_recommendations: Vec::new(),
        }
    }
}

impl Default for DriftDetectionConfig {
    fn default() -> Self {
        Self {
            ignore_mechanical_version_updates: false,
            flag_source_changes_high_risk: true,
            priority_overrides: HashMap::new(),
            include_dev_dependencies: false,
            include_build_dependencies: true,
            max_transitive_depth: Some(10),
        }
    }
}
