//! Security audit runner for Rust projects
//! 
//! This module integrates with cargo-audit and cargo-vet
//! to provide comprehensive security auditing capabilities.

use crate::models::*;
use crate::error::Result;
use async_trait::async_trait;
use std::process::Command;

/// Audit runner implementation
#[derive(Debug, Clone)]
pub struct AuditRunner {
    /// Runner configuration
    config: AuditRunnerConfig,
    /// Whether runner is ready
    ready: bool,
}

/// Configuration for audit runner
#[derive(Debug, Clone)]
pub struct AuditRunnerConfig {
    /// Audit timeout in seconds
    pub audit_timeout: u64,
    /// Whether to run cargo-audit
    pub run_cargo_audit: bool,
    /// Whether to run cargo-vet
    pub run_cargo_vet: bool,
    /// Whether to cache results
    pub cache_results: bool,
    /// Advisory database path
    pub advisory_db_path: Option<std::path::PathBuf>,
}

impl AuditRunner {
    /// Create new audit runner with configuration
    pub fn new(config: &RustAdapterConfig) -> Self {
        Self {
            config: AuditRunnerConfig {
                audit_timeout: config.audit_config.audit_timeout,
                run_cargo_audit: config.audit_config.run_cargo_audit,
                run_cargo_vet: config.audit_config.run_cargo_vet,
                cache_results: config.audit_config.cache_results,
                advisory_db_path: config.audit_config.advisory_db_path.clone(),
            },
            ready: true,
        }
    }
    
    /// Check if runner is ready
    pub fn is_ready(&self) -> bool {
        self.ready
    }
    
    /// Run comprehensive security audit
    pub async fn run_comprehensive_audit(&self, project: &Project) -> Result<AuditReport> {
        let mut report = AuditReport::new();
        report.offline_mode = project.requires_strict_security();
        
        // Run cargo-audit if enabled
        if self.config.run_cargo_audit {
            if let Ok(audit_output) = self.run_cargo_audit(project).await {
                report.raw_cargo_audit = Some(audit_output);
            }
        }
        
        // Run cargo-vet if enabled
        if self.config.run_cargo_vet {
            if let Ok(vet_output) = self.run_cargo_vet(project).await {
                report.raw_cargo_vet = Some(vet_output);
            }
        }
        
        // Parse findings from outputs
        if let Some(ref audit_output) = report.raw_cargo_audit {
            self.parse_audit_findings(audit_output, &mut report);
        }
        
        Ok(report)
    }
    
    /// Run cargo-audit
    async fn run_cargo_audit(&self, project: &Project) -> Result<String> {
        let output = Command::new("cargo")
            .args(&["audit", "--json"])
            .current_dir(&project.paths.root)
            .output()
            .map_err(|_| crate::AdapterError::tool_not_found("cargo-audit"))?;
        
        if !output.status.success() {
            return Err(crate::AdapterError::ToolExecutionFailed {
                tool: "cargo-audit".to_string(),
                exit_code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                source: anyhow::anyhow!("cargo-audit execution failed"),
            });
        }
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
    
    /// Run cargo-vet
    async fn run_cargo_vet(&self, project: &Project) -> Result<String> {
        let output = Command::new("cargo")
            .args(&["vet", "dump"])
            .current_dir(&project.paths.root)
            .output()
            .map_err(|_| crate::AdapterError::tool_not_found("cargo-vet"))?;
        
        if !output.status.success() {
            return Err(crate::AdapterError::ToolExecutionFailed {
                tool: "cargo-vet".to_string(),
                exit_code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                source: anyhow::anyhow!("cargo-vet execution failed"),
            });
        }
        
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
    
    /// Parse audit findings from cargo-audit output
    fn parse_audit_findings(&self, audit_output: &str, report: &mut AuditReport) {
        // Parse JSON output from cargo-audit
        if let Ok(audit_data) = serde_json::from_str::<serde_json::Value>(audit_output) {
            if let Some(vulnerabilities) = audit_data.get("vulnerabilities").and_then(|v| v.as_array()) {
                for vuln in vulnerabilities {
                    if let Some(finding) = self.parse_vulnerability(vuln) {
                        report.add_finding(finding);
                    }
                }
            }
        }
    }
    
    /// Parse individual vulnerability
    fn parse_vulnerability(&self, vuln: &serde_json::Value) -> Option<AuditFinding> {
        let id = vuln.get("id")?.as_str()?;
        let package_name = vuln.get("package")?.as_str()?;
        let severity_str = vuln.get("severity")?.as_str()?;
        let severity = match severity_str {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };
        
        let description = vuln.get("description")?.as_str().unwrap_or("").to_string();
        
        Some(AuditFinding::new(
            id.to_string(),
            package_name.to_string(),
            "unknown".to_string(), // Version info would need more parsing
            severity,
            description,
        ).with_source("cargo-audit".to_string()))
    }
}

impl Default for AuditRunnerConfig {
    fn default() -> Self {
        Self {
            audit_timeout: 300,
            run_cargo_audit: true,
            run_cargo_vet: true,
            cache_results: true,
            advisory_db_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RustAdapterConfig;
    
    #[test]
    fn test_audit_runner_creation() {
        let config = RustAdapterConfig::default();
        let runner = AuditRunner::new(&config);
        
        assert!(runner.is_ready());
        assert!(runner.config.run_cargo_audit);
        assert!(runner.config.run_cargo_vet);
    }
    
    #[tokio::test]
    async fn test_audit_runner_config() {
        let config = RustAdapterConfig::default();
        let runner = AuditRunner::new(&config);
        
        assert_eq!(runner.config.audit_timeout, 300);
        assert!(runner.config.cache_results);
    }
}
