//! Main entry point for Rust Ecosystem Adapter CLI
//! 
//! This module provides the command-line interface for the adapter,
//! allowing users to run various operations from the command line.

use clap::{Parser, Subcommand};
use rust_ecosystem_adapter::{RustAdapter, RustAdapterConfig, Project};
use std::path::PathBuf;

/// Rust Ecosystem Adapter CLI
#[derive(Parser, Debug)]
#[command(name = "rust-adapter")]
#[command(about = "Rust ecosystem adapter for supply-chain security")]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "rust-adapter.toml")]
    config: PathBuf,
    
    /// Enable offline mode
    #[arg(short, long)]
    offline: bool,
    
    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    /// Command to run
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Parse dependencies from Cargo.lock
    Parse {
        /// Project path
        #[arg(short, long)]
        project: PathBuf,
    },
    /// Run security audit
    Audit {
        /// Project path
        #[arg(short, long)]
        project: PathBuf,
    },
    /// Generate SBOM
    Sbom {
        /// Project path
        #[arg(short, long)]
        project: PathBuf,
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// SBOM format
        #[arg(short, long, default_value = "spdx")]
        format: String,
    },
    /// Vendor dependencies
    Vendor {
        /// Project path
        #[arg(short, long)]
        project: PathBuf,
        /// Output directory
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify vendored dependencies
    VerifyVendor {
        /// Project path
        #[arg(short, long)]
        project: PathBuf,
        /// Vendored directory path
        #[arg(short, long)]
        vendored: PathBuf,
    },
    /// Detect dependency drift
    Drift {
        /// Project path
        #[arg(short, long)]
        project: PathBuf,
        /// Expected epoch ID
        #[arg(short, long)]
        epoch: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Initialize logging
    init_logging(&cli.log_level);
    
    // Load configuration
    let config = load_config(&cli.config).await?;
    
    // Create adapter
    let adapter = RustAdapter::new(config);
    
    // Run command
    match cli.command {
        Commands::Parse { project } => {
            cmd_parse(&adapter, &project).await?;
        },
        Commands::Audit { project } => {
            cmd_audit(&adapter, &project).await?;
        },
        Commands::Sbom { project, output, format } => {
            cmd_sbom(&adapter, &project, &output, &format).await?;
        },
        Commands::Vendor { project, output } => {
            cmd_vendor(&adapter, &project, &output).await?;
        },
        Commands::VerifyVendor { project, vendored } => {
            cmd_verify_vendor(&adapter, &project, &vendored).await?;
        },
        Commands::Drift { project, epoch } => {
            cmd_drift(&adapter, &project, &epoch).await?;
        },
    }
    
    Ok(())
}

/// Initialize logging
fn init_logging(level: &str) {
    use tracing_subscriber::{EnvFilter, fmt};
    
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));
    
    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(false)
        .compact()
        .init();
}

/// Load configuration from file
async fn load_config(config_path: &PathBuf) -> Result<RustAdapterConfig, Box<dyn std::error::Error>> {
    if config_path.exists() {
        RustAdapterConfig::load_from_file(config_path)
            .map_err(|e| format!("Failed to load config: {}", e))?
    } else {
        eprintln!("Config file {:?} not found, using defaults", config_path);
        RustAdapterConfig::default()
    }
    
    Ok(config)
}

/// Parse dependencies command
async fn cmd_parse(adapter: &RustAdapter, project: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Parsing dependencies from project: {:?}", project);
    
    let project_obj = Project::new(
        "cli-project".to_string(),
        "CLI Project".to_string(),
        "rust".to_string(),
        project.clone(),
    );
    
    let dependency_graph = adapter.parse_dependencies(&project_obj).await
        .map_err(|e| format!("Failed to parse dependencies: {}", e))?;
    
    println!("Successfully parsed {} dependencies", dependency_graph.root_packages.len());
    
    for package in &dependency_graph.root_packages {
        println!("  {} {} ({})", package.name, package.version, 
            match &package.classification {
                crate::models::dependency_graph::Classification::TCS { category, .. } => 
                    format!("TCS: {:?}", category),
                crate::models::dependency_graph::Classification::Mechanical { .. } => 
                    "Mechanical".to_string(),
                crate::models::dependency_graph::Classification::Unknown => 
                    "Unknown".to_string(),
            });
    }
    
    Ok(())
}

/// Run audit command
async fn cmd_audit(adapter: &RustAdapter, project: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running security audit for project: {:?}", project);
    
    let project_obj = Project::new(
        "cli-project".to_string(),
        "CLI Project".to_string(),
        "rust".to_string(),
        project.clone(),
    );
    
    let audit_report = adapter.run_audit(&project_obj).await
        .map_err(|e| format!("Failed to run audit: {}", e))?;
    
    println!("Audit completed successfully");
    
    if let Some(cargo_audit_output) = &audit_report.raw_cargo_audit {
        println!("Cargo-audit output available ({} bytes)", cargo_audit_output.len());
    }
    
    if let Some(cargo_vet_output) = &audit_report.raw_cargo_vet {
        println!("Cargo-vet output available ({} bytes)", cargo_vet_output.len());
    }
    
    println!("Total findings: {}", audit_report.findings.len());
    
    Ok(())
}

/// Generate SBOM command
async fn cmd_sbom(
    adapter: &RustAdapter,
    project: &PathBuf,
    output: &Option<PathBuf>,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating {} SBOM for project: {:?}", format, project);
    
    let project_obj = Project::new(
        "cli-project".to_string(),
        "CLI Project".to_string(),
        "rust".to_string(),
        project.clone(),
    );
    
    let sbom = adapter.generate_sbom(&project_obj).await
        .map_err(|e| format!("Failed to generate SBOM: {}", e))?;
    
    let output_path = output.as_ref().unwrap_or(&PathBuf::from(format!("sbom.{}", format)));
    
    let sbom_content = match sbom {
        crate::models::Sbom::Spdx(doc) => serde_json::to_string_pretty(&doc)?,
        crate::models::Sbom::CycloneDx(doc) => serde_json::to_string_pretty(&doc)?,
    };
    
    std::fs::write(output_path, sbom_content)
        .map_err(|e| format!("Failed to write SBOM: {}", e))?;
    
    println!("SBOM generated successfully: {:?}", output_path);
    
    Ok(())
}

/// Vendor dependencies command
async fn cmd_vendor(
    adapter: &RustAdapter,
    project: &PathBuf,
    output: &Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = output.as_ref().unwrap_or(&PathBuf::from("vendor"));
    
    println!("Vendoring dependencies from project: {:?}", project);
    println!("Output directory: {:?}", output_dir);
    
    let project_obj = Project::new(
        "cli-project".to_string(),
        "CLI Project".to_string(),
        "rust".to_string(),
        project.clone(),
    );
    
    adapter.vendor_dependencies(&project_obj, output_dir).await
        .map_err(|e| format!("Failed to vendor dependencies: {}", e))?;
    
    println!("Dependencies vendored successfully");
    
    Ok(())
}

/// Verify vendored dependencies command
async fn cmd_verify_vendor(
    adapter: &RustAdapter,
    project: &PathBuf,
    vendored: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Verifying vendored dependencies: {:?}", vendored);
    
    let project_obj = Project::new(
        "cli-project".to_string(),
        "CLI Project".to_string(),
        "rust".to_string(),
        project.clone(),
    );
    
    adapter.verify_vendored(&project_obj, vendored).await
        .map_err(|e| format!("Failed to verify vendored dependencies: {}", e))?;
    
    println!("Vendored dependencies verified successfully");
    
    Ok(())
}

/// Detect drift command
async fn cmd_drift(
    adapter: &RustAdapter,
    project: &PathBuf,
    epoch: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Detecting drift against epoch: {}", epoch);
    
    let project_obj = Project::new(
        "cli-project".to_string(),
        "CLI Project".to_string(),
        "rust".to_string(),
        project.clone(),
    );
    
    // Parse current dependencies first
    let dependency_graph = adapter.parse_dependencies(&project_obj).await
        .map_err(|e| format!("Failed to parse dependencies: {}", e))?;
    
    // Create a mock epoch for demonstration
    let expected_epoch = crate::models::drift_types::Epoch {
        id: epoch.to_string(),
        analysis_timestamp: chrono::Utc::now().to_rfc3339(),
        drifts: vec![],
        summary: crate::models::drift_types::DriftSummary::default(),
        impact: crate::models::drift_types::DriftImpact::default(),
    };
    
    let drift_report = adapter.detect_drift(&expected_epoch, &dependency_graph).await
        .map_err(|e| format!("Failed to detect drift: {}", e))?;
    
    println!("Drift detection completed");
    println!("Total drifts detected: {}", drift_report.drifts.len());
    
    for drift in &drift_report.drifts {
        println!("  {} - {}: {:?}", drift.package_name, drift.change_type, drift.priority);
    }
    
    Ok(())
}
