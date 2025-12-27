//! Data models for Rust Ecosystem Adapter
//! 
//! This module defines the core data structures used throughout the adapter,
//! including the universal dependency graph, Rust-specific types, and
//! various result types for different operations.

pub mod dependency_graph;
pub mod cargo_types;
pub mod audit_types;
pub mod vendor_types;
pub mod sbom_types;
pub mod drift_types;
pub mod config_types;
pub mod project_types;

// Re-export commonly used types
pub use dependency_graph::*;
pub use cargo_types::*;
pub use audit_types::*;
pub use vendor_types::*;
pub use sbom_types::*;
pub use drift_types::*;
pub use config_types::*;
pub use project_types::*;