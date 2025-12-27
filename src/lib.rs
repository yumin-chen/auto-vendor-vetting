//! Rust Ecosystem Adapter
//! 
//! A language-specific integration component of the Universal Supply-Chain Security System
//! that translates Rust-ecosystem dependency management and security artifacts into the
//! universal dependency model used by the Control Plane.
//! 
//! # Architecture Principles
//! 
//! 1. **Cargo.lock Authority**: Cargo.lock is the canonical source of dependency state
//! 2. **Determinism and Reproducibility**: Identical inputs produce identical outputs
//! 3. **Offline-first Operation**: Supports fully air-gapped execution
//! 4. **Policy Neutrality**: Adapter gathers facts; Control Plane evaluates policy
//! 5. **Universal Graph Integrity**: UDG remains language-agnostic
//! 
//! # Example Usage
//! 
//! ```rust
//! use rust_ecosystem_adapter::{RustAdapter, RustAdapterConfig};
//! 
//! let config = RustAdapterConfig::default();
//! let adapter = RustAdapter::new(config);
//! 
//! let project = Project::new("/path/to/rust/project")?;
//! let dependency_graph = adapter.parse_dependencies(&project).await?;
//! ```

pub mod adapter;
pub mod config;
pub mod error;
pub mod models;
pub mod utils;

pub use adapter::RustAdapter;
pub use config::RustAdapterConfig;
pub use error::{AdapterError, Result};
pub use models::{
    DependencyGraph, PackageNode, DependencyEdge, PackageSource,
    TcsCategory, Classification, ClassificationSignal, AuditReport,
    SbomFormat, VendorInfo, DriftReport, Project
};

/// Re-export common types for convenience
pub mod prelude {
    pub use crate::{
        RustAdapter, RustAdapterConfig, AdapterError, Result,
        DependencyGraph, PackageNode, TcsCategory, Classification,
        AuditReport, SbomFormat, VendorInfo, DriftReport, Project,
    };
}