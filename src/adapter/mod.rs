//! Core adapter implementation module
//! 
//! This module contains the main RustAdapter implementation
//! and supporting components for the Rust ecosystem adapter.

pub mod rust_adapter;
pub mod dependency_parser;
pub mod tcs_classifier;
pub mod audit_runner;
pub mod vendor_manager;
pub mod sbom_generator;
pub mod drift_detector;

// Re-export main adapter
pub use rust_adapter::RustAdapter;