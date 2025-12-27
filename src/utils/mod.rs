//! Utility modules for Rust Ecosystem Adapter
//! 
//! This module provides utility functions and helpers
//! used across the adapter implementation.

pub mod command_runner;
pub mod checksum;

// Re-export commonly used utilities
pub use command_runner::CommandRunner;
pub use checksum::ChecksumCalculator;
