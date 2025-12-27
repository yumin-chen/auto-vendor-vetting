//! Checksum calculation utilities
//! 
//! This module provides utilities for calculating
//! various types of checksums for integrity verification.

use crate::error::{AdapterError, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Checksum calculator for various algorithms
#[derive(Debug, Clone)]
pub struct ChecksumCalculator {
    /// Default algorithm to use
    default_algorithm: ChecksumAlgorithm,
}

/// Supported checksum algorithms
#[derive(Debug, Clone, PartialEq)]
pub enum ChecksumAlgorithm {
    /// SHA-256
    Sha256,
    /// SHA-512
    Sha512,
    /// MD5 (legacy, not recommended for security)
    Md5,
}

impl ChecksumCalculator {
    /// Create new checksum calculator
    pub fn new() -> Self {
        Self {
            default_algorithm: ChecksumAlgorithm::Sha256,
        }
    }
    
    /// Create checksum calculator with specific algorithm
    pub fn with_algorithm(algorithm: ChecksumAlgorithm) -> Self {
        Self {
            default_algorithm: algorithm,
        }
    }
    
    /// Calculate checksum for file
    pub fn calculate_file_checksum<P>(&self, path: P, algorithm: Option<ChecksumAlgorithm>) -> Result<String>
    where
        P: AsRef<Path>,
    {
        let algorithm = algorithm.unwrap_or_else(|| self.default_algorithm.clone());
        let path = path.as_ref();
        
        let content = fs::read(path)
            .map_err(|e| AdapterError::permission_denied(path, "reading file for checksum"))?;
        
        match algorithm {
            ChecksumAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&content);
                Ok(format!("{:x}", hasher.finalize()))
            },
            ChecksumAlgorithm::Sha512 => {
                use sha2::Sha512;
                let mut hasher = Sha512::new();
                hasher.update(&content);
                Ok(format!("{:x}", hasher.finalize()))
            },
            ChecksumAlgorithm::Md5 => {
                use md5::Md5;
                let mut hasher = Md5::new();
                hasher.update(&content);
                Ok(format!("{:x}", hasher.finalize()))
            },
        }
    }
    
    /// Calculate checksum for directory recursively
    pub fn calculate_directory_checksum<P>(&self, path: P, algorithm: Option<ChecksumAlgorithm>) -> Result<String>
    where
        P: AsRef<Path>,
    {
        let algorithm = algorithm.unwrap_or_else(|| self.default_algorithm.clone());
        let path = path.as_ref();
        
        let mut hasher = match algorithm {
            ChecksumAlgorithm::Sha256 => {
                let mut h = Sha256::new();
                // Update with directory path for deterministic ordering
                h.update(path.to_string_lossy().as_bytes());
                h
            },
            ChecksumAlgorithm::Sha512 => {
                use sha2::Sha512;
                let mut h = Sha512::new();
                h.update(path.to_string_lossy().as_bytes());
                h
            },
            ChecksumAlgorithm::Md5 => {
                use md5::Md5;
                let mut h = Md5::new();
                h.update(path.to_string_lossy().as_bytes());
                h
            },
        };
        
        // Walk directory and hash all files
        self.walk_and_hash_directory(path, &mut hasher)?;
        
        let checksum = match algorithm {
            ChecksumAlgorithm::Sha256 => {
                let h: Sha256 = hasher;
                format!("{:x}", h.finalize())
            },
            ChecksumAlgorithm::Sha512 => {
                use sha2::Sha512;
                let h: Sha512 = hasher;
                format!("{:x}", h.finalize())
            },
            ChecksumAlgorithm::Md5 => {
                use md5::Md5;
                let h: Md5 = hasher;
                format!("{:x}", h.finalize())
            },
        };
        
        Ok(checksum)
    }
    
    /// Verify file checksum
    pub fn verify_file_checksum<P>(&self, path: P, expected: &str, algorithm: Option<ChecksumAlgorithm>) -> Result<bool>
    where
        P: AsRef<Path>,
    {
        let actual = self.calculate_file_checksum(path, algorithm)?;
        Ok(actual == expected)
    }
    
    /// Walk directory and update hasher
    fn walk_and_hash_directory(&self, path: &Path, hasher: &mut dyn digest::Digest) -> Result<()> {
        let entries = fs::read_dir(path)
            .map_err(|e| AdapterError::permission_denied(path, "reading directory"))?;
        
        let mut file_paths = Vec::new();
        
        // Collect all file paths
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                file_paths.push(entry_path);
            } else if entry_path.is_dir() {
                // Recursively process subdirectories
                self.walk_and_hash_directory(entry_path, hasher)?;
            }
        }
        
        // Sort paths for deterministic ordering
        file_paths.sort();
        
        // Hash each file
        for file_path in file_paths {
            let content = fs::read(&file_path)
                .map_err(|e| AdapterError::permission_denied(&file_path, "reading file for checksum"))?;
            
            hasher.update(file_path.to_string_lossy().as_bytes());
            hasher.update(&content);
        }
        
        Ok(())
    }
}

impl Default for ChecksumCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_checksum_calculator_creation() {
        let calculator = ChecksumCalculator::new();
        assert_eq!(calculator.default_algorithm, ChecksumAlgorithm::Sha256);
        
        let calculator = ChecksumCalculator::with_algorithm(ChecksumAlgorithm::Md5);
        assert_eq!(calculator.default_algorithm, ChecksumAlgorithm::Md5);
    }
    
    #[test]
    fn test_file_checksum() -> Result<()> {
        let calculator = ChecksumCalculator::new();
        
        // Create temporary file
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(b"Hello, world!")?;
        temp_file.flush()?;
        
        // Calculate checksum
        let checksum = calculator.calculate_file_checksum(temp_file.path(), None)?;
        
        // Should be SHA-256 of "Hello, world!"
        let expected = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
        assert_eq!(checksum, expected);
        
        Ok(())
    }
    
    #[test]
    fn test_file_checksum_verification() -> Result<()> {
        let calculator = ChecksumCalculator::new();
        
        // Create temporary file
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(b"test content")?;
        temp_file.flush()?;
        
        // Calculate expected checksum
        let expected_checksum = calculator.calculate_file_checksum(temp_file.path(), None)?;
        
        // Verify correct checksum
        assert!(calculator.verify_file_checksum(temp_file.path(), &expected_checksum, None)?);
        
        // Verify incorrect checksum
        assert!(!calculator.verify_file_checksum(temp_file.path(), "invalid", None)?);
        
        Ok(())
    }
    
    #[test]
    fn test_directory_checksum() -> Result<()> {
        let calculator = ChecksumCalculator::new();
        
        let temp_dir = tempfile::tempdir()?;
        
        // Create test files
        let file1_path = temp_dir.path().join("file1.txt");
        let file2_path = temp_dir.path().join("file2.txt");
        
        fs::write(&file1_path, b"content1")?;
        fs::write(&file2_path, b"content2")?;
        
        // Calculate directory checksum
        let checksum = calculator.calculate_directory_checksum(temp_dir.path(), None)?;
        
        // Should be deterministic
        let checksum2 = calculator.calculate_directory_checksum(temp_dir.path(), None)?;
        assert_eq!(checksum, checksum2);
        
        // Different content should produce different checksum
        fs::write(&file1_path, b"different content")?;
        let checksum3 = calculator.calculate_directory_checksum(temp_dir.path(), None)?;
        assert_ne!(checksum, checksum3);
        
        Ok(())
    }
    
    #[test]
    fn test_different_algorithms() -> Result<()> {
        let sha256_calculator = ChecksumCalculator::with_algorithm(ChecksumAlgorithm::Sha256);
        let md5_calculator = ChecksumCalculator::with_algorithm(ChecksumAlgorithm::Md5);
        
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(b"test")?;
        temp_file.flush()?;
        
        let sha256_checksum = sha256_calculator.calculate_file_checksum(temp_file.path(), None)?;
        let md5_checksum = md5_calculator.calculate_file_checksum(temp_file.path(), None)?;
        
        // Should be different
        assert_ne!(sha256_checksum, md5_checksum);
        
        // SHA-256 should be 64 characters
        assert_eq!(sha256_checksum.len(), 64);
        
        // MD5 should be 32 characters
        assert_eq!(md5_checksum.len(), 32);
        
        Ok(())
    }
}
