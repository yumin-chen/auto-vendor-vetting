//! TCS (Trust-Critical Software) classifier for Rust dependencies
//! 
//! This module implements deterministic, multi-signal classification
//! of Rust dependencies into TCS or Mechanical categories.

use crate::models::*;
use crate::error::Result;
use async_trait::async_trait;

/// TCS classifier implementation
#[derive(Debug, Clone)]
pub struct TcsClassifier {
    /// Classifier configuration
    config: TcsClassifierConfig,
    /// Whether classifier is ready
    ready: bool,
}

/// Configuration for TCS classifier
#[derive(Debug, Clone)]
pub struct TcsClassifierConfig {
    /// Whether to classify proc-macros as TCS
    pub classify_proc_macros: bool,
    /// Whether to classify build dependencies as TCS
    pub classify_build_deps: bool,
    /// Default category for unclassified packages
    pub default_category: MechanicalCategory,
    /// Classification confidence threshold
    pub confidence_threshold: f64,
}

impl TcsClassifier {
    /// Create new TCS classifier with configuration
    pub fn new(config: &RustAdapterConfig) -> Self {
        Self {
            config: TcsClassifierConfig {
                classify_proc_macros: config.classification_config.classify_proc_macros,
                classify_build_deps: config.classification_config.classify_build_deps,
                default_category: config.classification_config.default_category.clone(),
                confidence_threshold: config.classification_config.confidence_threshold,
            },
            ready: true,
        }
    }
    
    /// Check if classifier is ready
    pub fn is_ready(&self) -> bool {
        self.ready
    }
    
    /// Classify a single package
    pub async fn classify_package(&self, package: &CargoPackage) -> Result<ClassificationResult> {
        let mut signals = Vec::new();
        
        // 1. Check explicit overrides (highest priority)
        if let Some(override_category) = self.check_explicit_overrides(&package.name) {
            signals.push(ClassificationSignal::ExplicitOverride(package.name.clone()));
            return Ok(ClassificationResult::tcs(override_category, signals));
        }
        
        // 2. Check dependency role
        if self.config.classify_proc_macros && package.is_proc_macro {
            signals.push(ClassificationSignal::ProcMacroUsage);
            return Ok(ClassificationResult::tcs(TcsCategory::BuildTimeExecution, signals));
        }
        
        // 3. Apply deterministic pattern matching
        for pattern in &self.get_default_patterns() {
            if pattern.matches(&package.name) {
                signals.push(ClassificationSignal::NamePattern(pattern.regex.clone()));
                return Ok(ClassificationResult::tcs(pattern.category.clone(), signals));
            }
        }
        
        // 4. Default to Mechanical
        signals.push(ClassificationSignal::DependencyKind(CargoDependencyKind::Normal));
        Ok(ClassificationResult::mechanical(signals))
    }
    
    /// Check for explicit overrides
    fn check_explicit_overrides(&self, package_name: &str) -> Option<TcsCategory> {
        // This would check configuration for explicit overrides
        // For now, return None (no overrides)
        None
    }
    
    /// Get default TCS classification patterns
    fn get_default_patterns(&self) -> Vec<TcsPattern> {
        vec![
            // Cryptography patterns
            TcsPattern::new(
                "crypto-sha2".to_string(),
                r".*sha2.*".to_string(),
                TcsCategory::Cryptography,
                "SHA-2 cryptographic functions".to_string(),
            ),
            TcsPattern::new(
                "crypto-aes".to_string(),
                r".*aes.*".to_string(),
                TcsCategory::Cryptography,
                "AES cryptographic functions".to_string(),
            ),
            TcsPattern::new(
                "crypto-ring".to_string(),
                r"ring".to_string(),
                TcsCategory::Cryptography,
                "Ring cryptographic library".to_string(),
            ),
            
            // Authentication patterns
            TcsPattern::new(
                "auth-jwt".to_string(),
                r".*jwt.*".to_string(),
                TcsCategory::Authentication,
                "JWT token handling".to_string(),
            ),
            TcsPattern::new(
                "auth-oauth".to_string(),
                r".*oauth.*".to_string(),
                TcsCategory::Authentication,
                "OAuth authentication".to_string(),
            ),
            
            // Serialization patterns
            TcsPattern::new(
                "serde-core".to_string(),
                r"serde".to_string(),
                TcsCategory::Serialization,
                "Serde serialization framework".to_string(),
            ),
            TcsPattern::new(
                "serialization-toml".to_string(),
                r".*toml.*".to_string(),
                TcsCategory::Serialization,
                "TOML serialization".to_string(),
            ),
            
            // Transport patterns
            TcsPattern::new(
                "transport-tokio".to_string(),
                r"tokio".to_string(),
                TcsCategory::Transport,
                "Tokio async runtime".to_string(),
            ),
            TcsPattern::new(
                "transport-hyper".to_string(),
                r"hyper".to_string(),
                TcsCategory::Transport,
                "HTTP client/server library".to_string(),
            ),
            
            // Database patterns
            TcsPattern::new(
                "database-diesel".to_string(),
                r".*diesel.*".to_string(),
                TcsCategory::Database,
                "Diesel ORM".to_string(),
            ),
            TcsPattern::new(
                "database-sqlx".to_string(),
                r".*sqlx.*".to_string(),
                TcsCategory::Database,
                "SQLx async SQL toolkit".to_string(),
            ),
            
            // Random patterns
            TcsPattern::new(
                "random-rand".to_string(),
                r"rand".to_string(),
                TcsCategory::Random,
                "Random number generation".to_string(),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RustAdapterConfig;
    
    #[test]
    fn test_classifier_creation() {
        let config = RustAdapterConfig::default();
        let classifier = TcsClassifier::new(&config);
        
        assert!(classifier.is_ready());
        assert!(classifier.config.classify_proc_macros);
    }
    
    #[tokio::test]
    async fn test_crypto_classification() {
        let config = RustAdapterConfig::default();
        let classifier = TcsClassifier::new(&config);
        
        let crypto_package = CargoPackage {
            name: "sha2".to_string(),
            version: "0.10.0".to_string(),
            source: CargoSource::Registry {
                registry: "crates.io".to_string(),
                checksum: "test-checksum".to_string(),
            },
            dependencies: vec![],
            proc_macro: false,
            features: vec![],
            target_dependencies: std::collections::HashMap::new(),
        };
        
        let result = classifier.classify_package(&crypto_package).await.unwrap();
        assert!(result.is_tcs());
        assert_eq!(result.tcs_category(), Some(TcsCategory::Cryptography));
    }
    
    #[tokio::test]
    async fn test_proc_macro_classification() {
        let config = RustAdapterConfig::default();
        let classifier = TcsClassifier::new(&config);
        
        let proc_macro_package = CargoPackage {
            name: "my-proc-macro".to_string(),
            version: "1.0.0".to_string(),
            source: CargoSource::Registry {
                registry: "crates.io".to_string(),
                checksum: "test-checksum".to_string(),
            },
            dependencies: vec![],
            proc_macro: true,
            features: vec![],
            target_dependencies: std::collections::HashMap::new(),
        };
        
        let result = classifier.classify_package(&proc_macro_package).await.unwrap();
        assert!(result.is_tcs());
        assert_eq!(result.tcs_category(), Some(TcsCategory::BuildTimeExecution));
    }
    
    #[tokio::test]
    async fn test_mechanical_classification() {
        let config = RustAdapterConfig::default();
        let classifier = TcsClassifier::new(&config);
        
        let mechanical_package = CargoPackage {
            name: "ordinary-utils".to_string(),
            version: "1.0.0".to_string(),
            source: CargoSource::Registry {
                registry: "crates.io".to_string(),
                checksum: "test-checksum".to_string(),
            },
            dependencies: vec![],
            proc_macro: false,
            features: vec![],
            target_dependencies: std::collections::HashMap::new(),
        };
        
        let result = classifier.classify_package(&mechanical_package).await.unwrap();
        assert!(!result.is_tcs());
    }
}
