### Requirement 5: SBOM Generation

**User Story:** As a compliance officer, I want to generate Software Bills of Materials for Rust projects, so that I can track all components and their licenses for regulatory compliance.

#### Acceptance Criteria

1. WHEN generating an SBOM, THE Adapter SHALL create a standardized SPDX or CycloneDX format document
2. WHEN including dependencies in the SBOM, THE Adapter SHALL record package name, version, source location, and license information
3. WHEN license information is available in Cargo.toml, THE Adapter SHALL extract and include it in the SBOM
4. WHEN dependencies have multiple licenses, THE Adapter SHALL record all applicable licenses with proper SPDX expressions
5. WHEN the SBOM is generated, THE Adapter SHALL include metadata about the generation tool, timestamp, and project information
6. WHEN git dependencies are present, THE Adapter SHALL include repository URL and commit hash in the SBOM
