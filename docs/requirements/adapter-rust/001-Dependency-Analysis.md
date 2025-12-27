## Requirement 1: Dependency Analysis

**User Story:**
As a security engineer, I want to analyze Rust project dependencies, so that I can understand the complete dependency graph and identify security-critical components.

### Acceptance Criteria

1. WHEN provided with `Cargo.toml` and `Cargo.lock`, THE Adapter SHALL parse all direct and transitive dependencies
2. WHEN parsing dependencies, THE Adapter SHALL extract:

   * package name
   * version
   * source (registry, git, local path)
   * checksum (from `Cargo.lock`)
3. WHEN building the dependency graph, THE Adapter SHALL record dependency relationships and directionality
4. WHEN encountering git dependencies, THE Adapter SHALL extract repository URL, commit hash, and branch or tag
5. WHEN encountering local path dependencies, THE Adapter SHALL record the relative path and validate existence
6. WHEN parsing dependencies, THE Adapter SHALL record dependency kind:

   * normal
   * build
   * dev
7. WHEN dependency metadata conflicts across sources, THE Adapter SHALL treat `Cargo.lock` as authoritative
