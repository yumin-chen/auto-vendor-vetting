## Requirement 4: Dependency Vendoring

**User Story:**
As a build engineer, I want to vendor Rust dependencies locally, so that I can ensure reproducible builds and mitigate supply-chain attacks.

### Acceptance Criteria

1. WHEN vendoring dependencies, THE Adapter SHALL execute `cargo vendor`
2. WHEN vendoring completes, THE Adapter SHALL verify all dependencies from `Cargo.lock` are present
3. WHEN verifying vendored dependencies, THE Adapter SHALL validate checksums against `Cargo.lock`
4. WHEN vendoring git dependencies, THE Adapter SHALL ensure the exact commit hash is vendored
5. WHEN vendoring fails, THE Adapter SHALL report the specific dependencies that failed
6. WHEN vendoring completes, THE Adapter SHALL compute a cryptographic digest of the vendor directory
7. WHEN vendor verification detects mismatches, THE Adapter SHALL report missing files or checksum violations