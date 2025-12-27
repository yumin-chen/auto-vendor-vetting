---
Status: Draft
Date: 2025-12-27
Authors: [Security, Supply-Chain, DevOps, Rust Platform]
Reviewers: [Security, Supply-Chain, DevOps, Rust Platform]
Requirements:
  Driving This Decision:
    - R1: Vendoring must preserve all dependencies specified in `Cargo.lock`. (CP-2, CP-11)
    - R2: Checksum mismatches must **invalidate the entire epoch** to prevent undetected supply-chain compromise. (CP-11)
    - R3: Vendoring must function in **offline mode** without network access. (CP-5, CP-8)
    - R4: Git dependencies must be vendored at the **exact commit** specified in `Cargo.lock`. (CP-12)
    - R5: Vendoring errors must provide **clear, structured reporting** of missing or mismatched dependencies. (CP-13)
Related Correctness Properties:
  - CP-5: Offline Safety                       
  - CP-6: Vendoring Integrity                  
  - CP-11: Git Dependency Vendoring Verification
  - CP-12: Vendoring Error Reporting            
Related ADRs:
  - ADR-001: Cargo.lock as Canonical Source of Dependency Identity
  - ADR-002: Deterministic Trust-Critical Software (TCS) Classification
  - ADR-004: SBOM Generation Without Vulnerability Scoring
---

## Context

Vendoring dependencies is critical for supply-chain security, reproducibility, and offline operation. Rust projects may depend on crates from multiple sources: **registry**, **git**, or **local paths**. Ensuring **integrity**, **completeness**, and **offline availability** of dependencies is essential for:

* Air-gapped environments
* Deterministic builds and reproducible SBOMs
* Integrity verification and epoch validation
* Supply-chain drift detection

Current approaches often rely on network access or partial verification, which violates offline-first and high-assurance principles.


### Alternatives Considered

1. **Online-Only Vendoring:**

   * Pros: Always fetches latest dependencies.
   * Cons: Cannot guarantee reproducibility or offline operation; introduces supply-chain risk.

2. **Partial Offline with Cached Registry:**

   * Pros: Some offline support.
   * Cons: Incomplete verification; git dependencies may fail; cannot guarantee epoch integrity.

3. **Fully Offline, Lockfile-Driven Vendoring (Chosen)**:

   * Pros: Deterministic, reproducible, network-independent, fully verifiable.
   * Cons: Requires pre-fetched artifacts for initial setup; requires checksum validation.

**Decision:** Adopt a **fully offline, Cargo.lock-driven vendoring strategy** with checksum validation and epoch integrity enforcement. Git dependencies are vendored exactly at the specified commit, and local path dependencies are validated for existence and completeness.

## Decision

* **Offline-First Operation:**

  * All vendoring operations honor `offline_mode=true` and avoid network I/O.
  * Uses pre-fetched registries, local git mirrors, and advisory databases.
  * Missing artifacts cause deterministic failure with clear guidance.

* **Checksum-Based Integrity:**

  * Verify all dependencies from `Cargo.lock` against cryptographic checksums.
  * Any mismatch **invalidates the entire epoch** (preventing silent supply-chain compromise).

* **Git Dependency Handling:**

  * Extract repository URL, commit hash, branch/tag from `Cargo.lock`.
  * Ensure vendored crate matches exact commit.
  * Validation failures produce structured error reports.

* **Local Path Dependencies:**

  * Validate existence and completeness of referenced paths.
  * Include relative path metadata in UDG annotations.

* **Structured Error Reporting:**

  * Provide clear feedback on missing, mismatched, or inaccessible dependencies.
  * Include context (dependency name, expected vs. actual checksum, source).

* **.cargo/config.toml Generation:**

  * For offline builds, generate `.cargo/config.toml` pointing to vendored sources.
  * Ensures reproducibility across build environments.

* **Cryptographic Digest:**

  * Compute cryptographic digest of vendor directory for epoch identification and drift detection.

### Consequences

**Positive:**

* Guarantees reproducible, deterministic dependency vendoring.
* Enables offline operation in air-gapped environments.
* Provides clear audit trail and verification of all vendored dependencies.
* Supports epoch validation and drift detection.

**Negative / Considerations:**

* Initial setup requires pre-fetching all necessary artifacts.
* Errors in vendoring require manual remediation or automated re-vendoring.
* Requires careful maintenance of git mirrors and cached registries for offline support.

### References

* Cargo Vendor: [https://doc.rust-lang.org/cargo/commands/cargo-vendor.html](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)
* RustSec Advisory Database: [https://rustsec.org](https://rustsec.org)

---
