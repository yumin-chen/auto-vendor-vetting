# Correctness Properties 

## CP-1: Deterministic Output

**Description:**
For any **identical inputs**—including source tree, Cargo.lock, configuration, and environment—the Rust Ecosystem Adapter **must produce byte-identical outputs** across repeated runs. Outputs include:

* Universal Dependency Graph (UDG) JSON
* SBOMs (SPDX / CycloneDX)
* Audit logs
* Vendoring artifacts (checksums, digests)

**Rationale:**
Determinism ensures reproducibility, simplifies audit and drift detection, and guarantees that supply-chain analyses are repeatable and verifiable.

**Validation Methods:**

* Property-based tests (e.g., `proptest`) across ≥100 iterations.
* Compare serialized outputs for exact byte identity.
* Test in both online and offline modes to ensure environmental invariance.

---

## CP-2: Cargo.lock Authority

**Description:**
Cargo.lock is the **canonical source of truth** for dependency identity. For any dependency represented in the UDG:

* It **must exist in Cargo.lock**
* No dependency **may appear in the UDG** unless it is explicitly listed in Cargo.lock

**Rationale:**
This prevents inconsistencies between Cargo.lock, cargo metadata, and vendored dependencies. All dependency analysis, classification, and SBOM generation rely on this authority.

**Validation Methods:**

* Parse Cargo.lock and cross-validate against the UDG.
* Emit warnings if metadata or registry queries suggest divergent dependencies.
* Property-based tests to enforce strict lockfile precedence.

---

## CP-3: Identity Integrity

**Description:**
Each dependency node in the UDG **must preserve exact identity information** as recorded in Cargo.lock:

* Name
* Version
* Source (registry, git, path)
* Checksum

**Rationale:**
Preserves the integrity of the dependency graph and prevents silent substitution or tampering of artifacts. This is critical for reproducibility, auditability, and supply-chain security.

**Validation Methods:**

* Validate that every node in UDG matches Cargo.lock entries.
* Checksum verification against Cargo.lock’s recorded hash.
* Property-based tests with generated Cargo.lock variations.

---

## CP-4: Git Dependency Extraction

**Description:**
For any Rust project containing **git-sourced dependencies**, the adapter **must extract and record**:

* Repository URL
* Commit hash
* Branch or tag information (if specified)

**Rationale:**
Git dependencies can drift if not pinned. Accurate extraction ensures deterministic builds, auditability, and proper vendoring.

**Validation Methods:**

* Parse `[package].source` fields from Cargo.lock for git URLs.
* Verify that extracted commit hash matches Cargo.lock.
* Include in UDG annotations and SBOM metadata.

---

## CP-5: Local Path Dependency Validation

**Description:**
For any **local path dependencies**, the adapter **must**:

* Record the relative path in metadata
* Validate that the referenced path exists on the filesystem
* Include the path in UDG annotations

**Rationale:**
Local path dependencies may not be versioned or checksum-protected, so explicit validation prevents missing or broken references in builds, vendoring, or SBOMs.

**Validation Methods:**

* Walk filesystem paths and check existence.
* Cross-validate with Cargo.lock `path` entries.
* Fail deterministically if missing or inaccessible.

---

## CP-6: Vendoring Integrity

**Description:**
Vendoring operations **must guarantee full integrity**:

* All dependencies from Cargo.lock are present in the vendored directory
* All checksums **match** Cargo.lock
* **Any mismatch invalidates the entire epoch** to prevent unnoticed supply-chain compromise
* Git dependencies are vendored at the **exact commit** specified

**Rationale:**
Ensures offline, reproducible builds and strong supply-chain security guarantees. Detects tampering or drift proactively.

**Validation Methods:**

* Verify vendor directory contents against Cargo.lock entries
* Compute cryptographic digest of vendored directory
* Use property-based tests to simulate checksum mismatches and missing dependencies
* Structured error reporting for any failures

--

## CP-7: Custom TCS Configuration Override

**Description:**
For any project with **custom TCS categories or patterns** configured, the adapter **must apply project-specific classifications**:

* Explicit overrides take **highest precedence** over default rules
* Custom patterns are applied deterministically
* Classifications remain auditable with explicit signals

**Rationale:**
Allows projects to tailor Trust-Critical Software (TCS) classification to their domain requirements while preserving explainability and compliance.

**Validation Methods:**

* Property-based tests with combinations of explicit overrides and pattern rules
* Confirm that overrides supersede default classification
* Ensure classification signals are attached for every crate

---

## CP-8: Offline Safety

**Description:**
All operations **must respect offline mode**:

* No network I/O is performed when `offline_mode = true`
* All operations rely solely on **local artifacts** (vendored dependencies, cached advisories)
* Missing artifacts result in deterministic failure with clear error messages

**Rationale:**
Supports air-gapped environments and ensures reproducibility without external dependencies.

**Validation Methods:**

* Disable network and run full workflow
* Assert that no remote fetches are attempted
* Verify errors are deterministic and descriptive

---

## CP-9: Audit Tool Output Preservation

**Description:**
Audit operations **must capture external tool outputs verbatim**:

* cargo-audit and cargo-vet outputs are preserved without scoring, prioritization, or suppression
* Outputs are emitted as separate artifacts

**Rationale:**
Separates fact collection from policy evaluation, ensuring the Control Plane makes all security decisions.

**Validation Methods:**

* Execute audit tools with mocked and real outputs
* Compare captured output to raw tool output
* Validate no modification or filtering occurs

---

## CP-10: Audit Error Handling

**Description:**
For any audit operation failure:

* Structured error information is returned
* Stable error codes are provided
* Actionable guidance is included (retry instructions, offline mode guidance)

**Rationale:**
Ensures that automation and human operators can respond consistently to audit tool failures.

**Validation Methods:**

* Simulate tool failures (timeouts, missing tools, invalid Cargo.lock)
* Verify structured error object contains code, context, and suggestions
* Property-based tests for consistent error reporting

---

## CP-11: Vendoring Integrity

**Description:**
Vendoring operations **must ensure full integrity**:

* All dependencies from Cargo.lock are present in the vendored directory
* Checksums are validated against Cargo.lock
* Any checksum mismatch **invalidates the entire epoch**
* Cryptographic digest of the vendor directory is computed

**Rationale:**
Guarantees reproducible, secure builds and prevents supply-chain tampering.

**Validation Methods:**

* Verify all dependencies exist in the vendored directory
* Validate checksums against Cargo.lock
* Property-based tests simulating missing or corrupted dependencies

---

## CP-12: Vendoring Error Reporting

**Description:**
For any vendoring operation that fails:

* Errors clearly indicate **which dependencies failed** and **why**
* Structured reporting is provided with exit codes and context
* Deterministic failure prevents partial or inconsistent vendored state

**Rationale:**
Provides actionable feedback to developers and automation pipelines while maintaining integrity and reproducibility.

**Validation Methods:**

* Simulate failures such as missing dependencies, checksum mismatches, and permission errors
* Confirm that error reports include affected packages and detailed guidance
* Property-based tests to cover edge cases

---