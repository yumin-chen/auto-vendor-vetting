---
Status: Draft
Date: 2025-12-27
Authors: [Security, Supply-Chain, DevOps]
Reviewers: [Security, Supply-Chain, DevOps]        
Requirements:
  Driving This Decision:
    - R1: All dependency analysis must produce deterministic outputs across runs. (CP-1)
    - R2: Only dependencies present in Cargo.lock are included in the Universal Dependency Graph (CP-2, CP-3).
    - R3: Vendoring and offline builds must faithfully reproduce Cargo.lock state. (CP-6)
    - R4: Git and local path dependencies must be verifiable and tracked with exact commit hashes or paths. (CP-4, CP-5)
Related Correctness Properties:
  - CP-1: Deterministic Output             
  - CP-2: Cargo.lock Authority             
  - CP-3: Identity Integrity               
  - CP-4: Git Dependency Extraction        
  - CP-5: Local Path Dependency Validation 
  - CP-6: Vendoring Integrity
Related ADRs:
  - ADR-002: TCS Classification Deterministic Heuristics
  - ADR-003: Offline-First Vendor Management
  - ADR-004: SBOM Generation Without Vulnerability Scoring
---

# ADR-001: Adoption of Cargo.lock as Canonical Source of Dependency Identity

## Context

In the Rust ecosystem, `Cargo.toml` declares dependencies while `Cargo.lock` pins specific versions and resolves transitive dependency graphs. In supply-chain security systems, deterministic and reproducible dependency resolution is critical to prevent drift, supply-chain attacks, and inconsistencies in audits or SBOMs.

Existing Rust analysis tools (`cargo metadata`, `cargo-audit`, `cargo-vet`) provide useful information but can diverge from the authoritative dependency state represented in `Cargo.lock`. To guarantee deterministic, auditable, and policy-neutral operations across multiple Rust projects, a canonical source of dependency identity is required.

### Alternatives Considered

1. **Cargo.toml as canonical source:**

   * Pros: Declarative, human-readable.
   * Cons: Does not pin exact transitive versions; non-deterministic across builds; violates reproducibility principle.

2. **`cargo metadata` as canonical source:**

   * Pros: Provides enriched dependency information including features and dependency kinds.
   * Cons: Advisory-only; may diverge from Cargo.lock; not deterministic if lockfile is outdated.

3. **Combined approach (Cargo.lock + metadata enrichment):**

   * Pros: Cargo.lock remains authoritative; metadata used for optional enrichment.
   * Cons: Requires explicit offline support and validation against Cargo.lock.

**Decision:** Cargo.lock SHALL be treated as the canonical source of dependency identity. All other tools (Cargo.toml, cargo metadata) are advisory and used only for optional enrichment when operating in online mode or as specified by configuration.

## Decision

* **Canonical Authority:** `Cargo.lock` is the source of truth for all Rust dependency identity in the Universal Supply-Chain Security System.
* **Deterministic Graph Construction:** UDG nodes SHALL preserve exact name, version, source, and checksum from Cargo.lock.
* **Enrichment:** Optional metadata from `cargo metadata` can be used to annotate dependency kinds, features, and workspace information without overriding Cargo.lock authority.
* **Offline Compliance:** All operations (dependency parsing, vendoring, SBOM generation) must validate against Cargo.lock to guarantee offline reproducibility.
* **Git/Path Dependencies:** For git and local path dependencies, repository URLs, commit hashes, branch/tag, or relative paths SHALL be extracted and validated against Cargo.lock entries.

### Consequences

* **Positive:**

  * Ensures deterministic outputs (CP-1)
  * Guarantees identity integrity (CP-3)
  * Enables verifiable audits and reproducible SBOMs (CP-2, CP-15)
  * Supports offline-first operation (CP-5)

* **Negative / Considerations:**

  * Metadata enrichment from `cargo metadata` may be incomplete in offline mode.
  * Some advanced dependency resolution features (workspace overrides, patching) must be reconciled with Cargo.lock authority.
  * Developers must ensure Cargo.lock is up-to-date for correct analysis.


### References

* [Rust Cargo Book: Cargo.lock](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html)
* RustSec Advisory Database

---
