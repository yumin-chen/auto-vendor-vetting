---
Status: Draft
Date: 2025-12-27
Authors: [Security, Supply-Chain, DevOps]
Reviewers: [Security, Supply-Chain, DevOps]
Requirements:
  Driving This Decision:
    - R1: TCS classification must be deterministic across repeated runs on identical inputs. (CP-1, CP-6)
    - R2: Classification decisions must include explicit signals for auditability and explainability. (CP-6)
    - R3: Custom project-specific overrides must be supported, with highest precedence. (CP-7)
    - R4: All crate classifications (cryptography, authentication, serialization, transport, random, build-time execution) must be consistent and verifiable. (CP-6)
Related Correctness Properties:
  - CP-6: Classification Explainability                                   
  - CP-7: Custom TCS Configuration Override                               
  - CP-1: Deterministic Output (reproducibility of classification results)
Related ADRs:
  - ADR-001: Cargo.lock as Canonical Source of Dependency Identity
  - ADR-003: Offline-First Vendor Management
  - ADR-004: SBOM Generation Without Vulnerability Scoring
---

# ADR-002: Deterministic Trust-Critical Software (TCS) Classification

## Context

In supply-chain security, certain crates have elevated risk or criticality due to their role in cryptography, authentication, serialization, transport, or random number generation. Correctly identifying these **Trust-Critical Software (TCS)** dependencies is essential for audit, drift detection, and policy enforcement.

Existing classification approaches in Rust rely on heuristic name matching, keywords, or opaque machine learning models. These methods lack deterministic behavior, explainability, and reproducibility, which are required in high-assurance systems.

The Rust Ecosystem Adapter must provide a **deterministic, explainable, and overrideable TCS classification** system to support:

* Security audits
* Dependency drift detection with prioritization
* Policy-neutral consumption by the Control Plane

### Alternatives Considered

1. **Opaque Machine Learning Classification:**

   * Pros: Can detect implicit TCS patterns.
   * Cons: Non-deterministic, non-explainable, and unsuitable for high-assurance audits.

2. **Manual, Hard-Coded Rules Only:**

   * Pros: Deterministic and explainable.
   * Cons: Difficult to extend or maintain; cannot accommodate project-specific overrides.

3. **Deterministic Multi-Signal Heuristic System:**

   * Pros: Deterministic, auditable, extendable with patterns and explicit overrides, supports explainability.
   * Cons: Requires careful precedence handling; patterns must be maintained.

**Decision:** Adopt a **deterministic, multi-signal heuristic system** for TCS classification with explicit override precedence, pattern matching, and role assignment. Machine learning or opaque methods are explicitly prohibited for this system.

## Decision

* **Deterministic Classification:** Classification must produce identical results for identical inputs, ensuring reproducibility.
* **Signal-Based Explainability:** Every classification decision must include at least one explicit **ClassificationSignal** explaining why a crate is classified as TCS.
* **Explicit Overrides:** User or project-specific overrides take highest precedence, followed by pattern matches, then default rules.
* **Multi-Signal Heuristics:** Classification considers multiple signals including:

  * Dependency kind (normal, build, dev)
  * Build script usage (`build.rs`)
  * Proc-macro usage
  * Crate name patterns
  * Cargo keywords and categories
* **TCS Categories:** Crates are categorized into:

  * Cryptography
  * Authentication
  * Serialization
  * Transport
  * Random
  * Build-Time Execution (for `proc-macro` and build.rs)
* **Mechanical Default:** Crates not matching any TCS signals default to **Mechanical** classification.

### Consequences

* **Positive:**

  * Ensures deterministic and reproducible classification across multiple Rust projects. (CP-1, CP-6)
  * Supports auditability and traceable classification decisions. (CP-6)
  * Allows project-specific flexibility via explicit overrides. (CP-7)
  * Supports prioritization in drift detection based on TCS roles.

* **Negative / Considerations:**

  * Requires maintenance of pattern lists and override configurations.
  * Misconfiguration may misclassify crates; proper testing and property-based validation are required.
  * Does not automatically detect emerging TCS crates without updating patterns or overrides.

### References

* RustSec Advisory Database: [https://rustsec.org](https://rustsec.org)
* Cargo Documentation: [https://doc.rust-lang.org/cargo](https://doc.rust-lang.org/cargo)

---
