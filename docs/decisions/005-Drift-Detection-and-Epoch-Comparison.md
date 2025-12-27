---
Status: Proposed
Date: 2025-12-27
Authors: [Rust Platform]
Reviewers: [Security, Supply-Chain, Compliance, Control Plane, DevOps, Architecture]
Requirements:
  Addressed:
    - Detect **all changes** between epochs: additions, removals, version changes, source changes (registry → git → path)
    - Categorize changes according to **Trust-Critical Software (TCS) classification**
    - Maintain **comprehensive, auditable reports**
    - Support **offline operation** and deterministic comparison
Related ADRs:
  - ADR-001: Cargo.lock as Source of Truth
  - ADR-002: Deterministic Output Principle
  - ADR-003: Offline-First Vendor Management
  - ADR-004: SBOM Generation Without Vulnerability Scoring
---

# ADR-005: Drift Detection and Epoch Comparison

## Context

The Rust Ecosystem Adapter must support **dependency drift detection** to maintain high-integrity software supply chains. Drift occurs when a project’s dependencies diverge between epochs, e.g., through additions, removals, version changes, or source changes.

Drift detection enables:

- Continuous monitoring for unauthorized dependency changes
- Accurate assessment of supply chain risk
- Integration with the **Control Plane** for policy evaluation

---

## Decision

The adapter will implement an **epoch-based drift detection system** that compares consecutive Universal Dependency Graphs (UDGs) for a project.

### Key Decisions

1. **Epoch Representation**:

- Each project snapshot generates a cryptographic digest of the UDG
- Epoch ID derived from **Cargo.lock hash, vendored digest, and optional configuration**

2. **Drift Detection Algorithm**:

- Compare previous and current epochs at **dependency node level**
- Detect and categorize:
  - Added dependencies
  - Removed dependencies
  - Version changes
  - Source changes (registry → git, git commit changes, local path changes)
- Associate **TCS classification** with each node for priority assessment

3. **Reporting**:

- Generate structured drift report including:
  - Dependency name, old version/source, new version/source
  - Drift type (addition, removal, version change, source change)
  - TCS category of affected dependencies
  - Timestamp and epoch metadata
- Reports emitted as **JSON artifact** for Control Plane consumption

4. **Determinism & Offline Support**:

- Identical inputs produce identical drift reports
- Offline operation supported; comparisons performed using local artifacts only

5. **Integration with Vendor Manager**:

- Changes in vendored dependencies are considered part of epoch validation
- Checksum mismatches invalidate the epoch (CP-6)

---

## Consequences

**Positive**:

- Provides full visibility into supply chain changes
- Supports high-assurance auditing and compliance
- Maintains alignment with Control Plane policies

**Negative**:

- Requires storage of prior epoch data for comparison
- Computational overhead increases with large dependency graphs

**Mitigations**:

- Implement efficient hashing and comparison strategies
- Support optional pruning of historical epochs while maintaining audit trail

---

## Alternatives Considered

1. **Simple version-only comparison**: Rejected

- Fails to detect source changes (registry → git → path)
- Insufficient for high-assurance audits

2. **Manual drift detection**: Rejected

- Not scalable or auditable
- Inconsistent results across teams

3. **Drift detection with partial TCS categorization**: Rejected

- Reduces explainability and risk prioritization
- Violates CP-6 and CP-16 correctness properties

---
