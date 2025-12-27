## Requirement 3: Security Auditing Integration

**User Story:**
As a security auditor, I want to run comprehensive security scans on Rust projects, so that I can identify known vulnerabilities and verify audit status.

### Acceptance Criteria

1. WHEN running security audits, THE Adapter SHALL execute `cargo-audit`
2. WHEN running security audits, THE Adapter SHALL execute `cargo-vet`
3. WHEN vulnerabilities are found, THE Adapter SHALL extract:

   * CVE or advisory identifiers
   * severity
   * affected version ranges
4. WHEN audit status is reported, THE Adapter SHALL extract:

   * audit criteria
   * auditor identity
   * audit date
5. WHEN audit tools fail, THE Adapter SHALL return structured, actionable error information
6. WHEN audit results are available, THE Adapter SHALL correlate findings to nodes in the dependency graph
7. THE Adapter SHALL treat audit tool output as advisory input to the Control_Plane
