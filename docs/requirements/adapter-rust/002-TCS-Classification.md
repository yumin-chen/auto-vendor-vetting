## Requirement 2: TCS Classification

**User Story:**
As a security architect, I want to classify Rust dependencies as Trust-Critical Software or Mechanical, so that security efforts are focused on high-risk components.

### Acceptance Criteria

1. WHEN analyzing a dependency, THE Adapter SHALL classify it using deterministic classification rules
2. WHEN a dependency provides cryptographic functionality, THE Adapter SHALL classify it as TCS with category `Cryptography`
3. WHEN a dependency handles authentication or authorization, THE Adapter SHALL classify it as TCS with category `Authentication`
4. WHEN a dependency performs serialization or deserialization, THE Adapter SHALL classify it as TCS with category `Serialization`
5. WHEN a dependency handles network transport or protocols, THE Adapter SHALL classify it as TCS with category `Transport`
6. WHEN a dependency provides random number generation, THE Adapter SHALL classify it as TCS with category `Random`
7. WHEN a dependency executes build-time code (e.g., `build.rs`, `proc-macro`), THE Adapter SHALL classify it as TCS with category `Build-Time Execution`
8. WHEN a dependency does not match any TCS category, THE Adapter SHALL classify it as `Mechanical`
9. WHEN project-specific TCS classifications are configured, THE Adapter SHALL apply them in addition to default rules
