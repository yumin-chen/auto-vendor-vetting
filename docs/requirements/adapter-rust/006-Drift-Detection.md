## Requirement 6: Drift Detection

**User Story:**
As a security engineer, I want to detect dependency drift from approved epochs, so that unauthorized changes are identified quickly.

### Acceptance Criteria

1. WHEN comparing against an epoch, THE Adapter SHALL detect added dependencies
2. WHEN comparing against an epoch, THE Adapter SHALL detect removed dependencies
3. WHEN comparing against an epoch, THE Adapter SHALL detect version changes
4. WHEN dependency sources change (e.g., registry → git), THE Adapter SHALL flag high-risk drift
5. WHEN drift is detected, THE Adapter SHALL categorize it as:

   * addition
   * removal
   * version change
   * source change
6. WHEN TCS dependencies drift, THE Adapter SHALL flag them as high-priority security concerns
7. WHEN Mechanical dependencies drift, THE Adapter SHALL flag them as lower-priority items
