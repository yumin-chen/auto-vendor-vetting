---
Status: Draft
Classification: Internal Architecture
Date: 2025-12-27 
Version: 0.0.1.draft.1  
---

#  Universal Supply-Chain Security System

## 1. Executive Summary

### 1.1 Purpose

This document describes a **language-agnostic, project-independent supply-chain security system** capable of vetting, tracking, and vendoring dependencies across multiple software projects and technology stacks.

The system applies separation of concerns by:
- **Core Platform:** Generic dependency management engine
- **Ecosystem Adapters:** Language-specific plugins (Rust, Go, Node.js, Python, etc.)
- **Project Instances:** Per-project configuration and state (Vaultwarden, gitoxide, Radicle, etc.)

### 1.2 Design Goals

**Primary Goals:**
1. **Multi-Project Support:** Track N projects independently with shared infrastructure
2. **Multi-Language Support:** Rust, Go, Node.js, Python, Java, etc.
3. **Unified Security Model:** Same TCS/epoch concepts across all ecosystems
4. **Shared Intelligence:** Cross-project vulnerability insights and audit reuse
5. **Independent Evolution:** Projects can have different security postures
6. **Operational Efficiency:** Amortize tooling cost across all projects

**Non-Goals:**
- Single monolithic repository (projects remain independent)
- Language-agnostic package format (respect ecosystem conventions)
- Real-time continuous updates (epochs provide stability)

### 1.3 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Supply-Chain Control Plane                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Policy Engine│  │  Intelligence│  │ Audit System │     │
│  │   (Epochs)   │  │    (CVEs)    │  │  (Reviews)   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼────────┐  ┌─────────▼────────┐  ┌────────▼────────┐
│ Rust Adapter   │  │  Go Adapter      │  │ Node.js Adapter │
│ (cargo-vet)    │  │  (go.sum)        │  │ (npm audit)     │
└───────┬────────┘  └─────────┬────────┘  └────────┬────────┘
        │                     │                     │
┌───────▼────────┐  ┌─────────▼────────┐  ┌────────▼────────┐
│  Vaultwarden   │  │    gitoxide      │  │    Radicle      │
│  Project       │  │    Project       │  │    Project      │
└────────────────┘  └──────────────────┘  └─────────────────┘
```

---

## 2. Core Architecture

### 2.1 System Components

#### 2.1.1 Control Plane (Language-Agnostic)

**Policy Engine:**
- Manages epoch definitions across all projects
- Enforces TCS classification rules
- Validates security invariants
- Coordinates multi-project updates

**Intelligence Hub:**
- Aggregates CVE feeds (NVD, OSV, ecosystem-specific)
- Cross-references vulnerabilities across projects
- Provides exploitability assessments (VEX)
- Maintains audit history database

**Audit System:**
- Tracks all security decisions (ADRs)
- Maintains approval workflows
- Generates compliance reports
- Provides forensic timeline

**SBOM Registry:**
- Stores SBOMs from all projects
- Enables cross-project dependency analysis
- Tracks license compliance
- Identifies dependency overlap

#### 2.1.2 Ecosystem Adapters (Language-Specific)

Each adapter implements a standard interface:

```rust
pub trait EcosystemAdapter {
    // Metadata
    fn ecosystem_name(&self) -> &str;
    fn supported_lockfile_formats(&self) -> Vec<&str>;
    
    // Dependency Analysis
    async fn parse_dependencies(&self, project: &Project) -> Result<DependencyGraph>;
    async fn classify_tcs(&self, graph: &DependencyGraph) -> Result<TcsClassification>;
    async fn detect_drift(&self, expected: &Epoch, actual: &DependencyGraph) -> Result<Drift>;
    
    // Vetting
    async fn run_audit(&self, project: &Project) -> Result<AuditReport>;
    async fn check_supply_chain(&self, project: &Project) -> Result<SupplyChainReport>;
    
    // Vendoring
    async fn vendor_dependencies(&self, project: &Project, target: &Path) -> Result<()>;
    async fn verify_vendored(&self, project: &Project, vendored: &Path) -> Result<()>;
    
    // SBOM
    async fn generate_sbom(&self, project: &Project) -> Result<Sbom>;
}
```

**Example Adapters:**

| Adapter | Lock File | Audit Tool | Vendor Command |
|---------|-----------|------------|----------------|
| **Rust** | `Cargo.lock` | `cargo-audit`, `cargo-vet` | `cargo vendor` |
| **Go** | `go.sum` | `govulncheck` | `go mod vendor` |
| **Node.js** | `package-lock.json` | `npm audit` | Custom vendoring |
| **Python** | `poetry.lock`, `Pipfile.lock` | `pip-audit` | `pip download` |
| **Java** | `pom.xml.lock`, `gradle.lockfile` | OWASP Dependency-Check | Maven/Gradle vendor |

#### 2.1.3 Project Instances (Per-Project Configuration)

Each project maintains:

```toml
# project.toml for Vaultwarden
[project]
id = "vaultwarden"
name = "Vaultwarden Password Manager"
repository = "https://github.com/dani-garcia/vaultwarden"
ecosystem = "rust"
owner = "security-team@example.com"

[project.paths]
root = "/projects/vaultwarden"
lockfile = "Cargo.lock"
manifest = "Cargo.toml"
epochs = "security/epochs"
sboms = "security/sboms"
adrs = "security/adrs"

[project.security]
threat_level = "critical"  # critical, high, medium, low
compliance = ["SOC2", "HIPAA"]
current_epoch = "2025-Q4-001"

[project.tcs]
# Project-specific TCS components
crypto = ["ring", "argon2", "aes-gcm"]
auth = ["jsonwebtoken", "oauth2"]
serialization = ["serde", "serde_json"]
custom = ["vaultwarden_crypto"]  # Project-specific critical code

[project.policy]
# How aggressive is vetting?
tcs_requires_audit = true
mechanical_requires_scan = true
allow_git_dependencies = false
max_transitive_depth = 10

[project.alerting]
critical_cve_to = ["oncall@example.com"]
high_cve_to = ["security-team@example.com"]
drift_detected_to = ["security-team@example.com"]
```

### 2.2 Data Models

#### 2.2.1 Universal Dependency Graph

```rust
pub struct DependencyGraph {
    pub project_id: ProjectId,
    pub ecosystem: Ecosystem,
    pub root_packages: Vec<PackageNode>,
    pub edges: Vec<DependencyEdge>,
    pub metadata: GraphMetadata,
}

pub struct PackageNode {
    pub id: PackageId,
    pub name: String,
    pub version: Version,
    pub source: PackageSource,  // crates.io, npm, PyPI, etc.
    pub checksum: String,
    pub classification: Classification,  // TCS or Mechanical
    pub audit_status: AuditStatus,
}

pub enum PackageSource {
    Registry { url: String, checksum: String },
    Git { url: String, rev: String, checksum: String },
    Local { path: PathBuf },
}

pub enum Classification {
    TCS { category: TcsCategory, rationale: String },
    Mechanical { category: MechanicalCategory },
    Unknown,  // Requires classification
}

pub enum TcsCategory {
    Cryptography,
    Authentication,
    Serialization,
    Transport,
    Database,
    Random,
    Custom(String),
}
```

#### 2.2.2 Universal Epoch

```rust
pub struct Epoch {
    pub id: EpochId,  // "2025-Q4-001"
    pub project_id: ProjectId,
    pub created_at: DateTime<Utc>,
    pub metadata: EpochMetadata,
    pub dependencies: EpochDependencies,
    pub security: EpochSecurity,
    pub governance: EpochGovernance,
}

pub struct EpochDependencies {
    pub lockfile_hash: Hash,
    pub sbom_hash: Hash,
    pub tcs_pins: HashMap<PackageId, PackagePin>,
    pub mechanical_ranges: HashMap<PackageId, VersionRange>,
}

pub struct PackagePin {
    pub version: Version,
    pub audit: AuditProof,  // cargo-vet, manual ADR, etc.
    pub cve_status: CveStatus,
    pub vendored: Option<VendorInfo>,
}

pub struct AuditProof {
    pub method: AuditMethod,
    pub auditor: String,
    pub date: DateTime<Utc>,
    pub signature: Option<Signature>,
}

pub enum AuditMethod {
    CargoVet { criteria: String },
    Manual { adr_reference: u32 },
    Imported { source: String },
    Exemption { reason: String, expires: DateTime<Utc> },
}
```

#### 2.2.3 Universal CVE/Advisory Model

```rust
pub struct Advisory {
    pub id: AdvisoryId,  // CVE-2025-1234, RUSTSEC-2025-001, GHSA-xxxx
    pub ecosystem: Ecosystem,
    pub affected_packages: Vec<AffectedPackage>,
    pub severity: Severity,
    pub cvss: Option<CvssScore>,
    pub description: String,
    pub published: DateTime<Utc>,
    pub references: Vec<String>,
}

pub struct AffectedPackage {
    pub package_name: String,
    pub affected_versions: VersionRange,
    pub patched_versions: Vec<Version>,
    pub exploitability: Exploitability,  // From VEX
}

pub enum Exploitability {
    NotAffected { reason: String },
    Affected { details: String },
    UnderInvestigation,
    Unknown,
}
```

---

## 3. Separation of Concerns

### 3.1 Vertical Separation (Layers)

```
┌────────────────────────────────────────────────────┐
│ Layer 4: Presentation (CLI, Web UI, API)          │ ← User interaction
├────────────────────────────────────────────────────┤
│ Layer 3: Orchestration (Workflows, Automation)    │ ← Business logic
├────────────────────────────────────────────────────┤
│ Layer 2: Core Services (Policy, Intelligence)     │ ← Domain logic
├────────────────────────────────────────────────────┤
│ Layer 1: Adapters (Rust, Go, Node.js)             │ ← Ecosystem integration
└────────────────────────────────────────────────────┘
```

**Layer 1 (Adapters):**
- Knows ecosystem-specific tools and formats
- Translates ecosystem concepts to universal model
- No policy decisions, pure translation

**Layer 2 (Core Services):**
- Implements universal security model (TCS, epochs)
- Makes policy decisions (what requires auditing?)
- Stores cross-project intelligence

**Layer 3 (Orchestration):**
- Coordinates multi-step workflows (quarterly review)
- Manages asynchronous operations (background scanning)
- Handles inter-project dependencies

**Layer 4 (Presentation):**
- CLI for day-to-day operations
- Web UI for visualization and reporting
- API for CI/CD integration

### 3.2 Horizontal Separation (Projects)

```
Control Plane (Shared)
    │
    ├─── Vaultwarden Instance
    │       ├── Rust Adapter
    │       ├── Project Config
    │       ├── Epochs
    │       └── SBOMs
    │
    ├─── gitoxide Instance
    │       ├── Rust Adapter (same adapter!)
    │       ├── Project Config
    │       ├── Epochs
    │       └── SBOMs
    │
    └─── Radicle Instance
            ├── Rust Adapter (same adapter!)
            ├── Project Config
            ├── Epochs
            └── SBOMs
```

**Key Insight:** All three projects share:
- The same Rust adapter implementation
- The same vulnerability database
- The same audit infrastructure

But maintain independent:
- Epoch schedules
- Security policies
- TCS classifications
- Approval workflows

### 3.3 Shared vs. Independent Resources

**Shared Resources:**
- ✅ Control plane infrastructure
- ✅ Vulnerability intelligence database
- ✅ Audit tool wrappers (cargo-vet, cargo-audit)
- ✅ SBOM generation logic
- ✅ Reporting and visualization
- ✅ CI/CD templates

**Independent Resources:**
- ❌ Epoch definitions (different schedules)
- ❌ TCS classifications (different threat models)
- ❌ ADR repositories (different approvers)
- ❌ Vendor directories (different dependencies)
- ❌ Alerting channels (different teams)

---

## 4. Multi-Project Workflow Examples

### 4.1 Scenario: Three Rust Projects

**Setup:**
```bash
# Initialize control plane
supply-chain-control init --name my-org

# Register projects
supply-chain-control project add \
  --id vaultwarden \
  --ecosystem rust \
  --path /projects/vaultwarden

supply-chain-control project add \
  --id gitoxide \
  --ecosystem rust \
  --path /projects/gitoxide

supply-chain-control project add \
  --id radicle \
  --ecosystem rust \
  --path /projects/radicle
```

**Daily Operations:**
```bash
# Scan all projects for new CVEs
supply-chain-control scan-all --daily

# Output:
# ✓ vaultwarden: No new CVEs
# ⚠ gitoxide: 1 medium CVE in tokio (mechanical component)
# ✓ radicle: No new CVEs
```

**Cross-Project Intelligence:**
```bash
# Which projects use vulnerable version of tokio?
supply-chain-control query vulnerable-packages --cve CVE-2025-1234

# Output:
# Projects using tokio 1.32.0 (vulnerable):
# - gitoxide (mechanical, medium priority)
# - radicle (mechanical, medium priority)
#
# Recommended action:
# Update both projects to tokio 1.33.0 in next epoch
```

**Shared Audit Reuse:**
```bash
# Alice audits `ring 0.17.8` for Vaultwarden
cd /projects/vaultwarden
cargo vet certify ring 0.17.8 --criteria safe-to-deploy

# Bob can import Alice's audit for gitoxide
cd /projects/gitoxide
supply-chain-control audit import \
  --from vaultwarden \
  --package ring:0.17.8

# Radicle automatically benefits (same control plane)
cd /projects/radicle
supply-chain-control audit status ring
# Output: ring 0.17.8 - Audited by alice@example.com (2025-10-15)
```

### 4.2 Scenario: Mixed Ecosystems

**Setup:**
```bash
# Add Go project
supply-chain-control project add \
  --id backend-service \
  --ecosystem go \
  --path /projects/backend-go

# Add Node.js project
supply-chain-control project add \
  --id web-frontend \
  --ecosystem nodejs \
  --path /projects/web-ui
```

**Cross-Ecosystem CVE Scanning:**
```bash
supply-chain-control scan-all

# Output:
# ✓ vaultwarden (rust): Clean
# ⚠ backend-service (go): 1 critical CVE in golang.org/x/crypto
# ✓ web-frontend (nodejs): Clean
```

**Unified Reporting:**
```bash
supply-chain-control report --format html --output security-posture.html

# Generates single report covering:
# - All 5 projects
# - All ecosystems
# - Unified severity scoring
# - Cross-project dependency overlap
```

### 4.3 Scenario: Dependency Overlap Analysis

**Problem:** Multiple projects use similar libraries, which ones overlap?

```bash
supply-chain-control analyze overlaps

# Output:
# Common dependencies across projects:
#
# serde (rust):
#   - vaultwarden: 1.0.210 (epoch 2025-Q4-001)
#   - gitoxide: 1.0.205 (epoch 2025-Q3-002)
#   - radicle: 1.0.210 (epoch 2025-Q4-003)
#
# Recommendation: Align gitoxide to serde 1.0.210
#
# tokio (rust):
#   - vaultwarden: 1.38.0
#   - gitoxide: 1.32.0 (vulnerable!)
#   - radicle: 1.39.0
#
# Recommendation: Update gitoxide to tokio 1.38.0+
```

**Action:**
```bash
# Create coordinated update across projects
supply-chain-control update-coordinated \
  --package tokio \
  --version 1.39.0 \
  --projects vaultwarden,gitoxide,radicle \
  --reason "CVE-2025-1234 mitigation"

# Creates draft epochs for all three projects
# Security team reviews and approves together
```

---

## 5. Vendoring Strategy

### 5.1 Why Vendor?

**Security Benefits:**
1. **Offline Verification:** Dependencies can't change after vendoring
2. **Reproducible Builds:** Guaranteed same source across environments
3. **Air-Gap Deployments:** No internet required during build
4. **Audit Trail:** Exact source code is preserved
5. **Supply-Chain Isolation:** Protected from registry compromise

**Operational Benefits:**
1. **Build Speed:** No network dependency downloads
2. **Reliability:** No registry outages
3. **Compliance:** Source code retention for audits

### 5.2 Vendoring Model

```rust
pub struct VendorStrategy {
    pub mode: VendorMode,
    pub storage: VendorStorage,
    pub verification: VendorVerification,
}

pub enum VendorMode {
    /// Vendor all dependencies
    Full,
    /// Vendor only TCS dependencies
    TcsOnly,
    /// Vendor nothing (validate checksums only)
    None,
}

pub enum VendorStorage {
    /// Local directory (e.g., vendor/)
    Local { path: PathBuf },
    /// Git submodule
    GitSubmodule { path: PathBuf },
    /// Separate Git repository
    SeparateRepo { url: String },
    /// Artifact registry (Artifactory, Nexus)
    ArtifactRegistry { url: String },
}

pub struct VendorVerification {
    /// Verify checksums match lockfile
    pub verify_checksums: bool,
    /// Scan vendored source for malware
    pub malware_scan: bool,
    /// Compare vendored to fresh download
    pub compare_fresh: bool,
}
```

### 5.3 Per-Ecosystem Vendoring

#### Rust Vendoring

```bash
# Vendor all dependencies
cargo vendor vendor/

# Verify vendored sources
supply-chain-control vendor verify \
  --project vaultwarden \
  --vendored vendor/

# Output:
# ✓ 147/147 packages verified
# ✓ All checksums match Cargo.lock
# ✓ No unexpected files detected
```

**Vendor Configuration:**
```toml
# .cargo/config.toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

#### Go Vendoring

```bash
# Vendor all modules
go mod vendor

# Verify
supply-chain-control vendor verify \
  --project backend-service \
  --vendored vendor/

# Go includes checksums in go.sum, verification automatic
```

#### Node.js Vendoring

```bash
# Node.js doesn't have native vendoring, we implement it
supply-chain-control vendor create \
  --project web-frontend \
  --output vendor-node/

# This downloads all packages from package-lock.json
# and stores them with checksums
```

### 5.4 Vendor Repository Structure

```
vendor-repos/
├── rust/
│   ├── vaultwarden-2025-Q4-001/
│   │   ├── vendor/           # Vendored source
│   │   ├── Cargo.lock        # Exact lockfile
│   │   ├── checksums.txt     # SHA256 of all files
│   │   └── metadata.json     # Epoch info
│   ├── gitoxide-2025-Q3-002/
│   └── radicle-2025-Q4-003/
├── go/
│   └── backend-service-2025-Q4-001/
└── nodejs/
    └── web-frontend-2025-Q4-001/
```

**Benefits:**
- Each epoch has isolated vendor snapshot
- Rollback = checkout previous vendor directory
- Audit = compare vendored source to registry
- Air-gap = copy vendor directory to isolated network

### 5.5 Vendor Verification Workflow

```bash
# Continuous verification (weekly)
supply-chain-control vendor verify-all

# For each project:
# 1. Re-download dependencies from registry
# 2. Compare to vendored versions
# 3. Alert on any differences (supply-chain attack detection)
```

**Attack Detection:**
```bash
# Scenario: crates.io compromised, `serde 1.0.210` replaced with backdoor

supply-chain-control vendor verify --project vaultwarden

# Output:
# ⚠ CRITICAL: Vendor verification FAILED
# Package: serde 1.0.210
# Expected hash: sha256:a3f8b9c2d4e5...
# Actual hash:   sha256:9e7d2c1a3b8f... (DIFFERENT!)
#
# This indicates potential registry compromise or MITM attack.
# Do NOT update vendored copy. Investigate immediately.
```

---

## 6. Intelligence Sharing

### 6.1 Shared CVE Database

```rust
pub struct IntelligenceHub {
    pub cve_db: CveDatabase,
    pub audit_db: AuditDatabase,
    pub vex_db: VexDatabase,
}

impl IntelligenceHub {
    /// Check if any project is affected by CVE
    pub async fn check_cve_impact(&self, cve_id: &str) -> Vec<ProjectImpact> {
        // Query all registered projects
        // Return which projects use vulnerable versions
    }
    
    /// Find audits that can be reused across projects
    pub async fn find_reusable_audits(&self, package: &Package) -> Vec<AuditRecord> {
        // Check if any project has audited this package
        // Return audit proofs that can be imported
    }
    
    /// Get VEX (exploitability) assessment
    pub async fn get_exploitability(&self, cve_id: &str, project: &Project) -> Exploitability {
        // Return whether CVE is exploitable in this project's context
    }
}
```

### 6.2 Cross-Project Audit Reuse

**Scenario:** Alice audits `tokio 1.38.0` for Vaultwarden

```bash
cd /projects/vaultwarden
cargo vet certify tokio 1.38.0 --criteria safe-to-deploy
```

This audit is automatically available to:
- gitoxide (if they use tokio 1.38.0)
- radicle (if they use tokio 1.38.0)
- Any future Rust project added to control plane

**Audit Reuse Rules:**
```toml
[intelligence.audit_reuse]
# Trust audits from other projects in same organization
trust_internal = true

# Trust audits from specific external sources
trust_external = [
    "https://github.com/mozilla/supply-chain",
    "https://github.com/google/oss-rust-audits"
]

# Minimum auditor count for reuse
min_auditors = 1

# Maximum age of audit (days)
max_age_days = 365
```

### 6.3 Vulnerability Correlation

**Scenario:** New CVE affects multiple projects

```bash
# New CVE published: CVE-2025-5678 in serde
supply-chain-control intel check-impact CVE-2025-5678

# Output:
# CVE-2025-5678: Deserialization gadget in serde 1.0.200-1.0.209
# Severity: HIGH (CVSS 7.5)
#
# Affected Projects:
# ⚠ vaultwarden: Uses serde 1.0.210 (NOT AFFECTED)
# ⚠ gitoxide: Uses serde 1.0.205 (AFFECTED - TCS component!)
# ⚠ radicle: Uses serde 1.0.210 (NOT AFFECTED)
#
# Recommended Actions:
# 1. URGENT: Update gitoxide to serde 1.0.210+
# 2. Priority: HIGH (TCS component in affected project)
# 3. Timeline: 48 hours (high-severity TCS CVE)
```

### 6.4 License Intelligence

```bash
# Check license compliance across all projects
supply-chain-control intel check-licenses

# Output:
# License Compliance Summary:
#
# ✓ vaultwarden: All clear (MIT, Apache-2.0)
# ⚠ gitoxide: 1 GPL-3.0 dependency (libgit2-sys)
# ✓ radicle: All clear (MIT, Apache-2.0, BSD-3-Clause)
#
# Recommendation: Review gitoxide GPL-3.0 usage for compliance
```

---

## 7. Implementation Architecture

### 7.1 Technology Stack

**Core Platform:**
- **Language:** Rust (performance, safety, ecosystem maturity)
- **Storage:** SQLite for metadata (simple, reliable, embedded)
- **Cache:** Redis for distributed caching (optional)
- **Queue:** Tokio async for background tasks
- **CLI:** clap for command-line interface
- **Web:** Axum for REST API and web UI

**Adapters:**
- **Rust:** Native (cargo-audit, cargo-vet, cargo-vendor)
- **Go:** Shell execution (go list, govulncheck, go mod vendor)
- **Node.js:** Shell execution (npm audit, npm pack)
- **Python:** Shell execution (pip-audit, pip download)

**Integrations:**
- **CVE Feeds:** OSV.dev API, NVD API, GitHub Advisory Database
- **CI/CD:** GitHub Actions, GitLab CI, Jenkins plugins
- **Notifications:** SMTP, Slack, PagerDuty, Webhooks

### 7.2 Database Schema

```sql
-- Projects
CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    root_path TEXT NOT NULL,
    owner_email TEXT,
    threat_level TEXT CHECK(threat_level IN ('critical','high','medium','low')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Epochs
CREATE TABLE epochs (
    id TEXT PRIMARY KEY,  -- "vaultwarden-2025-Q4-001"
    project_id TEXT NOT NULL REFERENCES projects(id),
    created_at TIMESTAMP NOT NULL,
    lockfile_hash TEXT NOT NULL,
    sbom_hash TEXT NOT NULL,
    approvers JSON NOT NULL,  -- Array of approver emails/signatures
    current BOOLEAN DEFAULT FALSE,
    supersedes TEXT REFERENCES epochs(id),
    UNIQUE(project_id, current) WHERE current = TRUE
);

-- Dependencies (denormalized for query performance)
CREATE TABLE dependencies (
    id INTEGER PRIMARY KEY,
    epoch_id TEXT NOT NULL REFERENCES epochs(id),
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    classification TEXT CHECK(classification IN ('tcs','mechanical','unknown')),
    tcs_category TEXT,  -- 'cryptography', 'authentication', etc.
    audit_status TEXT CHECK(audit_status IN ('audited','exempted','unaudited')),
    audit_method TEXT,
    auditor TEXT,
    audit_date TIMESTAMP,
    checksum TEXT NOT NULL,
    INDEX(epoch_id),
    INDEX(package_name, package_version, ecosystem)
);

-- Advisories
CREATE TABLE advisories (
    id TEXT PRIMARY KEY,  -- "CVE-2025-1234" or "RUSTSEC-2025-001"
    ecosystem TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    published_at TIMESTAMP NOT NULL,
    description TEXT,
    references JSON,  -- Array of URLs
    INDEX(ecosystem, published_at)
);

-- Advisory Affects (which packages are vulnerable)
CREATE TABLE advisory_affects (
    id INTEGER PRIMARY KEY,
    advisory_id TEXT NOT NULL REFERENCES advisories(id),
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    affected_versions TEXT NOT NULL,  -- Version range
    patched_versions JSON,  -- Array of patched versions
    exploitability TEXT CHECK(exploitability IN ('not_affected','affected','under_investigation','unknown')),
    INDEX(advisory_id),
    INDEX(package_name, ecosystem)
);

-- Audit Records (shared across projects)
CREATE TABLE audits (
    id INTEGER PRIMARY KEY,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    method TEXT NOT NULL,  -- 'cargo-vet', 'manual', 'imported'
    criteria TEXT,  -- 'safe-to-deploy', 'safe-to-run'
    auditor TEXT NOT NULL,
    audit_date TIMESTAMP NOT NULL,
    notes TEXT,
    signature TEXT,  -- GPG signature
    source_project TEXT,  -- Which project created this audit?
    UNIQUE(package_name, package_version, ecosystem, auditor)
);

-- Vendor Snapshots
CREATE TABLE vendor_snapshots (
    id INTEGER PRIMARY KEY,
    epoch_id TEXT NOT NULL REFERENCES epochs(id),
    storage_path TEXT NOT NULL,
    total_packages INTEGER NOT NULL,
    total_size_bytes BIGINT NOT NULL,
    checksums_file TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP  -- Last verification time
);
```

### 7.3 API Design

**REST API Endpoints:**

```
# Projects
GET    /api/v1/projects                    # List all projects
POST   /api/v1/projects                    # Register new project
GET    /api/v1/projects/{id}               # Get project details
PUT    /api
