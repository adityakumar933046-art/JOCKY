# JOCKY Enterprise Security Demonstration & Architecture Walkthrough

## 1. Overview

The JOCKY platform incorporates enterprise-grade security controls designed to guarantee multi-tenant data confidentiality, evidence admissibility, agent authenticity, and non-repudiation. This document provides a complete technical walkthrough of the security architecture and details the 27 automated checks executed in the Security End-to-End Demonstration (`scripts/e2e_security_demo.py`).

---

## 2. Security Architecture Components

### 2.1 7-Tier Role-Based Access Control (RBAC)

JOCKY implements a fine-grained RBAC model with seven distinct roles:

```
SUPER_ADMIN (Global Fleet Governance)
    │
    ├── ORGANIZATION_ADMIN (Tenant Administration)
    │       │
    │       ├── SECURITY_ANALYST (Triage & Scan Dispatch)
    │       │
    │       ├── SIGNER (Evidence Signing & Seal Attestation)
    │       │
    │       ├── VERIFIER (Independent Hash & Custody Verification)
    │       │
    │       └── INVESTIGATOR (Case Workspace & Incident Analysis)
    │
    └── VIEWER (Read-Only Audit & Compliance Inspection)
```

| Role | Key Permissions | Intended Persona |
| :--- | :--- | :--- |
| `SUPER_ADMIN` | Global tenant creation, platform config, agent revocation, audit inspection | Chief Information Security Officer (CISO) |
| `ORGANIZATION_ADMIN` | User provisioning, agent approval/suspension, organization policies | Security Operations Center (SOC) Manager |
| `SECURITY_ANALYST` | Script authoring, job dispatch, evidence inspection, threat correlation | Senior Forensic Analyst |
| `SIGNER` | `evidence.sign`, `reports.sign`, `custody.attest` | Digital Evidence Officer / Notary |
| `VERIFIER` | `evidence.verify`, `custody.verify`, `audit.verify` | Independent Quality Assurance Auditor |
| `INVESTIGATOR` | Case management, artifact pinning, notes authoring, snapshot freezing | Incident Response Investigator |
| `VIEWER` | Read-only dashboards, sanitized timeline viewing, read-only search | Compliance Auditor / Executive |

### 2.2 Password Security & PBKDF2 Configuration
- Passwords are encrypted using **PBKDF2-HMAC-SHA256** with a unique 32-byte cryptographically secure random salt per user.
- **Configurable Iterations**: The iteration count is loaded dynamically via the `JOCKY_PBKDF2_ITERATIONS` environment variable (defaults to 310,000 for production and 1,000 in testing environments for sub-second execution).
- Brute-force lockout triggers after consecutive failed authentication attempts.

### 2.3 JWT Token Lifecycle & Organization Scoping
- JSON Web Tokens (JWT) are signed using HMAC-SHA256 with the server's private secret (`JOCKY_SECRET_KEY`).
- Token payload enforces organization boundaries:
  ```json
  {
    "sub": "analyst@example.com",
    "org_id": "org-corp-alpha",
    "role": "SECURITY_ANALYST",
    "exp": 1759248000
  }
  ```
- Every incoming API request validates the token, extracts the tenant context (`org_id`), and automatically scopes all database operations to that organization.

### 2.4 Agent Trust Lifecycle
Agents must pass cryptographic trust verification before receiving tasks:
1. **Enrollment (`PENDING`)**: Agent generates a local identity and submits its public key and hardware fingerprint.
2. **Approval (`AUTHORIZED`)**: An organization administrator approves the agent. Only authorized agents can receive jobs or upload evidence.
3. **Suspension (`SUSPENDED`)**: In case of anomalous behavior, the agent can be suspended without losing historical evidence.
4. **Revocation (`REVOKED`)**: Agent credentials are permanently blacklisted; future connection attempts are rejected.

### 2.5 Canonical Evidence Integrity & Tamper Detection
- Raw evidence captured by collectors is serialized using a canonical JSON schema:
  - Dictionary keys sorted alphabetically at every nesting level.
  - Zero redundant whitespace (`separators=(',', ':')`).
  - Standard UTF-8 encoding.
- A SHA-256 hash is computed immediately upon capture.
- **Tampering Demonstration**: If an adversary modifies even a single bit of evidence in the database (e.g., altering an IP address or PID), recalculating the canonical hash reveals a checksum mismatch, immediately marking the record as `COMPROMISED`.

### 2.6 Hash-Linked Chain of Custody
- Evidence transitions are recorded in an append-only ledger.
- Each entry stores `evidence_id`, `actor_id`, `action` (`COLLECTED`, `RECEIVED`, `TRANSFERRED`, `VIEWED`, `ARCHIVED`), `timestamp`, `hash_at_time`, and a cryptographic link to the prior custody entry's hash.

---

## 3. Running the Security E2E Demonstration

Execute the automated security test script:

```bash
python -m scripts.e2e_security_demo
```

### Expected Output (27/27 Checks Passing)

```
============================================================
JOCKY STEP 5 ENTERPRISE SECURITY E2E DEMO
============================================================
[1/27] Organization isolation setup... PASS
[2/27] Super admin authentication... PASS
[3/27] Organization admin creation... PASS
[4/27] Analyst user creation... PASS
[5/27] Investigator user creation... PASS
[6/27] Viewer user creation... PASS
[7/27] Signer user creation... PASS
[8/27] Verifier user creation... PASS
[9/27] PBKDF2 hash verification & iteration count... PASS
[10/27] JWT access token issuance... PASS
[11/27] RBAC: Analyst can create jobs... PASS
[12/27] RBAC: Viewer cannot create jobs (403 Forbidden)... PASS
[13/27] RBAC: Signer can sign evidence... PASS
[14/27] RBAC: Verifier can verify evidence... PASS
[15/27] Multi-tenant isolation: Org A cannot read Org B jobs... PASS
[16/27] Multi-tenant isolation: Org A cannot read Org B evidence... PASS
[17/27] Agent enrollment in PENDING state... PASS
[18/27] Pending agent cannot receive jobs... PASS
[19/27] Agent approval to AUTHORIZED state... PASS
[20/27] Authorized agent receives jobs... PASS
[21/27] Canonical JSON SHA-256 evidence hashing... PASS
[22/27] Evidence integrity verification (untampered)... PASS
[23/27] Tamper detection: altered evidence fails verification... PASS
[24/27] Chain of custody entry creation (COLLECTED)... PASS
[25/27] Chain of custody entry creation (RECEIVED)... PASS
[26/27] Chain of custody ledger hash linkage verification... PASS
[27/27] Append-only audit logging verification... PASS

============================================================
ALL 27 SECURITY CHECKS PASSED SUCCESSFULLY!
============================================================
```
