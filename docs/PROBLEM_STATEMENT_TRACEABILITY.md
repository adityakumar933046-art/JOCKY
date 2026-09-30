# JOCKY — Problem Statement Traceability & Defense Scope

## 1. Problem Statement Overview

Modern cybersecurity operations require rapid, verifiable, and non-destructive digital forensic triage across heterogeneous multi-platform fleets (Windows, Linux). Organizations face critical challenges during incident response:
- **Triage Inconsistency**: Lack of standardized forensic querying leading to ad-hoc, error-prone shell scripts.
- **Accidental State Mutation**: Unvetted scripts altering timestamps, registry keys, or memory state, compromising evidence admissibility.
- **Security Vulnerabilities in Tooling**: Unrestricted remote script execution introduces remote code execution (RCE) vulnerabilities.
- **Forensic Disconnect**: Disparate endpoints generate fragmented artifacts that cannot be easily correlated across systems.

JOCKY addresses this problem statement through a purpose-built forensic programming language, deterministic threat detection engine, and central correlation platform.

---

## 2. Requirement Traceability Matrix

| Requirement Domain | Detailed Functional Requirement | JOCKY Implementation | Verification Method | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Domain-Specific Language (DSL)** | Verifiable, declarative language for forensic querying without Turing-complete vulnerabilities. | Custom Lexer, Parser, AST, Semantic Analyzer, and Linear IR in `compiler/`. | `tests/test_lexer.py`, `tests/test_parser.py`, `tests/test_compiler.py` | **100% Implemented & Verified** |
| **Cross-Platform Forensic Collection** | Read-only extraction of processes, sockets, services, drivers, persistence, and memory. | Native Win32/Registry collector (`windows_collector.py`) and Linux `/proc`/systemd collector (`linux_collector.py`). | `tests/test_collectors.py`, `python cli.py --real` | **100% Implemented & Verified** |
| **Evidence Integrity & Custody** | Cryptographic proof of non-tampering and auditable custody ledger. | Canonical JSON serialization, SHA-256 evidence hashing, hash-linked custody ledger in `evidence/store.py` and `server/models/`. | `tests/test_evidence_store.py`, `python -m scripts.e2e_security_demo` | **100% Implemented & Verified** |
| **Automated Threat Detection** | Deterministic detection rules mapped to standard threat frameworks. | 15 deterministic detection rules across 7 domains mapped to MITRE ATT&CK tactics & techniques in `detection/`. | `tests/test_detection_engine.py`, `python cli.py --real --detect` | **100% Implemented & Verified** |
| **Multi-System Orchestration** | Central server managing distributed endpoint agents, jobs, and evidence ingestion. | FastAPI backend (`server/main.py`), lightweight endpoint agent daemons (`agent/agent.py`), heartbeat monitoring. | `tests/test_e2e_pipeline.py`, `python -m scripts.e2e_demo` | **100% Implemented & Verified** |
| **Enterprise Governance & RBAC** | Strict multi-tenancy, authentication, role-based access control, and audit logging. | Salted PBKDF2 hashing, JWT authentication, 7 RBAC roles, organization isolation, append-only audit trail in `server/security/`. | `tests/test_security_enterprise.py`, `tests/test_signer_verifier_roles.py` | **100% Implemented & Verified** |
| **Forensic Correlation & Graph** | Cross-system entity correlation, unified timeline reconstruction, and graph visualization. | Normalization engine, directional relationship mapping, IOC extraction, SVG force graph, and global search in `forensics/`. | `tests/test_correlation_subsystem.py`, `python -m scripts.e2e_correlation_demo` | **100% Implemented & Verified** |
| **Analyst Web Dashboard** | Modern responsive interface for triage, script validation, and visual investigation. | React 18 + TypeScript + Tailwind CSS application with 10 dedicated DFIR pages and interactive modals. | Production build (`npm run build`), manual UI verification | **100% Implemented & Verified** |

---

## 3. Defense-Only Scope vs. Offensive Evasion Capabilities

A foundational architectural requirement of JOCKY is **strict adherence to authorized, defensive digital forensics**. JOCKY is engineered exclusively for detection, triage, and post-incident investigation.

### 3.1 Prohibited Offensive Capabilities (Intentionally Excluded)

In strict accordance with defensive engineering principles and cybersecurity ethics, the following offensive techniques are **intentionally and rigorously excluded** from the JOCKY codebase:

1. **EDR Disabling & Antivirus Tampering**:
   - JOCKY does not contain code to terminate, suspend, or unload defensive security agents.
   - *Defensive Counterpart*: JOCKY includes detection rules that identify when unauthorized services attempt to stop security products.
2. **Process Hollowing & Reflective DLL Injection**:
   - The JOCKY execution runtime contains no Windows memory manipulation APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) that could be abused for memory injection.
   - *Defensive Counterpart*: The `AnalyzeMemory` and `ScanProcesses` modules inspect suspect process memory metrics (commit ratios, anomalous threads) to detect injected code.
3. **API Unhooking & Direct Syscall Evasion**:
   - JOCKY relies on standard, legitimate Win32 and Linux userland APIs. It does not unhook NTDLL or perform manual syscall stubs to evade monitored hooks.
   - *Defensive Counterpart*: Standard API calls maintain full forensic transparency and auditability.
4. **Bring Your Own Vulnerable Driver (BYOVD) Exploitation**:
   - JOCKY never loads kernel drivers to gain ring-0 code execution.
   - *Defensive Counterpart*: The `ScanDrivers` module explicitly compares loaded drivers against known vulnerable driver blocklists (e.g., LOLDrivers) to detect adversaries utilizing BYOVD tactics.
5. **Credential Dumping & Memory Scraping**:
   - JOCKY does not access LSASS process memory or attempt to extract plaintext passwords or Kerberos tickets.
   - *Defensive Counterpart*: JOCKY flags unauthorized access attempts to sensitive processes in audit telemetry.

### 3.2 Security and Legal Admissibility Rationale

Digital forensic evidence must satisfy strict legal standards (such as Federal Rules of Evidence Rule 902 in the US, or Section 65B of the Indian Evidence Act):
- **Reproducibility**: Forensic tools must produce identical results when executed under identical conditions.
- **Zero Host Contamination**: Tools must not alter system state or introduce malware-like evasion artifacts.
- **Accountability**: Every collection action must be logged and bound to an authenticated operator.

By enforcing an IR allow-list, read-only collection APIs, canonical JSON SHA-256 hashing, and immutable chain-of-custody logging, JOCKY delivers enterprise forensic readiness that stands up to scrutiny in legal proceedings.
