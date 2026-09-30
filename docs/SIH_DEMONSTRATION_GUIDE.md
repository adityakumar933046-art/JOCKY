# JOCKY — SIH Live Demonstration Guide

This guide provides a comprehensive, step-by-step procedure for evaluators and presenters demonstrating the **JOCKY Digital Forensics Platform** during the Smart India Hackathon (SIH) evaluation.

---

## 1. Quick Launch Checklist

Before starting the presentation, verify that the platform services are operational:

```bash
# 1. Start Central Server (Terminal 1)
python -m uvicorn server.main:app --host 127.0.0.1 --port 8000

# 2. Start Analyst Dashboard (Terminal 2)
cd frontend && npm run dev -- --host 127.0.0.1

# 3. Start Endpoint Agent (Terminal 3)
python -m agent.agent
```

*Analyst Web Dashboard*: `http://localhost:5173` (or `http://localhost:5174` if 5173 is occupied)  
*Interactive REST API Documentation*: `http://localhost:8000/docs`

---

## 2. 12-Step Demonstration Matrix

| Step | Action | Command / Operation | Expected Result | UI Screen | Key Point to Explain |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | **Environment & Health Verification** | `curl http://localhost:8000/api/health` | HTTP 200 with `status: healthy`, database connection active, platform version verified. | Terminal / Swagger Docs | Central FastAPI server is ready, multi-tenant database initialized with seeded organizations. |
| **2** | **Standalone JOCKY Script Compilation** | `python cli.py examples/forensic_complete.jocky` | Script parses cleanly into AST and emits linear IR opcodes (`SYSTEM_INFO`, `SCAN`, `DETECT`, `REPORT`). | Terminal CLI | Demonstrates JOCKY DSL compiler pipeline (Lexer, Parser, AST, Semantic Analyzer, IR) running in safe simulation mode. |
| **3** | **Live Real Collection & Threat Detection** | `python cli.py examples/forensic_complete.jocky --real --detect` | 8 real host evidence records collected via Win32/Linux APIs, canonical SHA-256 hashes generated, threat detection executed. | Terminal CLI | Strict read-only live host collection. No shell/PowerShell/Bash execution. Deterministic 15-rule detection engine. |
| **4** | **Multi-Role Authentication & RBAC** | Navigate to Web UI, click quick demo buttons (`admin`, `analyst`, `signer`, `verifier`). | Instant authentication via PBKDF2-HMAC-SHA256 and JWT tokens. Role badge displayed in header. | `/login` & Top Header | 7-tier RBAC (`SUPER_ADMIN`, `ORG_ADMIN`, `SECURITY_ANALYST`, `SIGNER`, `VERIFIER`, `INVESTIGATOR`, `VIEWER`). Strict least-privilege enforcement. |
| **5** | **Agent Trust Lifecycle & Fleet Health** | Navigate to Agents tab, view enrolled endpoints, inspect trust states. | Connected agents display hostname, OS, IP, active trust badge (`AUTHORIZED`), and real-time heartbeat. | `/agents` | Cryptographic hardware-bound agent identities. 4 trust lifecycle states (`PENDING`, `AUTHORIZED`, `SUSPENDED`, `REVOKED`). |
| **6** | **JOCKY Script Authoring & Validation** | On Jobs page, click **Create Job**, select **Complete Threat Assessment**, click **Validate JOCKY Script**. | Green validation badge with compiled AST node count, token count, and strict IR allow-list confirmation. | `/jobs` Modal | Server-side static verification. Disallows any unrecognized opcodes or injection vectors before execution. |
| **7** | **Job Dispatch & Automated Ingestion** | Click **Submit Job**. Watch agent pick up job, execute read-only collections, and complete. | Job status transitions: `PENDING` -> `RUNNING` -> `COMPLETED`. Evidence records and findings auto-ingested. | `/jobs` Table | Asynchronous job queue, distributed execution, zero disruption to suspect endpoint, deterministic output. |
| **8** | **Evidence Integrity & Chain of Custody** | Open Evidence page, click **Verify Hash** on any evidence record. Inspect ledger. | Checksum verification succeeds (`STATUS: VALID`). Hash-linked chain-of-custody ledger records all access. | `/evidence` & Custody Modal | Canonical JSON serialization ensures bit-for-bit SHA-256 reproducibility. Court-admissible forensic proof. |
| **9** | **Threat Detection & MITRE Mapping** | Navigate to Findings tab. Filter by severity (`CRITICAL`, `HIGH`). View finding details. | Categorized threats displayed with confidence scores, MITRE ATT&CK tactics/techniques, and remediation advice. | `/findings` | 15 deterministic detection rules across 7 domains (Process, Persistence, Network, Driver, Memory, Service, File). |
| **10** | **Cross-System Threat Correlation** | Open Correlations page. Inspect multi-host attack campaigns. | Correlated clusters linking Windows and Linux endpoints communicating with the same external C2 or sharing hashes. | `/correlations` | Correlates decentralized endpoint evidence to detect lateral movement and coordinated threat campaigns. |
| **11** | **Interactive Investigation Cockpit** | Navigate to Investigations page, open a case, explore the interactive entity graph. | Force-directed SVG topology graph with node clustering, severity rings, and clickable entity detail drawers. | `/investigations` | Visual incident triage: processes, network sockets, drivers, and files displayed in dynamic relationship topology. |
| **12** | **Global Forensic Search & Export** | Press `Ctrl+K` to open Global Search, search for suspicious IP or hash. Export formal report. | Instant cross-platform search results across all artifacts. Executive HTML and JSON report downloaded. | Global Modal & `/reports` | Sub-second search across thousands of normalized artifacts; signed, tamper-proof executive deliverables. |

---

## 3. Key Talking Points for Judges & Evaluators

1. **Safety-First Engineering**: Unlike offensive frameworks or ad-hoc scripts, JOCKY operates strictly through read-only forensic collectors. It possesses zero capabilities to modify files, inject code, or tamper with system logs.
2. **Deterministic IR**: General-purpose scripts can execute unpredictable subprocesses. JOCKY enforces a mathematical guarantee: only pre-approved IR opcodes can execute on endpoints.
3. **Legal Admissibility**: By combining canonical JSON hashing (SHA-256) with an immutable, hash-linked chain-of-custody ledger, JOCKY preserves digital evidence integrity meeting forensic standards.
4. **Platform Unification**: Evaluators can observe Windows (Win32/Registry) and Linux (`/proc`/systemd) data normalized into identical schemas, enabling true cross-platform detection and correlation.
