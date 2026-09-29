# JOCKY — Digital Forensics Programming Language & Investigation Platform

[![Tests](https://img.shields.io/badge/Tests-127%20Passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-teal.svg)]()
[![React](https://img.shields.io/badge/React-18-cyan.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)]()

**JOCKY** is a domain-specific programming language (DSL) and multi-system digital forensics and incident response (DFIR) platform designed for authorized computer and network forensic investigation. It enables security analysts, incident responders, and forensic auditors to write declarative, verifiable triage scripts that execute safe, read-only evidence collections across Windows and Ubuntu/Linux hosts, correlate artifacts, detect advanced persistent threat indicators, and conduct investigations via a modern web interface.

---

## 1. Problem Statement & Mission

Traditional forensic triage often relies on inconsistent, fragmented, and error-prone shell scripts (PowerShell, Bash) executed directly on suspect systems. This approach introduces significant risks:
- **Triage Inconsistency**: Different investigators collect different data with disparate schemas.
- **Accidental System Modification**: Unvetted shell commands risk modifying timestamps, deleting forensic artifacts, or altering system state.
- **Lack of Defense-in-Depth**: Unrestricted remote execution channels open avenues for arbitrary command injection or tool abuse.
- **Broken Chain of Custody**: Evidence is often transferred without cryptographic checksums or verifiable access audit trails.

**JOCKY solves this by introducing a domain-specific language and centralized architecture:**
- **Declarative & Verifiable**: Scripts are parsed into an Abstract Syntax Tree (AST) and compiled into linear Intermediate Representation (IR) opcodes validated against a strict allow-list.
- **Strictly Read-Only**: The forensic runtime and collectors perform only non-destructive, read-only data extraction. Arbitrary shell, PowerShell, or Bash execution is strictly forbidden.
- **Cryptographic Evidence Integrity**: Every captured evidence record receives a canonical SHA-256 checksum and immutable, hash-linked chain-of-custody ledger.
- **Multi-Tenant Governance**: Enterprise RBAC, organization isolation, agent trust states, and append-only audit logging ensure defense-grade accountability.

---

## 2. High-Level Architecture

```
                    JOCKY Forensic Script (*.jocky)
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │      Compiler Pipeline       │
                    │   Lexer -> Parser -> AST     │
                    │   -> Semantic Analyzer       │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  JOCKY Intermediate Rep (IR) │
                    │   Strict IR Allow-List Audit │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │   Forensic Runtime Engine    │
                    │  Simulation or Real Runtime  │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴───────────────┐
                    ▼                              ▼
      ┌───────────────────────────┐  ┌───────────────────────────┐
      │     Windows Collector     │  │      Linux Collector      │
      │   (Win32, Registry, APIs) │  │  (/proc, /etc, systemd)   │
      └─────────────┬─────────────┘  └─────────────┬─────────────┘
                    │                              │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  Structured Evidence Store   │
                    │   Canonical SHA-256 Hashing  │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │    Threat Detection Engine   │
                    │  Rule Registry (7 Domains)   │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │    Central FastAPI Server    │
                    │ RBAC, Org Isolation, Trust   │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │   Forensic Normalization     │
                    │    NormalizedArtifacts       │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │   Artifact Relationships     │
                    │    Deterministic Links       │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  Indicator (IOC) Extractor   │
                    │  IP, Domain, Port, Hash      │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │   Cross-System Correlation   │
                    │  Fleet-wide Campaign Finders │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │    Investigation Cockpit     │
                    │  Graph, Timeline, Reports    │
                    └──────────────────────────────┘
```

---

## 3. Features & Platform Capabilities

### Language & Compiler (Step 1)
- **Declarative JOCKY DSL**: Human-readable syntax for system triage, process enumeration, network auditing, file scanning, service analysis, and driver verification.
- **Static Semantic Analysis**: Validates syntax, keyword arguments, and program structure prior to execution.
- **Linear IR Generation**: Emits deterministic, serializable intermediate representation opcodes (`SYSTEM_INFO`, `SCAN`, `ANALYZE`, `REPORT`).

### Platform-Specific Collectors (Step 2)
- **Windows Collector**: Native Win32 API and Registry inspection for processes, network sockets, drivers, services, autostart entries, and memory metrics.
- **Ubuntu/Linux Collector**: Direct kernel pseudo-filesystem (`/proc`, `/sys`), systemd service inspection, network routing, and cron persistence audit.
- **Non-Destructive & Read-Only**: Enforces safety constraints preventing host modification.

### Rule-Based Threat Detection (Step 3)
- **Independent Rule Registry**: 15 out-of-the-box detection rules across 7 operational categories:
  - `PROCESS`: Parent-child anomalies, temp execution, missing binary metadata.
  - `PERSISTENCE`: Suspicious registry autoruns, suspicious cron job paths.
  - `DRIVER`: Known vulnerable drivers (BYOVD risk), path anomalies.
  - `NETWORK`: Unexpected outbound traffic, unusual listening ports, high-frequency beacons.
  - `MEMORY`: Excessive virtual commit ratios, high thread anomalies.
  - `SERVICE`: Binary path anomalies, unquoted service paths.
  - `FILE`: Suspicious extensions, executable masquerading in temp directories.
- **Confidence Scoring & Severity Ranks**: Standardized scoring (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

### Central Multi-System Architecture (Step 4)
- **Central FastAPI Server**: REST API orchestrating job queues, evidence ingestion, and investigation cases.
- **Distributed JOCKY Agents**: Lightweight daemons for Windows and Linux endpoints with automated enrollment and liveness heartbeats.
- **Defense-in-Depth IR Allow-List**: Validated at both the Central Server and on local Agents before any collection begins.

### Enterprise Security Architecture (Step 5)
- **User Authentication**: Salted PBKDF2-HMAC-SHA256 password hashing with configurable iteration counts and brute-force lockout protection.
- **5-Tier Role-Based Access Control (RBAC)**: `SUPER_ADMIN`, `ORGANIZATION_ADMIN`, `SECURITY_ANALYST`, `INVESTIGATOR`, and `VIEWER`.
- **Multi-Tenant Organization Isolation**: Strict tenant isolation across agents, jobs, evidence, findings, and cases.
- **Agent Trust Lifecycle**: Four-state trust governor (`PENDING` -> `AUTHORIZED` -> `SUSPENDED` -> `REVOKED`).
- **Cryptographic Evidence Integrity**: Deterministic canonical SHA-256 hashing detects any post-acquisition evidence tampering.
- **Hash-Linked Chain of Custody**: Verifiable audit trail recording every evidence transition (`COLLECTED`, `RECEIVED`, `TRANSFERRED`, `VIEWED`, `ARCHIVED`).
- **Append-Only Audit Ledger**: Security audit logging recording actor, organization, IP, resource, and outcome.

### Advanced Forensic Investigation & Correlation (Step 6)
- **Forensic Normalization Engine**: Translates heterogeneous endpoint data into uniform `NormalizedArtifact` schemas.
- **Artifact Relationship Engine**: Deterministic directional links (`PARENT_OF`, `CONNECTED_TO`, `LOCATED_AT`, `EXECUTED_FROM`, `SPAWNED`, `ASSOCIATED_WITH`).
- **IOC Extraction & Indexing**: Automatic classification and severity scoring for IP addresses, file hashes, domains, and paths.
- **Cross-System Correlation**: Detects shared C2 channels and identical malicious hashes operating across different operating systems.
- **Master Chronological Timeline**: Unified chronological reconstruction of all security events.
- **Interactive Entity Graph**: SVG force-directed topology visualizer with node clustering, severity rings, and metadata drawers.
- **Analyst Investigation Cockpit**: 10-tab investigation modal, global forensic search (`Ctrl+K`), collaborative case notes, and point-in-time snapshots.

---

## 4. Repository Structure

```
JOCKY/
├── compiler/              # JOCKY DSL Compiler (Lexer, Parser, AST, Semantic, IR)
├── runtime/               # Forensic execution engine & platform collectors
│   └── collectors/        # Windows and Linux read-only collectors
├── evidence/              # EvidenceRecord models, store, and canonical serializers
├── detection/             # Threat Detection Engine, Rule Registry, and Detection Rules
├── reports/               # Threat report generators (JSON & console formatters)
├── agent/                 # JOCKY Endpoint Agent daemon & local job executor
├── server/                # Central FastAPI Forensic Platform
│   ├── api/               # REST API endpoints (agents, jobs, evidence, auth, etc.)
│   ├── models/            # SQLAlchemy database models (PostgreSQL & SQLite)
│   ├── schemas/           # Pydantic schemas with strict validation
│   ├── security/          # RBAC, JWT, PBKDF2 cryptography, and token revocation
│   └── services/          # Business logic, audit logging, and correlation services
├── forensics/             # Step 6 Advanced Forensic Correlation Subsystem
│   ├── normalization/     # Canonical normalization engine & item-type inference
│   ├── correlation/       # Cross-artifact & cross-system correlation rules
│   ├── indicators/        # IOC extraction, deduplication, and severity ranking
│   ├── timeline/          # Master chronological timeline aggregator
│   └── graph/             # Dynamic topology entity graph generator
├── frontend/              # Analyst Web Dashboard (React 18 + TypeScript + Vite)
│   └── src/
│       ├── components/    # Reusable UI widgets, graph visualizer, search modal
│       ├── pages/         # 10 dedicated DFIR analysis views
│       └── services/      # REST API client services
├── examples/              # Sample JOCKY forensic scripts (*.jocky)
├── scripts/               # End-to-end multi-step verification demonstration scripts
│   ├── e2e_demo.py             # Step 4 Multi-System Collection E2E (15 checks)
│   ├── e2e_security_demo.py    # Step 5 Enterprise Security E2E (27 checks)
│   └── e2e_correlation_demo.py # Step 6 Correlation & Investigation E2E (20 checks)
├── tests/                 # Comprehensive pytest test suite (127+ tests)
├── cli.py                 # Standalone JOCKY Forensic CLI
├── requirements.txt       # Python package dependencies
├── .env.example           # Environment template configuration
└── README.md              # Project documentation
```

---

## 5. Installation & Setup

### Prerequisites
- **Python**: 3.11, 3.12, or 3.13
- **Node.js**: v18+ and **npm**
- **Operating System**: Windows 10/11 or Ubuntu/Debian Linux

### 1. Python Environment Setup
```bash
# Clone the repository
git clone https://github.com/adityakumar933046-art/JOCKY.git
cd JOCKY

# Create and activate a virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install backend dependencies
pip install -r requirements.txt
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run build
cd ..
```

### 3. Environment Configuration
Copy `.env.example` to `.env` and set your configuration:
```bash
cp .env.example .env
```
*(On Windows: `copy .env.example .env`)*

---

## 6. Running the Platform

### Option A: Local Forensic CLI (Standalone)
Execute forensic investigations locally on Windows or Linux without running a central server:
```bash
# Simulation mode (compiles and displays planned forensic collection)
python cli.py examples/forensic_scan.jocky

# Real collection mode with rule-based threat detection
python cli.py examples/forensic_scan.jocky --real --detect

# Structured JSON export
python cli.py examples/forensic_scan.jocky --real --detect --json
```

### Option B: Central Distributed Platform

#### 1. Start the Central FastAPI Server
```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```
Interactive OpenAPI / Swagger documentation will be available at: `http://localhost:8000/docs`.

#### 2. Start an Endpoint Agent
```bash
python -m agent.agent
```
The agent automatically generates a persistent hardware identity (`.jocky_agent_identity.json`), registers with the server, enters `PENDING` trust state, sends heartbeats, and polls for authorized forensic jobs.

#### 3. Launch the Web Dashboard
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser to access the DFIR workspace.

---

## 7. Verification & Testing

### Complete Unit & Integration Suite
Run all 127 automated tests:
```bash
python -m pytest tests -v
```

### End-to-End Verification Demonstrations

#### Step 4 Multi-System Collection E2E (15 Checks)
```bash
python -m scripts.e2e_demo
```
Verifies server health, agent registration, heartbeat recording, compiler validation, job dispatch, local execution, evidence/finding ingestion, timeline generation, and HTML/JSON report export.

#### Step 5 Enterprise Security E2E (27 Checks)
```bash
python -m scripts.e2e_security_demo
```
Verifies JWT authentication, PBKDF2 password security, 5-tier RBAC enforcement, multi-tenant organization isolation, agent trust states, canonical SHA-256 evidence integrity, tampering detection, hash-linked chain of custody, and append-only audit logging.

#### Step 6 Advanced Investigation & Correlation E2E (20 Checks)
```bash
python -m scripts.e2e_correlation_demo
```
Verifies multi-endpoint evidence ingestion, canonical normalization, IOC indexing, directional artifact relationships, cross-system C2 correlation, multi-stage campaign findings, dynamic entity graph generation, master timeline, global search (`Ctrl+K`), case notes, point-in-time snapshots, and executive HTML report generation.

---

## 8. Forensic Model & Data Lifecycles

The platform maintains a clear separation between observable evidence, derived relationships, and analyst interpretation:

1. **Original Evidence (`EvidenceRecord`)**: Unmodified raw output captured directly from the operating system, signed with a canonical SHA-256 content hash. Never mutated.
2. **Normalized Artifact (`NormalizedArtifact`)**: Uniformly structured representations (Process, Network, File, Service, Driver, Persistence) linking back to original `evidence_id`.
3. **Artifact Relationship (`ArtifactRelationship`)**: Deterministic directional links (`source -> relationship_type -> target`) identifying process execution parents, sockets, and persistence.
4. **Forensic Indicator (`Indicator`)**: Extracted and indexed IOCs (IPs, domains, hashes, paths) with frequency metrics and severity ratings.
5. **Threat Finding (`Finding`)**: Rule-based technical indicators generated by the Threat Detection Engine with MITRE ATT&CK categorization.
6. **Correlation (`CrossSystemCorrelation`)**: Multi-endpoint correlation linking distinct hosts communicating with identical threat indicators.
7. **Investigation Case (`Investigation`)**: Collaborative analyst workspace containing affected endpoints, master timeline, entity graph, collaborative notes, snapshots, and formal reports.

---

## 9. Security Model & Defensive Scope

### Defensive Scope Statement
JOCKY is strictly an **authorized digital forensics and incident response** tool.
- **NO process injection** (no CreateRemoteThread, WriteProcessMemory, NtWriteVirtualMemory)
- **NO process hollowing or reflective DLL injection**
- **NO thread hijacking, API unhooking, or direct syscall evasion**
- **NO BYOVD exploitation or driver weaponization**
- **NO EDR/AV disabling or security-control bypass**
- **NO persistence creation or privilege escalation**
- **NO arbitrary remote shell or command execution**

### IR Allow-List Guarantee
Agents only execute pre-authorized, read-only forensic collection opcodes validated by the compiler:
- `SYSTEM_INFO`
- `SCAN` (`PROCESSES`, `NETWORK`, `FILES`, `DRIVERS`, `SERVICES`)
- `ANALYZE` (`PERSISTENCE`, `MEMORY`, `NETWORK`)
- `REPORT` (`<report_name>`)

Any script containing unrecognized opcodes, shell invocations, or injection keywords is rejected immediately with a 400 Bad Request error.

---

## 10. Known Limitations

- **Kernel Memory Inspection**: JOCKY collectors operate in userland and rely on standard OS APIs and kernel pseudo-filesystems; full physical memory dump analysis (e.g. Volatility-style raw RAM parsing) requires external memory acquisition tools.
- **Live Windows Registry Writing**: The registry collector is strictly read-only and queries keys via the standard Win32 `winreg` interface without taking registry hive file locks.
- **Encrypted Network Traffic**: Network collectors audit socket endpoints, states, and process ownership; deep packet inspection (DPI) of encrypted TLS payloads is out of scope.

---

## 11. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
