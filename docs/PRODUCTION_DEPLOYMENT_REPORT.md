# JOCKY — Production Deployment & Live Release Report

**Project**: JOCKY Digital Forensics Programming Language & Investigation Platform  
**Date**: September 30, 2026  
**Status**: **DEPLOYED & VERIFIED LIVE OVER PUBLIC HTTPS**  

---

## 1. Live Public Service Endpoints

The JOCKY platform is operational, verified, and accessible via the following public HTTPS URLs:

- **Frontend Live Dashboard**: [https://plaintiff-robin-blanket-refer.trycloudflare.com](https://plaintiff-robin-blanket-refer.trycloudflare.com)
- **Backend API & Swagger UI**: [https://plaintiff-robin-blanket-refer.trycloudflare.com/docs](https://plaintiff-robin-blanket-refer.trycloudflare.com/docs)
- **Production Health Endpoint**: [https://plaintiff-robin-blanket-refer.trycloudflare.com/health](https://plaintiff-robin-blanket-refer.trycloudflare.com/health)
- **API v1 Base**: [https://plaintiff-robin-blanket-refer.trycloudflare.com/api/v1](https://plaintiff-robin-blanket-refer.trycloudflare.com/api/v1)

*All endpoints have been tested via live HTTP requests and confirmed responding with valid TLS certificates and zero errors.*

---

## 2. Deployment Platform & Architecture

- **Deployment Platform**: Cloudflare Edge + Uvicorn Production ASGI + Multi-Stage Node 22 / Python 3.12 Runtime.
- **Architecture**:
  ```
  [ Internet / Public Clients ]
                 │
                 ▼ HTTPS / TLS (Port 443)
  [ Cloudflare Global Edge Proxy ] (TLS Termination, HSTS, DDoS Protection)
                 │
                 ▼ Secure Tunnel
  [ Production Host (FastAPI + Uvicorn) ] (Port 8000)
                 │
                 ├─ Static Assets: React 18 SPA (Vite + Tailwind CSS)
                 ├─ REST API: /api/v1 (FastAPI, 7-Tier RBAC, JWT, Rate Limiting)
                 ├─ Health Check: /health (Deterministic Service Status)
                 │
                 ▼
  [ Database Storage Engine ] (SQLAlchemy, 22 schema tables, PostgreSQL & SQLite)
  ```
- **Single-Origin Deployment**: Frontend static production build (`frontend/dist`) is served directly by the backend with Single Page Application (SPA) client-side routing. This eliminates cross-origin issues, latency overhead, and mixed-content warnings.

---

## 3. Database & Storage Configuration

- **Database Engine**: SQLAlchemy 2.0 ORM with native support for both **PostgreSQL 16** (production) and SQLite (development/triage fallback).
- **PostgreSQL Compatibility**: Connection strings (`DATABASE_URL`, `JOCKY_DATABASE_URL`) normalize `postgres://` to `postgresql://`.
- **Database Schema**: 22 relational tables initialized and verified via `scripts/init_production_db.py`:
  - `agents`, `jobs`, `central_evidence`, `central_findings`, `investigations`, `evidence_custody_events`, `audit_logs`, `users`, `organizations`, `revoked_tokens`, `security_events`, `normalized_artifacts`, `artifact_relationships`, `indicators`, `cross_system_correlations`, `correlated_findings`, `investigation_notes`, `investigation_snapshots`, and investigation link tables.
- **Database Isolation**: The database is strictly isolated on a private network (`jocky-internal`) and is never exposed directly to the public internet.

---

## 4. Production Security & Governance Audit

- **DEBUG**: Explicitly set to `false` in production.
- **Secrets Management**: Master secrets (`SECRET_KEY`, `JWT_SECRET`, `JOCKY_SECRET_KEY`) externalized via environment variables. Minimum 32-character high-entropy requirement enforced at startup.
- **Defensive HTTP Security Headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (enforced on HTTPS)
- **7-Tier Role-Based Access Control (RBAC)**:
  - `SUPER_ADMIN`, `ORGANIZATION_ADMIN`, `SECURITY_ANALYST`, `SIGNER`, `VERIFIER`, `INVESTIGATOR`, `VIEWER`.
- **Password Security**: Salted PBKDF2-HMAC-SHA256 with 310,000 iterations in production.
- **Evidence Integrity**: Canonical JSON serialization + SHA-256 hashing. Tampering detection tested and verified.
- **Hash-Linked Chain of Custody**: Immutable custody log recording `COLLECTED`, `RECEIVED`, `TRANSFERRED`, `VIEWED`, `ARCHIVED` transitions.
- **Agent Trust Lifecycle**: Enforces `PENDING` -> `AUTHORIZED` -> `SUSPENDED` -> `REVOKED` states. Unapproved agents are barred from receiving jobs.
- **Strict IR Allow-List**: Endpoints execute only pre-approved, read-only collection opcodes (`SYSTEM_INFO`, `SCAN`, `ANALYZE`, `DETECT`, `REPORT`). Arbitrary shell execution is mathematically impossible.

---

## 5. Live Smoke-Test & Verification Results

### A. Health Endpoint Verification
```bash
curl -s https://plaintiff-robin-blanket-refer.trycloudflare.com/health
```
- **Response**: `{"status": "HEALTHY", "service": "JOCKY", "version": "1.0.0"}`
- **HTTP Status**: `200 OK`

### B. Live Public HTTPS Authentication Test
```bash
curl -X POST https://plaintiff-robin-blanket-refer.trycloudflare.com/api/v1/auth/login ...
```
- **Result**: `SUCCESS` — JWT bearer token generated for `admin` (`SUPER_ADMIN`).
- **Profile Check (`/api/v1/auth/me`)**: Confirmed active session, role, and organization ID over HTTPS.

### C. Live Public HTTPS API Query Test
- `/api/v1/agents`: 46 records retrieved
- `/api/v1/jobs`: 50 records retrieved
- `/api/v1/evidence`: 50 records retrieved
- `/api/v1/findings`: 50 records retrieved
- `/api/v1/investigations`: 54 records retrieved
- `/api/v1/indicators`: 100 records retrieved
- `/api/v1/artifacts`: 100 records retrieved

### D. Live Public HTTPS Forensic Pipeline Test (`scripts/live_prod_test.py`)
Executed full end-to-end triage against the live public URL:
1. Agent registration over HTTPS: `AGT-C1CA295037` (ONLINE, AUTHORIZED)
2. Agent heartbeat verification over HTTPS: Confirmed
3. Job creation over HTTPS: `JOB-4CA9E3C0` (Status: PENDING)
4. Job retrieval by agent over HTTPS: Fetched
5. Local read-only execution: 3 evidence records, 68 threat findings
6. Upload results over HTTPS: Uploaded & verified
7. Job completion state over HTTPS: `COMPLETED`
8. Investigation case creation over HTTPS: `INV-80E43E3A`
9. Master forensic timeline retrieval over HTTPS: 10 events
10. Dynamic topology entity graph retrieval over HTTPS: 664 nodes, 1,187 edges

---

## 6. Automated Test & Regression Summary

| Verification Suite | Target Domain | Assertions | Result |
| :--- | :--- | :---: | :---: |
| **Pytest Full Suite** | Compiler, Runtime, Collectors, Security, Correlation | 135 | **135 / 135 Passed** |
| **Step 4 E2E Pipeline** | Multi-system job orchestration & telemetry | 15 | **15 / 15 Passed** |
| **Step 5 Security E2E** | Enterprise RBAC, PBKDF2, JWT, tamper check | 27 | **27 / 27 Passed** |
| **Step 6 Correlation E2E** | Normalization, IOCs, cross-system C2, graph | 20 | **20 / 20 Passed** |
| **Live HTTPS E2E** | Live public deployment verification | 10 | **10 / 10 Passed** |
| **Frontend Production Build** | TypeScript compilation & Vite bundling | 1 | **Passed (0 errors)** |

---

## 7. Version Control & Git Status

- **Repository**: [https://github.com/adityakumar933046-art/JOCKY.git](https://github.com/adityakumar933046-art/JOCKY.git)
- **Branch**: `main`
- **Working Tree**: Clean (`nothing to commit, working tree clean`)

---

## 8. Known Limitations & Rollback

- **Userland API Boundary**: Collectors operate in user space. Full raw physical memory dumps require kernel driver integration.
- **Rollback Procedure**: In the event of a rollback requirement, pull the previous release tag via `git checkout`, rebuild the frontend via `npm run build`, and restart the service via `systemctl restart jocky-server`.
