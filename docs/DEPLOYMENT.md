# JOCKY Production Deployment Guide

## 1. Production Architecture Overview

The JOCKY Digital Forensics Platform uses a secure, unified multi-tier production architecture designed for high throughput, defense-in-depth security, and non-destructive incident triage:

```
                    INTERNET (Analysts & Distributed Agents)
                                      │
                                      ▼ HTTPS / TLS (Port 443)
                       ┌──────────────────────────────┐
                       │ Cloudflare Edge / TLS Proxy  │
                       │   DDoS, SSL/TLS Termination  │
                       └──────────────┬───────────────┘
                                      │
                                      ▼ Reverse Proxy / Tunnel
                       ┌──────────────────────────────┐
                       │   JOCKY Production Host      │
                       └──────────────┬───────────────┘
                                      │
                       ┌──────────────┴───────────────┐
                       ▼                              ▼
        ┌─────────────────────────────┐┌─────────────────────────────┐
        │   React 18 SPA (Vite)       ││   FastAPI ASGI Application  │
        │ Static Asset Bundle (Cached)││  (Uvicorn Workers, RBAC)   │
        └──────────────┬──────────────┘└──────────────┬──────────────┘
                       │                              │
                       │                              ▼
                       │               ┌─────────────────────────────┐
                       └──────────────>│  Private Database Network   │
                                       │ PostgreSQL 16 / Dev SQLite  │
                                       │   (Non-Exposed, Internal)   │
                                       └─────────────────────────────┘
```

### Key Architectural Characteristics
- **Unified Single-Origin Serving**: The compiled production React bundle (`frontend/dist`) is served directly by the production application server with SPA client-side fallback routing. This completely eliminates CORS issues, preflight latency, and mixed-content SSL warnings.
- **Strict HTTPS/TLS Termination**: All public traffic passes through TLS termination with HTTP-to-HTTPS redirection and defensive security headers (`HSTS`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`).
- **Isolated Database Boundary**: The production database (PostgreSQL 16) resides on an isolated internal network (`jocky-internal`) with no public internet port exposure.
- **Cryptographic Agent Ingestion**: Distributed Windows and Linux agents communicate with the central server via TLS-encrypted REST endpoints using hardware-bound tokens and canonical SHA-256 evidence seals.

---

## 2. Environment Variables & Configuration

Configure production settings using environment variables. An example template is provided in `.env.example`:

| Variable | Description | Production Default / Example | Required |
| :--- | :--- | :--- | :---: |
| `ENVIRONMENT` / `JOCKY_ENV` | Application environment mode | `production` | **Yes** |
| `DEBUG` | Enable/disable debug diagnostics | `false` | **Yes** |
| `PORT` | ASGI listening port | `8000` | No |
| `SECRET_KEY` / `JOCKY_SECRET_KEY` | Master server secret (min 32 chars) | Cryptographically random string | **Yes** |
| `DATABASE_URL` | PostgreSQL or SQLite database URI | `postgresql://user:pass@db:5432/jocky` | **Yes** |
| `CORS_ORIGINS` | Comma-separated allowed web origins | `https://your-domain.com` | Optional |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Lifetime of JWT session tokens | `120` | No |
| `JOCKY_PBKDF2_ITERATIONS` | PBKDF2 password hashing rounds | `310000` (production default) | No |
| `JOCKY_SERVER_URL` | Base HTTPS URL for distributed agents | `https://your-domain.com` | **Yes (Agents)** |

---

## 3. Database Setup & Migration

### PostgreSQL Production Setup

1. **Provision Managed PostgreSQL or Docker Container**:
   ```bash
   docker run -d \
     --name jocky-postgres \
     --network jocky-internal \
     -e POSTGRES_DB=jocky \
     -e POSTGRES_USER=jocky_admin \
     -e POSTGRES_PASSWORD=SecurePassword2026! \
     -v jocky_pgdata:/var/lib/postgresql/data \
     postgres:16-alpine
   ```

2. **Initialize Database Schema & Verify Tables**:
   Execute the automated schema initialization and verification script:
   ```bash
   export DATABASE_URL="postgresql://jocky_admin:SecurePassword2026!@localhost:5432/jocky"
   python -m scripts.init_production_db
   ```
   *The script creates all 22 database tables, verifies primary keys and indexes, and seeds default administrative roles (`admin`, `analyst`, `signer`, `verifier`).*

---

## 4. Native Deployment Procedure

### Step 1: Clone and Prepare Environment
```bash
git clone https://github.com/adityakumar933046-art/JOCKY.git
cd JOCKY

# Create Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
pip install psycopg2-binary gunicorn
```

### Step 2: Build the Production Frontend
```bash
cd frontend
npm install
npm run build
cd ..
```

### Step 3: Configure Production Environment
```bash
cp .env.example .env
# Populate SECRET_KEY and DATABASE_URL with secure production values
```

### Step 4: Launch Production ASGI Server
```bash
# On Linux / Production Host with Uvicorn workers:
python -m uvicorn server.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --no-access-log
```

---

## 5. Docker Deployment Procedure

The repository provides a multi-stage `Dockerfile` and `docker-compose.yml`:

```bash
# 1. Start Database and Backend Services
docker compose up -d --build

# 2. Check Service Logs
docker compose logs -f jocky-server

# 3. Check Health
curl http://localhost:8000/health
```

---

## 6. HTTPS & Public Domain Configuration

To expose the application securely over public HTTPS:

### Option A: Cloudflare Edge Tunnel (Recommended & Zero-Config)
```bash
# Launch Cloudflare edge tunnel pointing to the production port
cloudflared tunnel --url http://127.0.0.1:8000
```
*Cloudflare generates a live public HTTPS URL with automatic TLS termination and DDoS mitigation.*

### Option B: Nginx Reverse Proxy with Let's Encrypt Certbot
```nginx
server {
    listen 80;
    server_name jocky.your-domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name jocky.your-domain.com;

    ssl_certificate /etc/letsencrypt/live/jocky.your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/jocky.your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

---

## 7. Distributed Agent Configuration

To connect remote Windows and Linux agents to the central server:

1. **Set Server URL**:
   Set `JOCKY_SERVER_URL` in the agent environment or configuration:
   ```bash
   export JOCKY_SERVER_URL="https://your-domain.com"
   ```
2. **Start Agent**:
   ```bash
   python -m agent.agent
   ```
3. **Approve Agent in Dashboard**:
   - Log in to the Web Dashboard as an Administrator.
   - Navigate to `/agents`.
   - Locate the newly registered agent (in `PENDING` state).
   - Click **Approve** to transition the agent to `AUTHORIZED`.

---

## 8. Rollback Procedure

If a deployment rollback is necessary:
1. Revert to the prior Git release tag: `git checkout <PREVIOUS_COMMIT>`
2. Re-run frontend build: `cd frontend && npm run build && cd ..`
3. Restart ASGI application workers: `systemctl restart jocky-server` (or `docker compose restart`)
4. Verify health endpoint: `curl -f https://your-domain.com/health`
