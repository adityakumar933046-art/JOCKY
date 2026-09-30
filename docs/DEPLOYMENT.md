# JOCKY Production Deployment Guide
## Vercel Frontend + Render Backend + Render PostgreSQL

This guide provides the complete, professional deployment manual for operating the **JOCKY Digital Forensics Platform** in a distributed production cloud environment utilizing **Vercel** for the React/Vite frontend and **Render** for the FastAPI backend and managed PostgreSQL database.

---

## 1. Target Production Architecture

```
                               INTERNET
                                  │
                                  ▼ HTTPS / TLS
                   ┌──────────────────────────────┐
                   │       VERCEL PLATFORM        │
                   │   React 18 + Vite Frontend   │
                   │ (Global Edge CDN, SSL, WAF)  │
                   └──────────────┬───────────────┘
                                  │
                                  ▼ HTTPS (REST API)
                   ┌──────────────────────────────┐
                   │       RENDER PLATFORM        │
                   │    FastAPI ASGI Backend      │
                   │   (Uvicorn Workers, RBAC)    │
                   └──────────────┬───────────────┘
                                  │
                                  ▼ Private Internal Network
                   ┌──────────────────────────────┐
                   │      RENDER POSTGRESQL       │
                   │  Managed Database (16-Alpine)│
                   │   (22 Relational Tables)     │
                   └──────────────────────────────┘
```

### Architectural Guarantees
- **Front-to-Back Isolation**: The Vercel frontend contains zero backend business logic or database credentials. It communicates exclusively over HTTPS using JSON Web Tokens (JWT) and signed request headers.
- **Render PostgreSQL Protection**: The managed database is bound to Render's internal network and never exposed to the public internet.
- **Defense-Only Read-Only Collection**: All endpoint triage instructions dispatched through this architecture strictly execute JOCKY IR allow-listed operations without arbitrary command execution or shell injection capabilities.

---

## 2. Repository Blueprint & Structure

The repository contains pre-configured blueprints for automated deployment:

```
JOCKY/
├── render.yaml            # Render Infrastructure-as-Code Blueprint
├── vercel.json            # Root Vercel SPA routing & build configuration
├── frontend/
│   ├── vercel.json        # Sub-folder Vercel configuration
│   ├── package.json       # Node.js dependencies (React 18, Vite, Tailwind CSS)
│   └── src/services/api.ts # API client with dynamic VITE_API_BASE_URL resolution
├── server/
│   ├── main.py            # FastAPI production application entry point (server.main:app)
│   ├── config.py          # Environment settings with auto postgresql:// normalization
│   └── database.py        # SQLAlchemy engine supporting PostgreSQL and SQLite
├── scripts/
│   └── init_production_db.py # Production schema creator & 22-table verification
├── start.py               # Dynamic cloud bootloader (binds to $PORT on Render/Fly/Docker)
├── requirements.txt       # Python dependencies (includes psycopg2-binary & gunicorn)
└── .env.example           # Production environment variable reference
```

---

## 3. Deployment Step-by-Step

### Step A: Synchronize GitHub Repository
Ensure the latest codebase is pushed to `main` on GitHub:
```bash
git status
git push origin main
```
*Repository*: `https://github.com/adityakumar933046-art/JOCKY.git`

---

### Step B: Deploy Render Backend & PostgreSQL Database

1. **Log in to Render**: Navigate to [https://dashboard.render.com](https://dashboard.render.com).
2. **Deploy via Blueprint (Recommended)**:
   - Click **New +** -> **Blueprint**.
   - Connect the repository: `adityakumar933046-art/JOCKY`.
   - Render detects `render.yaml` and provisions:
     - **Database**: `jocky-postgres` (PostgreSQL 16, free/starter plan)
     - **Web Service**: `jocky-backend` (Python 3.12/3.13)
3. **Manual Configuration (Alternative)**:
   - **PostgreSQL**:
     - Name: `jocky-postgres`
     - Database: `jocky`
     - User: `jocky_admin`
   - **Web Service**:
     - Name: `jocky-backend`
     - Runtime: `Python`
     - Build Command: `pip install -r requirements.txt && python -m scripts.init_production_db`
     - Start Command: `uvicorn server.main:app --host 0.0.0.0 --port $PORT --workers 2`
     - Health Check Path: `/health`

#### Render Environment Variables

| Variable Name | Value / Source | Description |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `production` | Enables production security checks |
| `DEBUG` | `false` | Disables diagnostic debug exposure |
| `DATABASE_URL` | *From Database Connection String* | PostgreSQL connection URI |
| `SECRET_KEY` | *(Auto-generated, min 32 chars)* | Master encryption and HMAC secret |
| `JWT_SECRET` | *(Auto-generated, min 32 chars)* | JWT token signing key |
| `CORS_ORIGINS` | `https://jocky-dfir.vercel.app` | Allowed Vercel frontend origin |
| `FRONTEND_URL` | `https://jocky-dfir.vercel.app` | Primary frontend web address |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `120` | Session lifetime |
| `JOCKY_PBKDF2_ITERATIONS` | `310000` | Enterprise password hashing rounds |

---

### Step C: Verify Render Backend Health

Once Render completes the build, test the live backend:
```bash
# Verify health endpoint
curl -s https://<your-render-service>.onrender.com/health
```
**Expected Response**:
```json
{"status": "HEALTHY", "service": "JOCKY", "version": "1.0.0"}
```

---

### Step D: Deploy Vercel Frontend

1. **Log in to Vercel**: Navigate to [https://vercel.com/dashboard](https://vercel.com/dashboard).
2. **Import Project**:
   - Click **Add New...** -> **Project**.
   - Select the `JOCKY` GitHub repository.
3. **Configure Project Settings**:
   - **Framework Preset**: `Vite`
   - **Root Directory**: `frontend` (or `.` with root `vercel.json`)
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`
4. **Configure Environment Variables**:
   Add the following environment variable under **Settings -> Environment Variables**:
   - `VITE_API_BASE_URL`: `https://<your-render-service>.onrender.com/api/v1`
   - Target: `Production`, `Preview`, `Development`
5. **Deploy**: Click **Deploy**. Vercel will build the frontend and issue an HTTPS domain (e.g., `https://jocky-dfir.vercel.app`).

---

### Step E: Update Backend CORS Origins

After Vercel generates your live frontend URL:
1. Open the Render Dashboard for `jocky-backend`.
2. Go to **Environment**.
3. Set `CORS_ORIGINS` to your exact Vercel URL:
   ```
   CORS_ORIGINS=https://jocky-dfir.vercel.app
   FRONTEND_URL=https://jocky-dfir.vercel.app
   ```
4. Save changes. Render will automatically redeploy the backend with restricted CORS.

---

## 4. End-to-End Verification Checklist

| Phase | Check | Verification Method |
| :--- | :--- | :--- |
| **Backend** | Health Check | `GET https://<render-url>/health` returns `HEALTHY` |
| **Backend** | OpenAPI Docs | `GET https://<render-url>/docs` renders Swagger UI |
| **Database** | 22 Schema Tables | Verified during build via `python -m scripts.init_production_db` |
| **Frontend** | Assets & SPA | `GET https://<vercel-url>/` loads React app with zero console errors |
| **Auth** | Login | Submitting credentials generates JWT token |
| **CORS** | Restricted Headers | Browser makes authenticated API calls without CORS errors |
| **Agents** | HTTPS Connectivity | Remote agents register via `JOCKY_SERVER_URL=https://<render-url>` |

---

## 5. Distributed Agent Ingestion over HTTPS

Remote agents connect securely to the Render backend:
```bash
# On endpoint machine:
export JOCKY_SERVER_URL="https://<your-render-service>.onrender.com"
python -m agent.agent
```
The agent enrolls in `PENDING` state, reports periodic heartbeats, and only receives jobs once promoted to `AUTHORIZED` by an administrator in the web dashboard.
