"""
JOCKY Central Forensic Platform - Main FastAPI Application.
Equipped with enterprise authentication, RBAC, immutable audit logging, and security headers.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from server.config import config
from server.database import init_db
from server.api import (
    auth_router,
    agents_router,
    jobs_router,
    evidence_router,
    findings_router,
    investigations_router,
    compiler_router,
    audit_router,
    security_router,
    artifacts_router,
    relationships_router,
    indicators_router,
    correlation_router,
    search_router,
    command_center_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize and seed database tables on startup
    init_db()
    yield


app = FastAPI(
    title=config.PROJECT_NAME,
    version=config.VERSION,
    description="Central Multi-System Digital Forensics Platform for JOCKY Agents and Investigations.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Ensure database tables and initial seed data exist immediately
init_db()

# Determine allowed CORS origins
allowed_origins = list(config.CORS_ORIGINS)
if config.FRONTEND_URL and config.FRONTEND_URL not in allowed_origins:
    allowed_origins.append(config.FRONTEND_URL)
if not allowed_origins:
    allowed_origins = ["*"]

# Enable CORS for React Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Enforce defensive HTTP security headers on all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Register API Routers under /api/v1
app.include_router(auth_router, prefix=config.API_V1_PREFIX)
app.include_router(agents_router, prefix=config.API_V1_PREFIX)
app.include_router(jobs_router, prefix=config.API_V1_PREFIX)
app.include_router(evidence_router, prefix=config.API_V1_PREFIX)
app.include_router(findings_router, prefix=config.API_V1_PREFIX)
app.include_router(investigations_router, prefix=config.API_V1_PREFIX)
app.include_router(compiler_router, prefix=config.API_V1_PREFIX)
app.include_router(audit_router, prefix=config.API_V1_PREFIX)
app.include_router(security_router, prefix=config.API_V1_PREFIX)
app.include_router(artifacts_router, prefix=config.API_V1_PREFIX)
app.include_router(relationships_router, prefix=config.API_V1_PREFIX)
app.include_router(indicators_router, prefix=config.API_V1_PREFIX)
app.include_router(correlation_router, prefix=config.API_V1_PREFIX)
app.include_router(search_router, prefix=config.API_V1_PREFIX)
app.include_router(command_center_router, prefix=config.API_V1_PREFIX)


@app.get("/health")
@app.get(f"{config.API_V1_PREFIX}/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "JOCKY",
        "version": config.VERSION,
    }


# Static Frontend & Single Page Application (SPA) Serving
frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if frontend_dist.exists() and (frontend_dist / "index.html").exists():
    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="static_assets")

    @app.get("/")
    def serve_index():
        return FileResponse(str(frontend_dist / "index.html"))

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str):
        # Exclude API endpoints, docs, and openapi schema
        if (
            full_path.startswith("api/")
            or full_path.startswith("docs")
            or full_path.startswith("redoc")
            or full_path.startswith("openapi.json")
            or full_path == "health"
        ):
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        target_file = frontend_dist / full_path
        if target_file.is_file():
            return FileResponse(str(target_file))
        return FileResponse(str(frontend_dist / "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "platform": config.PROJECT_NAME,
            "version": config.VERSION,
            "docs_url": "/docs",
            "api_v1": config.API_V1_PREFIX,
        }
