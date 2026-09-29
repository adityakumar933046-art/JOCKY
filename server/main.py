"""
JOCKY Central Forensic Platform - Main FastAPI Application.
Equipped with enterprise authentication, RBAC, immutable audit logging, and security headers.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
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
)

# Ensure database tables and initial seed data exist immediately
init_db()

# Enable CORS for React Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


@app.get("/health")
@app.get(f"{config.API_V1_PREFIX}/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": config.PROJECT_NAME,
        "version": config.VERSION,
    }


@app.get("/")
def root():
    return {
        "platform": config.PROJECT_NAME,
        "version": config.VERSION,
        "docs_url": "/docs",
        "api_v1": config.API_V1_PREFIX,
    }
