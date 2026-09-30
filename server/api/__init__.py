"""
JOCKY Server API Package.
Exports all REST API routers for Step 1-6 forensic platform.
"""

from server.api.auth import router as auth_router
from server.api.agents import router as agents_router
from server.api.jobs import router as jobs_router
from server.api.evidence import router as evidence_router
from server.api.findings import router as findings_router
from server.api.investigations import router as investigations_router
from server.api.compiler_api import router as compiler_router
from server.api.audit import router as audit_router
from server.api.security_events import router as security_router
from server.api.artifacts import artifacts_router, relationships_router
from server.api.indicators import indicators_router
from server.api.correlation import correlation_router
from server.api.search import search_router
from server.api.command_center import command_center_router

__all__ = [
    "auth_router",
    "agents_router",
    "jobs_router",
    "evidence_router",
    "findings_router",
    "investigations_router",
    "compiler_router",
    "audit_router",
    "security_router",
    "artifacts_router",
    "relationships_router",
    "indicators_router",
    "correlation_router",
    "search_router",
    "command_center_router",
]
