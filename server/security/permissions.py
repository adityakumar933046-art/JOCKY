"""
JOCKY Role-Based Access Control (RBAC) Permissions System.
Defines explicit permissions and maps roles to allowable operations.
"""

from typing import Set, Dict


class Permissions:
    USERS_READ = "users.read"
    USERS_WRITE = "users.write"

    ORGANIZATIONS_READ = "organizations.read"
    ORGANIZATIONS_WRITE = "organizations.write"

    AGENTS_READ = "agents.read"
    AGENTS_REGISTER = "agents.register"
    AGENTS_APPROVE = "agents.approve"
    AGENTS_SUSPEND = "agents.suspend"
    AGENTS_REVOKE = "agents.revoke"

    JOBS_READ = "jobs.read"
    JOBS_CREATE = "jobs.create"
    JOBS_CANCEL = "jobs.cancel"

    EVIDENCE_READ = "evidence.read"
    EVIDENCE_EXPORT = "evidence.export"

    FINDINGS_READ = "findings.read"

    INVESTIGATIONS_READ = "investigations.read"
    INVESTIGATIONS_CREATE = "investigations.create"
    INVESTIGATIONS_UPDATE = "investigations.update"

    REPORTS_READ = "reports.read"
    REPORTS_GENERATE = "reports.generate"

    AUDIT_READ = "audit.read"

    SECURITY_READ = "security.read"
    SECURITY_CONFIGURE = "security.configure"

    ARTIFACTS_READ = "artifacts.read"
    INDICATORS_READ = "indicators.read"
    CORRELATION_READ = "correlation.read"
    CORRELATION_RUN = "correlation.run"


class Roles:
    SUPER_ADMIN = "SUPER_ADMIN"
    ORGANIZATION_ADMIN = "ORGANIZATION_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    INVESTIGATOR = "INVESTIGATOR"
    VIEWER = "VIEWER"


ALL_PERMISSIONS = {
    getattr(Permissions, attr)
    for attr in dir(Permissions)
    if not attr.startswith("__") and isinstance(getattr(Permissions, attr), str)
}

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    Roles.SUPER_ADMIN: ALL_PERMISSIONS,

    Roles.ORGANIZATION_ADMIN: {
        Permissions.USERS_READ,
        Permissions.USERS_WRITE,
        Permissions.ORGANIZATIONS_READ,
        Permissions.AGENTS_READ,
        Permissions.AGENTS_APPROVE,
        Permissions.AGENTS_SUSPEND,
        Permissions.AGENTS_REVOKE,
        Permissions.JOBS_READ,
        Permissions.JOBS_CREATE,
        Permissions.JOBS_CANCEL,
        Permissions.EVIDENCE_READ,
        Permissions.EVIDENCE_EXPORT,
        Permissions.FINDINGS_READ,
        Permissions.INVESTIGATIONS_READ,
        Permissions.INVESTIGATIONS_CREATE,
        Permissions.INVESTIGATIONS_UPDATE,
        Permissions.REPORTS_READ,
        Permissions.REPORTS_GENERATE,
        Permissions.AUDIT_READ,
        Permissions.SECURITY_READ,
        Permissions.ARTIFACTS_READ,
        Permissions.INDICATORS_READ,
        Permissions.CORRELATION_READ,
        Permissions.CORRELATION_RUN,
    },

    Roles.SECURITY_ANALYST: {
        Permissions.AGENTS_READ,
        Permissions.JOBS_READ,
        Permissions.JOBS_CREATE,
        Permissions.EVIDENCE_READ,
        Permissions.EVIDENCE_EXPORT,
        Permissions.FINDINGS_READ,
        Permissions.INVESTIGATIONS_READ,
        Permissions.INVESTIGATIONS_CREATE,
        Permissions.INVESTIGATIONS_UPDATE,
        Permissions.REPORTS_READ,
        Permissions.REPORTS_GENERATE,
        Permissions.SECURITY_READ,
        Permissions.ARTIFACTS_READ,
        Permissions.INDICATORS_READ,
        Permissions.CORRELATION_READ,
        Permissions.CORRELATION_RUN,
    },

    Roles.INVESTIGATOR: {
        Permissions.INVESTIGATIONS_READ,
        Permissions.INVESTIGATIONS_UPDATE,
        Permissions.EVIDENCE_READ,
        Permissions.FINDINGS_READ,
        Permissions.REPORTS_READ,
        Permissions.REPORTS_GENERATE,
        Permissions.ARTIFACTS_READ,
        Permissions.INDICATORS_READ,
        Permissions.CORRELATION_READ,
    },

    Roles.VIEWER: {
        Permissions.AGENTS_READ,
        Permissions.JOBS_READ,
        Permissions.EVIDENCE_READ,
        Permissions.FINDINGS_READ,
        Permissions.INVESTIGATIONS_READ,
        Permissions.REPORTS_READ,
        Permissions.ARTIFACTS_READ,
        Permissions.INDICATORS_READ,
        Permissions.CORRELATION_READ,
    },
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a given role possesses a specific permission."""
    perms = ROLE_PERMISSIONS.get(role.upper(), set())
    return permission in perms
