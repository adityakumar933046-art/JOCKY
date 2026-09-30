"""
Unit tests for Signer and Verifier RBAC roles and permissions.
"""

from server.security.permissions import Permissions, Roles, has_permission, ROLE_PERMISSIONS


def test_signer_permissions():
    assert has_permission(Roles.SIGNER, Permissions.EVIDENCE_SIGN) is True
    assert has_permission(Roles.SIGNER, Permissions.REPORTS_SIGN) is True
    assert has_permission(Roles.SIGNER, Permissions.EVIDENCE_READ) is True
    assert has_permission(Roles.SIGNER, Permissions.REPORTS_READ) is True
    # Signer should NOT have administrative write permissions
    assert has_permission(Roles.SIGNER, Permissions.USERS_WRITE) is False
    assert has_permission(Roles.SIGNER, Permissions.SECURITY_CONFIGURE) is False


def test_verifier_permissions():
    assert has_permission(Roles.VERIFIER, Permissions.EVIDENCE_VERIFY) is True
    assert has_permission(Roles.VERIFIER, Permissions.EVIDENCE_READ) is True
    assert has_permission(Roles.VERIFIER, Permissions.AUDIT_READ) is True
    # Verifier should NOT have signing permissions
    assert has_permission(Roles.VERIFIER, Permissions.EVIDENCE_SIGN) is False
    assert has_permission(Roles.VERIFIER, Permissions.REPORTS_SIGN) is False
    assert has_permission(Roles.VERIFIER, Permissions.USERS_WRITE) is False


def test_superadmin_has_all_signing_permissions():
    assert has_permission(Roles.SUPER_ADMIN, Permissions.EVIDENCE_SIGN) is True
    assert has_permission(Roles.SUPER_ADMIN, Permissions.EVIDENCE_VERIFY) is True
    assert has_permission(Roles.SUPER_ADMIN, Permissions.REPORTS_SIGN) is True
