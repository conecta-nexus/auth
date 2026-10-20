"""Unit tests for OAuth2 scopes and RBAC permission matrix (Section 4.1)."""

import pytest

from src.core.security import (
    ADMIN_SCOPES,
    COMPANY_SCOPES,
    STUDENT_SCOPES,
    get_scopes_for_role,
    get_scopes_string_for_role,
)


def test_student_scopes_completeness():
    """Verify STUDENT role has all required scopes per Section 4.1."""
    expected_scopes = {
        "consent:write",
        "consent:read",
        "profile:student:read",
        "profile:student:write",
        "profile:company:read_public",
        "challenge:read",
        "application:create",
        "application:read_own",
    }
    actual_scopes = set(get_scopes_for_role("STUDENT"))
    assert actual_scopes == expected_scopes
    assert len(STUDENT_SCOPES) == 8


def test_company_scopes_completeness():
    """Verify COMPANY role has all required scopes per Section 4.1."""
    expected_scopes = {
        "consent:write",
        "consent:read",
        "profile:company:read",
        "profile:company:write",
        "profile:student:read_public",
        "challenge:create",
        "challenge:read_own",
        "challenge:write_own",
        "application:read_received",
        "application:decide",
    }
    actual_scopes = set(get_scopes_for_role("COMPANY"))
    assert actual_scopes == expected_scopes
    assert len(COMPANY_SCOPES) == 10


def test_admin_scopes_completeness():
    """Verify ADMIN role has all required scopes per Section 4.1."""
    expected_scopes = {
        "profile:read_all",
        "challenge:read_all",
        "challenge:moderate",
        "user:status:write",
        "audit:read",
    }
    actual_scopes = set(get_scopes_for_role("ADMIN"))
    assert actual_scopes == expected_scopes
    assert len(ADMIN_SCOPES) == 5


def test_rbac_scope_isolation_student_vs_company():
    """Verify student and company roles cannot access unauthorized operational domains."""
    student_scopes = set(get_scopes_for_role("STUDENT"))
    company_scopes = set(get_scopes_for_role("COMPANY"))

    # Student cannot publish challenges or decide applications
    assert "challenge:create" not in student_scopes
    assert "challenge:write_own" not in student_scopes
    assert "application:decide" not in student_scopes
    assert "profile:company:write" not in student_scopes

    # Company cannot create student applications or modify student profiles
    assert "application:create" not in company_scopes
    assert "application:read_own" not in company_scopes
    assert "profile:student:write" not in company_scopes

    # Both share legal consent scopes
    assert "consent:read" in student_scopes and "consent:read" in company_scopes
    assert "consent:write" in student_scopes and "consent:write" in company_scopes


def test_rbac_scope_isolation_admin_privileges():
    """Verify administrative privileges are strictly isolated to ADMIN role."""
    student_scopes = set(get_scopes_for_role("STUDENT"))
    company_scopes = set(get_scopes_for_role("COMPANY"))
    admin_scopes = set(get_scopes_for_role("ADMIN"))

    privileged_scopes = {"user:status:write", "challenge:moderate", "audit:read", "profile:read_all"}
    for scope in privileged_scopes:
        assert scope in admin_scopes
        assert scope not in student_scopes
        assert scope not in company_scopes


@pytest.mark.parametrize("role_input", ["student", "STUDENT", "Student", "  student  "])
def test_role_case_and_whitespace_insensitivity(role_input):
    """Verify role lookup handles mixed case and surrounding whitespace."""
    scopes = get_scopes_for_role(role_input)
    assert set(scopes) == set(STUDENT_SCOPES)


@pytest.mark.parametrize("invalid_role", ["", "   ", "ANONYMOUS", "SUPERUSER", "MODERATOR"])
def test_unknown_roles_return_empty(invalid_role):
    """Verify invalid or unmapped roles return an empty scope list."""
    assert get_scopes_for_role(invalid_role) == []
    assert get_scopes_string_for_role(invalid_role) == ""


def test_scopes_string_format():
    """Verify space-delimited scope string conforming to RFC 6749 Section 3.3."""
    scope_str = get_scopes_string_for_role("STUDENT")
    tokens = scope_str.split(" ")
    assert len(tokens) == len(STUDENT_SCOPES)
    assert set(tokens) == set(STUDENT_SCOPES)
