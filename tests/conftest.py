"""Global pytest fixtures for auth microservice tests."""

import os
import uuid
from datetime import timedelta
from typing import Any, Dict

# Establish safe, non-production environment variables before importing src
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test_user:test_password@localhost:5432/db_auth")
os.environ.setdefault("DB_ECHO", "false")
os.environ.setdefault("APP_ENV", "test")

import pytest
from fastapi.testclient import TestClient

from src.auth.main import app
from src.core.crypto import load_rsa_keys
from src.services.jwt_service import (
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
)


@pytest.fixture(scope="session", autouse=True)
def ensure_rsa_keys():
    """Ensure RSA keys exist in certs/ or environment before running tests."""
    priv, pub = load_rsa_keys()
    assert priv is not None
    assert pub is not None
    return priv, pub


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient instance."""
    return TestClient(app)


@pytest.fixture
def sample_student_user() -> Dict[str, Any]:
    """Sample student user data dictionary."""
    return {
        "id": str(uuid.uuid4()),
        "email": "student.test@ufps.edu.co",
        "role": "STUDENT",
        "is_active": True,
    }


@pytest.fixture
def sample_company_user() -> Dict[str, Any]:
    """Sample company user data dictionary."""
    return {
        "id": str(uuid.uuid4()),
        "email": "contact@techcorp.com",
        "role": "COMPANY",
        "is_active": True,
    }


@pytest.fixture
def sample_admin_user() -> Dict[str, Any]:
    """Sample admin user data dictionary."""
    return {
        "id": str(uuid.uuid4()),
        "email": "admin.security@ufps.edu.co",
        "role": "ADMIN",
        "is_active": True,
    }


@pytest.fixture
def student_access_token(sample_student_user: Dict[str, Any]) -> str:
    """Valid access token for a student."""
    return create_access_token(sample_student_user)


@pytest.fixture
def company_access_token(sample_company_user: Dict[str, Any]) -> str:
    """Valid access token for a company."""
    return create_access_token(sample_company_user)


@pytest.fixture
def admin_access_token(sample_admin_user: Dict[str, Any]) -> str:
    """Valid access token for an admin."""
    return create_access_token(sample_admin_user)


@pytest.fixture
def expired_access_token(sample_student_user: Dict[str, Any]) -> str:
    """Expired access token."""
    return create_access_token(sample_student_user, expires_delta=timedelta(seconds=-10))


@pytest.fixture
def student_refresh_token(sample_student_user: Dict[str, Any]) -> str:
    """Valid refresh token for a student."""
    return create_refresh_token(sample_student_user)


@pytest.fixture
def student_password_reset_token(sample_student_user: Dict[str, Any]) -> str:
    """Valid password reset token for a student."""
    return create_password_reset_token(sample_student_user)
