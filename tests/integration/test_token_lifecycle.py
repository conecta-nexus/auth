"""Integration tests for the complete RS256 token lifecycle.

Covers end-to-end token generation, claims verification, role transitions,
and security attack vector defenses (tampering, algorithm confusion, replay).
"""

import uuid
from datetime import timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from src.core.crypto import load_private_key_pem, load_public_key_pem
from src.core.security import JWT_ALGORITHM, JWT_AUDIENCES, JWT_ISSUER
from src.services.jwt_service import create_access_token, create_refresh_token, decode_token


def test_end_to_end_student_lifecycle(client: TestClient, sample_student_user):
    """Complete cycle: issue access token -> verify at endpoint -> validate claims & scopes."""
    token = create_access_token(sample_student_user)

    # Decode directly using public key
    decoded = decode_token(token)
    assert decoded["sub"] == sample_student_user["id"]
    assert decoded["role"] == "STUDENT"
    assert "profile:student:read" in decoded["scope"].split()

    # Verify through API endpoint (as the API Gateway or downstream service would)
    resp = client.get("/api/v1/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["user_id"] == sample_student_user["id"]
    assert body["email"] == sample_student_user["email"]
    assert body["role"] == "STUDENT"
    assert "profile:student:read" in body["scopes"]
    assert "consent:read" in body["scopes"]


def test_end_to_end_company_lifecycle(client: TestClient, sample_company_user):
    """Complete cycle for company: issue token -> verify through Gateway endpoint."""
    token = create_access_token(sample_company_user)

    resp = client.get("/api/v1/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["role"] == "COMPANY"
    assert "challenge:create" in body["scopes"]
    assert "application:decide" in body["scopes"]


def test_end_to_end_admin_lifecycle(client: TestClient, sample_admin_user):
    """Complete cycle for administrator: issue token -> verify administrative scopes."""
    token = create_access_token(sample_admin_user)

    resp = client.get("/api/v1/auth/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["role"] == "ADMIN"
    assert "user:status:write" in body["scopes"]
    assert "challenge:moderate" in body["scopes"]


def test_token_type_segregation(client: TestClient, sample_student_user):
    """Ensure refresh tokens cannot be used as access tokens at the verification endpoint."""
    refresh_token = create_refresh_token(sample_student_user)

    resp = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert resp.status_code == 401
    assert "access token required" in resp.json()["detail"]


def test_algorithm_confusion_attack_defense(client: TestClient, sample_student_user):
    """Defend against HMAC key confusion attack where an attacker signs with HS256.

    Our verifier strictly enforces algorithms=['RS256'] and must reject any HS256 token.
    """
    payload = {
        "iss": JWT_ISSUER,
        "aud": list(JWT_AUDIENCES),
        "sub": sample_student_user["id"],
        "jti": str(uuid.uuid4()),
        "exp": 9999999999,
        "type": "access",
        "email": sample_student_user["email"],
        "role": "ADMIN",  # Privilege escalation attempt
        "scope": "user:status:write profile:read_all",
    }

    # Maliciously sign with HS256 using an arbitrary 32-byte symmetric secret
    malicious_token = jwt.encode(payload, "attacker-symmetric-key-32-bytes!", algorithm="HS256")

    # Direct decode must fail
    with pytest.raises(Exception):
        decode_token(malicious_token)

    # API verify endpoint must reject with 401
    resp = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {malicious_token}"},
    )
    assert resp.status_code == 401


def test_token_with_none_algorithm_rejected(client: TestClient, sample_student_user):
    """Ensure tokens with 'none' algorithm are strictly rejected."""
    payload = {
        "iss": JWT_ISSUER,
        "aud": list(JWT_AUDIENCES),
        "sub": sample_student_user["id"],
        "type": "access",
        "exp": 9999999999,
        "role": "ADMIN",
    }
    # Create unsigned token
    none_token = jwt.encode(payload, key="", algorithm="none")

    resp = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {none_token}"},
    )
    assert resp.status_code == 401


def test_token_expiration_boundary_rejection(client: TestClient, sample_student_user):
    """Ensure token expired by 1 second is immediately rejected."""
    expired_token = create_access_token(sample_student_user, expires_delta=timedelta(seconds=-1))

    resp = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401
    assert "Token has expired" in resp.json()["detail"]


def test_authorization_header_malformed_formats(client: TestClient, student_access_token):
    """Test various malformed Authorization headers."""
    # Missing scheme prefix
    resp = client.get("/api/v1/auth/verify", headers={"Authorization": student_access_token})
    assert resp.status_code == 401

    # Wrong scheme (Basic instead of Bearer)
    resp = client.get("/api/v1/auth/verify", headers={"Authorization": f"Basic {student_access_token}"})
    assert resp.status_code == 401

    # Bearer with empty token
    resp = client.get("/api/v1/auth/verify", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401

    # Empty Authorization header
    resp = client.get("/api/v1/auth/verify", headers={"Authorization": ""})
    assert resp.status_code == 401
