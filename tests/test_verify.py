import time
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from src.auth.main import app
from src.services.jwt_service import create_access_token, create_refresh_token


@pytest.fixture
def client():
    return TestClient(app)


def test_verify_valid_student_token(client):
    user_id = uuid.uuid4()
    user = {
        "id": user_id,
        "email": "student@ufps.edu.co",
        "role": "STUDENT",
        "is_active": True,
    }
    token = create_access_token(user)

    response = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["user_id"] == str(user_id)
    assert data["email"] == "student@ufps.edu.co"
    assert data["role"] == "STUDENT"
    assert "profile:student:read" in data["scopes"]
    assert "consent:read" in data["scopes"]


def test_verify_valid_company_token(client):
    user_id = uuid.uuid4()
    user = {
        "id": user_id,
        "email": "empresa@corp.com",
        "role": "COMPANY",
        "is_active": True,
    }
    token = create_access_token(user)

    response = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["role"] == "COMPANY"
    assert "profile:company:read" in data["scopes"]
    assert "challenge:create" in data["scopes"]


def test_verify_valid_admin_token(client):
    user = {
        "id": uuid.uuid4(),
        "email": "admin@ufps.edu.co",
        "role": "ADMIN",
        "is_active": True,
    }
    token = create_access_token(user)

    response = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["role"] == "ADMIN"
    assert "user:status:write" in data["scopes"]


def test_verify_missing_header_returns_401(client):
    response = client.get("/api/v1/auth/verify")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.json()["detail"] == "Missing Bearer authorization header"


def test_verify_expired_token_returns_401(client):
    user = {"id": uuid.uuid4(), "email": "user@ufps.edu.co", "role": "STUDENT"}
    expired_token = create_access_token(user, expires_delta=timedelta(seconds=-1))

    response = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has expired"


def test_verify_rejects_refresh_token(client):
    user = {"id": uuid.uuid4(), "email": "user@ufps.edu.co", "role": "STUDENT"}
    refresh_token = create_refresh_token(user)

    response = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )
    assert response.status_code == 401
    assert "access token required" in response.json()["detail"]


def test_verify_tampered_token_returns_401(client):
    user = {"id": uuid.uuid4(), "email": "user@ufps.edu.co", "role": "STUDENT"}
    token = create_access_token(user)
    tampered = token[:-4] + "ABCD"

    response = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {tampered}"},
    )
    assert response.status_code == 401


def test_verify_sub_50ms_sla_benchmark(client):
    user = {"id": uuid.uuid4(), "email": "benchmark@ufps.edu.co", "role": "STUDENT"}
    token = create_access_token(user)

    # Warm-up request
    client.get("/api/v1/auth/verify", headers={"Authorization": f"Bearer {token}"})

    # Benchmark 20 iterations
    latencies = []
    for _ in range(20):
        start = time.perf_counter()
        resp = client.get(
            "/api/v1/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)
        assert resp.status_code == 200

    avg_latency = sum(latencies) / len(latencies)
    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]

    print(f"\nVerification Benchmark: avg={avg_latency:.2f}ms, p95={p95_latency:.2f}ms")
    # Strictly enforce SLA < 50ms
    assert avg_latency < 50.0, f"Average latency {avg_latency}ms exceeded 50ms SLA"
    assert p95_latency < 50.0, f"P95 latency {p95_latency}ms exceeded 50ms SLA"
