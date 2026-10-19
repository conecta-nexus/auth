import uuid
from datetime import timedelta

import jwt
import pytest

from src.core.crypto import load_private_key_pem
from src.core.security import (
    ADMIN_SCOPES,
    COMPANY_SCOPES,
    JWT_ALGORITHM,
    JWT_AUDIENCES,
    JWT_ISSUER,
    STUDENT_SCOPES,
    get_scopes_for_role,
    get_scopes_string_for_role,
)
from src.services.jwt_service import (
    InvalidTokenError,
    TokenExpiredError,
    create_access_token,
    create_refresh_token,
    decode_token,
)


class MockUser:
    def __init__(self, user_id, email, role, is_active=True):
        self.id = user_id
        self.email = email
        self.role = role
        self.is_active = is_active


def test_scope_mapping_functions():
    assert set(get_scopes_for_role("STUDENT")) == set(STUDENT_SCOPES)
    assert set(get_scopes_for_role("student")) == set(STUDENT_SCOPES)
    assert set(get_scopes_for_role("COMPANY")) == set(COMPANY_SCOPES)
    assert set(get_scopes_for_role("ADMIN")) == set(ADMIN_SCOPES)
    assert get_scopes_for_role("UNKNOWN") == []

    scope_str = get_scopes_string_for_role("STUDENT")
    assert "profile:student:read" in scope_str
    assert "challenge:read" in scope_str


def test_create_and_decode_access_token_student():
    user_id = uuid.uuid4()
    jti = uuid.uuid4()
    user = MockUser(user_id=user_id, email="student@ufps.edu.co", role="STUDENT")

    token = create_access_token(user, jti=jti)
    assert isinstance(token, str)

    payload = decode_token(token)
    assert payload["iss"] == JWT_ISSUER
    assert set(payload["aud"]) == set(JWT_AUDIENCES)
    assert payload["sub"] == str(user_id)
    assert payload["jti"] == str(jti)
    assert payload["type"] == "access"
    assert payload["email"] == "student@ufps.edu.co"
    assert payload["role"] == "STUDENT"
    assert payload["is_active"] is True

    scopes = payload["scope"].split()
    assert "profile:student:read" in scopes
    assert "profile:student:write" in scopes
    assert "consent:read" in scopes


def test_create_access_token_with_dict_user():
    user_id = str(uuid.uuid4())
    user_dict = {
        "id": user_id,
        "email": "company@acme.com",
        "role": "COMPANY",
        "is_active": True,
    }

    token = create_access_token(user_dict)
    payload = decode_token(token)
    assert payload["sub"] == user_id
    assert payload["role"] == "COMPANY"
    scopes = payload["scope"].split()
    assert "profile:company:read" in scopes
    assert "challenge:create" in scopes


def test_create_and_decode_access_token_admin():
    user = MockUser(user_id=uuid.uuid4(), email="admin@ufps.edu.co", role="ADMIN")
    token = create_access_token(user)
    payload = decode_token(token)
    assert payload["role"] == "ADMIN"
    scopes = payload["scope"].split()
    assert "profile:read_all" in scopes
    assert "user:status:write" in scopes
    assert "challenge:moderate" in scopes


def test_create_and_decode_refresh_token():
    user_id = uuid.uuid4()
    jti = uuid.uuid4()
    user = MockUser(user_id=user_id, email="user@ufps.edu.co", role="STUDENT")

    token = create_refresh_token(user, jti=jti)
    payload = decode_token(token)

    assert payload["iss"] == JWT_ISSUER
    assert payload["sub"] == str(user_id)
    assert payload["jti"] == str(jti)
    assert payload["type"] == "refresh"
    assert payload["role"] == "STUDENT"
    assert payload["exp"] > payload["iat"]


def test_expired_token_raises_token_expired_error():
    user = MockUser(user_id=uuid.uuid4(), email="expired@ufps.edu.co", role="STUDENT")
    token = create_access_token(user, expires_delta=timedelta(seconds=-10))

    with pytest.raises(TokenExpiredError, match="Token has expired"):
        decode_token(token)


def test_tampered_token_signature_raises_invalid_token_error():
    user = MockUser(user_id=uuid.uuid4(), email="valid@ufps.edu.co", role="STUDENT")
    token = create_access_token(user)

    parts = token.split(".")
    tampered_sig = parts[2][:-4] + "AAAA"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    with pytest.raises(InvalidTokenError):
        decode_token(tampered_token)


def test_invalid_issuer_rejected():
    private_pem = load_private_key_pem()
    payload = {
        "iss": "https://malicious-issuer.com",
        "aud": JWT_AUDIENCES,
        "sub": str(uuid.uuid4()),
        "exp": 9999999999,
    }
    bogus_token = jwt.encode(payload, private_pem, algorithm=JWT_ALGORITHM)

    with pytest.raises(InvalidTokenError, match="Invalid token"):
        decode_token(bogus_token)


def test_invalid_audience_rejected():
    private_pem = load_private_key_pem()
    payload = {
        "iss": JWT_ISSUER,
        "aud": ["unknown-service"],
        "sub": str(uuid.uuid4()),
        "exp": 9999999999,
    }
    bogus_token = jwt.encode(payload, private_pem, algorithm=JWT_ALGORITHM)

    with pytest.raises(InvalidTokenError, match="Invalid token"):
        decode_token(bogus_token)


def test_user_without_id_raises_value_error():
    with pytest.raises(ValueError, match="must have an 'id' attribute"):
        create_access_token({"email": "no-id@test.com"})
