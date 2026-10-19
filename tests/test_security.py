"""Tests for password security and local registration validation rules."""

import pytest

from src.core.security import hash_password, verify_password
from src.services.validation_service import (
    validate_email_domain,
    validate_password_strength,
)


TEST_PASSWORD = "FictionalPassword!9"


@pytest.fixture(scope="module")
def password_hash() -> str:
    return hash_password(TEST_PASSWORD)


def test_hash_password_returns_argon2id_hash() -> None:
    hashed_password = hash_password(TEST_PASSWORD)

    assert isinstance(hashed_password, str)
    assert hashed_password != TEST_PASSWORD
    assert hashed_password.startswith("$argon2id$")


def test_hash_password_uses_a_random_salt() -> None:
    first_hash = hash_password(TEST_PASSWORD)
    second_hash = hash_password(TEST_PASSWORD)

    assert first_hash != second_hash


def test_verify_password_accepts_correct_password(password_hash: str) -> None:
    assert verify_password(TEST_PASSWORD, password_hash) is True


def test_verify_password_rejects_incorrect_password(password_hash: str) -> None:
    assert verify_password("WrongPassword!9", password_hash) is False


@pytest.mark.parametrize(
    "invalid_hash",
    [
        "not-a-password-hash",
        "$argon2id$v=19$m=65536,t=3,p=4$invalid$invalid",
    ],
)
def test_verify_password_rejects_invalid_hash(invalid_hash: str) -> None:
    assert verify_password(TEST_PASSWORD, invalid_hash) is False


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("SecurePassword!1", True),
        ("Aa1!aaaa", True),
        ("Aa1!aaa", False),
        ("lowercase!1", False),
        ("UPPERCASE!1", False),
        ("NoNumber!", False),
        ("NoSymbol1", False),
        ("", False),
    ],
)
def test_validate_password_strength(password: str, expected: bool) -> None:
    assert validate_password_strength(password) is expected


@pytest.mark.parametrize(
    ("email", "role"),
    [
        ("student@ufps.edu.co", "STUDENT"),
        ("STUDENT@UFPS.EDU.CO", "student"),
        ("student@UfPs.EdU.cO", " Student "),
    ],
)
def test_validate_student_email_domain_accepts_exact_ufps_domain(
    email: str,
    role: str,
) -> None:
    assert validate_email_domain(email, role) is True


@pytest.mark.parametrize(
    "email",
    [
        "student@gmail.com",
        "student@hotmail.com",
        "student@yahoo.com",
        "student@ufps.edu.co.example.com",
        "student@fakeufps.edu.co",
        "student@ufps.edu.com",
        "studentufps.edu.co",
        "@ufps.edu.co",
        "student@",
        "student@@ufps.edu.co",
    ],
)
def test_validate_student_email_domain_rejects_invalid_addresses(email: str) -> None:
    assert validate_email_domain(email, "STUDENT") is False


@pytest.mark.parametrize(
    ("email", "role"),
    [
        ("contact@empresa.com", "COMPANY"),
        ("CONTACT@EMPRESA.COM", "company"),
        ("contact@Empresa.Com", " Company "),
    ],
)
def test_validate_company_email_domain_accepts_corporate_domain(
    email: str,
    role: str,
) -> None:
    assert validate_email_domain(email, role) is True


@pytest.mark.parametrize(
    "email",
    [
        "company@gmail.com",
        "company@GMAIL.COM",
        "company@hotmail.com",
        "company@yahoo.com",
        "companyempresa.com",
        "@empresa.com",
        "company@",
        "company@@empresa.com",
        "company@localhost",
        "company@empresa..com",
        "company@-empresa.com",
        "company@empresa-.com",
    ],
)
def test_validate_company_email_domain_rejects_invalid_addresses(email: str) -> None:
    assert validate_email_domain(email, "COMPANY") is False


@pytest.mark.parametrize("role", ["ADMIN", "UNKNOWN", ""])
def test_validate_email_domain_rejects_unsupported_roles(role: str) -> None:
    assert validate_email_domain("person@empresa.com", role) is False
