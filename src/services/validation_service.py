"""Local validation rules for authentication inputs."""

from typing import Final


STUDENT_EMAIL_DOMAIN: Final[str] = "ufps.edu.co"
FREE_EMAIL_DOMAINS: Final[frozenset[str]] = frozenset(
    {"gmail.com", "hotmail.com", "yahoo.com"}
)


def validate_password_strength(password: str) -> bool:
    """Return whether a password meets every required complexity rule."""
    return (
        len(password) >= 8
        and any(character.isupper() for character in password)
        and any(character.islower() for character in password)
        and any(character.isdigit() for character in password)
        and any(not character.isalnum() for character in password)
    )


def validate_email_domain(email: str, role: str) -> bool:
    """Validate a student or company email using local domain rules."""
    if email.count("@") != 1:
        return False

    local_part, domain = email.rsplit("@", maxsplit=1)
    if not local_part or not domain or any(character.isspace() for character in email):
        return False

    normalized_domain = domain.casefold()
    if not _is_valid_domain(normalized_domain):
        return False

    normalized_role = role.strip().upper()
    if normalized_role == "STUDENT":
        return normalized_domain == STUDENT_EMAIL_DOMAIN
    if normalized_role == "COMPANY":
        return normalized_domain not in FREE_EMAIL_DOMAINS
    return False


def _is_valid_domain(domain: str) -> bool:
    """Check the minimal structure required for a domain name."""
    labels = domain.split(".")
    return len(labels) >= 2 and all(
        label
        and not label.startswith("-")
        and not label.endswith("-")
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )
