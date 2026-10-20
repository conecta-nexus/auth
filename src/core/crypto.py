"""RSA asymmetric cryptographic key management for RS256 token signing (ADR-002).

This module handles loading, parsing, and validating 2048-bit RSA key pairs
used by the Conecta Nexus identity and authorization system.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class PrivateKeyNotFoundError(CryptoError):
    """Raised when the RSA private key cannot be located or loaded."""


class PublicKeyNotFoundError(CryptoError):
    """Raised when the RSA public key cannot be located or loaded."""


class InvalidKeyError(CryptoError):
    """Raised when an RSA key is malformed, corrupted, or has an invalid key size."""


# Standard search locations relative to repository root or container root
DEFAULT_SEARCH_DIRS = [
    Path("certs"),
    Path("keys"),
    Path("."),
    Path("/etc/secrets"),
]

PRIVATE_KEY_FILENAME = "jwt_private.pem"
PUBLIC_KEY_FILENAME = "jwt_public.pem"


def _find_key_file(filename: str, custom_path: str | Path | None = None) -> Path | None:
    """Find a key file given a custom path or by probing standard locations."""
    if custom_path:
        path = Path(custom_path).expanduser().resolve()
        if path.is_file():
            return path
        return None

    # Probe current directory and search dirs
    for search_dir in DEFAULT_SEARCH_DIRS:
        candidate = (search_dir / filename).expanduser().resolve()
        if candidate.is_file():
            return candidate

    return None


def load_private_key_pem(custom_path: str | Path | None = None) -> str:
    """Load the RSA private key in PEM format.

    Priority order:
    1. Direct environment variable content (JWT_PRIVATE_KEY)
    2. File path from environment variable (JWT_PRIVATE_KEY_PATH)
    3. Explicit custom_path argument
    4. Default locations (certs/jwt_private.pem, keys/jwt_private.pem, etc.)
    """
    env_content = os.getenv("JWT_PRIVATE_KEY")
    if env_content and env_content.strip():
        pem_str = env_content.strip()
        _validate_private_key_pem(pem_str)
        return pem_str

    env_path = os.getenv("JWT_PRIVATE_KEY_PATH")
    key_file = _find_key_file(PRIVATE_KEY_FILENAME, custom_path or env_path)

    if not key_file:
        raise PrivateKeyNotFoundError(
            f"RSA private key '{PRIVATE_KEY_FILENAME}' was not found. "
            "Please ensure the file exists in certs/, keys/, or current directory, "
            "or set JWT_PRIVATE_KEY / JWT_PRIVATE_KEY_PATH. "
            "For local development, generate keys using: uv run python scripts/generate_keys.py"
        )

    try:
        pem_str = key_file.read_text(encoding="utf-8").strip()
    except Exception as exc:
        raise PrivateKeyNotFoundError(f"Failed to read private key from '{key_file}': {exc}") from exc

    _validate_private_key_pem(pem_str)
    return pem_str


def load_public_key_pem(
    custom_path: str | Path | None = None,
    fallback_private_pem: str | None = None,
) -> str:
    """Load the RSA public key in PEM format.

    Priority order:
    1. Direct environment variable content (JWT_PUBLIC_KEY)
    2. File path from environment variable (JWT_PUBLIC_KEY_PATH)
    3. Explicit custom_path argument
    4. Default locations (certs/jwt_public.pem, keys/jwt_public.pem, etc.)
    5. Derive from fallback_private_pem if provided
    """
    env_content = os.getenv("JWT_PUBLIC_KEY")
    if env_content and env_content.strip():
        pem_str = env_content.strip()
        _validate_public_key_pem(pem_str)
        return pem_str

    env_path = os.getenv("JWT_PUBLIC_KEY_PATH")
    key_file = _find_key_file(PUBLIC_KEY_FILENAME, custom_path or env_path)

    if key_file:
        try:
            pem_str = key_file.read_text(encoding="utf-8").strip()
            _validate_public_key_pem(pem_str)
            return pem_str
        except Exception as exc:
            raise PublicKeyNotFoundError(f"Failed to read public key from '{key_file}': {exc}") from exc

    # If public key file is missing but private key PEM is available, derive it
    if fallback_private_pem:
        return derive_public_key_pem(fallback_private_pem)

    raise PublicKeyNotFoundError(
        f"RSA public key '{PUBLIC_KEY_FILENAME}' was not found. "
        "Please ensure the file exists in certs/, keys/, or current directory, "
        "or set JWT_PUBLIC_KEY / JWT_PUBLIC_KEY_PATH."
    )


def derive_public_key_pem(private_pem: str) -> str:
    """Derive public key PEM string from an existing private key PEM."""
    try:
        private_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"),
            password=None,
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise InvalidKeyError("Key is not an RSA private key.")

        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_bytes.decode("utf-8").strip()
    except Exception as exc:
        raise InvalidKeyError(f"Could not derive public key from private key: {exc}") from exc


def _validate_private_key_pem(pem_str: str) -> rsa.RSAPrivateKey:
    """Validate that the given string is a valid RSA private key with >= 2048 bits."""
    try:
        key = serialization.load_pem_private_key(
            pem_str.encode("utf-8"),
            password=None,
        )
    except Exception as exc:
        raise InvalidKeyError(f"Invalid RSA private key PEM data: {exc}") from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise InvalidKeyError("Loaded key is not an RSA private key.")

    if key.key_size < 2048:
        raise InvalidKeyError(
            f"RSA private key size ({key.key_size} bits) is insecure. "
            "Minimum required key size is 2048 bits per ADR-002."
        )

    return key


def _validate_public_key_pem(pem_str: str) -> rsa.RSAPublicKey:
    """Validate that the given string is a valid RSA public key with >= 2048 bits."""
    try:
        key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    except Exception as exc:
        raise InvalidKeyError(f"Invalid RSA public key PEM data: {exc}") from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidKeyError("Loaded key is not an RSA public key.")

    if key.key_size < 2048:
        raise InvalidKeyError(
            f"RSA public key size ({key.key_size} bits) is insecure. "
            "Minimum required key size is 2048 bits per ADR-002."
        )

    return key


def load_rsa_keys(
    private_key_path: str | Path | None = None,
    public_key_path: str | Path | None = None,
) -> Tuple[str, str]:
    """Load both RSA private and public keys as PEM formatted strings.

    Returns:
        tuple[str, str]: (private_key_pem, public_key_pem)
    """
    private_pem = load_private_key_pem(private_key_path)
    public_pem = load_public_key_pem(public_key_path, fallback_private_pem=private_pem)
    return private_pem, public_pem


def load_rsa_key_objects(
    private_key_path: str | Path | None = None,
    public_key_path: str | Path | None = None,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Load both RSA keys as cryptography key objects."""
    priv_pem, pub_pem = load_rsa_keys(private_key_path, public_key_path)
    priv_obj = _validate_private_key_pem(priv_pem)
    pub_obj = _validate_public_key_pem(pub_pem)
    return priv_obj, pub_obj


def verify_rsa_roundtrip(private_pem: str, public_pem: str) -> bool:
    """Verify that private and public keys match by performing a sign and verify cycle."""
    priv_key = _validate_private_key_pem(private_pem)
    pub_key = _validate_public_key_pem(public_pem)

    sample_payload = b"conecta-nexus-rs256-cryptographic-check"
    signature = priv_key.sign(
        sample_payload,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    try:
        pub_key.verify(
            signature,
            sample_payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
