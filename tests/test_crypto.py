import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts.generate_keys import generate_rsa_key_pair
from src.core.crypto import (
    CryptoError,
    InvalidKeyError,
    PrivateKeyNotFoundError,
    PublicKeyNotFoundError,
    derive_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
    load_rsa_key_objects,
    load_rsa_keys,
    verify_rsa_roundtrip,
)


def test_generate_rsa_key_pair():
    priv_bytes, pub_bytes = generate_rsa_key_pair(2048)
    assert b"BEGIN PRIVATE KEY" in priv_bytes
    assert b"BEGIN PUBLIC KEY" in pub_bytes


def test_generate_rsa_key_pair_under_2048_fails():
    with pytest.raises(ValueError, match="less than minimum 2048 bits"):
        generate_rsa_key_pair(1024)


def test_load_rsa_keys_from_files():
    priv_pem, pub_pem = load_rsa_keys()
    assert priv_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert pub_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert verify_rsa_roundtrip(priv_pem, pub_pem) is True


def test_load_rsa_key_objects():
    priv_obj, pub_obj = load_rsa_key_objects()
    assert isinstance(priv_obj, rsa.RSAPrivateKey)
    assert isinstance(pub_obj, rsa.RSAPublicKey)
    assert priv_obj.key_size >= 2048
    assert pub_obj.key_size >= 2048


def test_load_rsa_keys_from_environment_variables(monkeypatch):
    priv_bytes, pub_bytes = generate_rsa_key_pair(2048)
    priv_str = priv_bytes.decode()
    pub_str = pub_bytes.decode()

    monkeypatch.setenv("JWT_PRIVATE_KEY", priv_str)
    monkeypatch.setenv("JWT_PUBLIC_KEY", pub_str)

    loaded_priv, loaded_pub = load_rsa_keys()
    assert loaded_priv == priv_str.strip()
    assert loaded_pub == pub_str.strip()
    assert verify_rsa_roundtrip(loaded_priv, loaded_pub) is True


def test_load_rsa_keys_from_custom_paths(tmp_path):
    priv_bytes, pub_bytes = generate_rsa_key_pair(2048)
    priv_file = tmp_path / "custom_priv.pem"
    pub_file = tmp_path / "custom_pub.pem"

    priv_file.write_bytes(priv_bytes)
    pub_file.write_bytes(pub_bytes)

    loaded_priv, loaded_pub = load_rsa_keys(
        private_key_path=priv_file,
        public_key_path=pub_file,
    )
    assert loaded_priv == priv_bytes.decode().strip()
    assert loaded_pub == pub_bytes.decode().strip()


def test_derive_public_key_from_private():
    priv_bytes, pub_bytes = generate_rsa_key_pair(2048)
    derived_pub = derive_public_key_pem(priv_bytes.decode())
    assert derived_pub == pub_bytes.decode().strip()


def test_fallback_derive_public_key_when_public_file_missing(tmp_path, monkeypatch):
    priv_bytes, pub_bytes = generate_rsa_key_pair(2048)
    priv_file = tmp_path / "only_priv.pem"
    priv_file.write_bytes(priv_bytes)

    # Clear env
    monkeypatch.delenv("JWT_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("JWT_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("JWT_PRIVATE_KEY_PATH", raising=False)
    monkeypatch.delenv("JWT_PUBLIC_KEY_PATH", raising=False)

    loaded_priv, loaded_pub = load_rsa_keys(
        private_key_path=priv_file,
        public_key_path=tmp_path / "non_existent_pub.pem",
    )
    assert loaded_priv == priv_bytes.decode().strip()
    assert loaded_pub == pub_bytes.decode().strip()


def test_missing_private_key_raises_error(monkeypatch, tmp_path):
    monkeypatch.delenv("JWT_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("JWT_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("JWT_PRIVATE_KEY_PATH", raising=False)
    monkeypatch.delenv("JWT_PUBLIC_KEY_PATH", raising=False)

    non_existent = tmp_path / "missing.pem"
    with pytest.raises(PrivateKeyNotFoundError) as exc_info:
        load_private_key_pem(custom_path=non_existent)

    assert "was not found" in str(exc_info.value)


def test_corrupt_private_key_raises_invalid_key_error(tmp_path):
    corrupt_file = tmp_path / "corrupt.pem"
    corrupt_file.write_text("-----BEGIN PRIVATE KEY-----\nNOT_A_VALID_KEY\n-----END PRIVATE KEY-----")

    with pytest.raises(InvalidKeyError):
        load_private_key_pem(custom_path=corrupt_file)


def test_weak_rsa_key_size_rejected(monkeypatch):
    # Generate weak 1024-bit key
    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak_pem = weak_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    monkeypatch.setenv("JWT_PRIVATE_KEY", weak_pem)

    with pytest.raises(InvalidKeyError, match="insecure"):
        load_rsa_keys()
