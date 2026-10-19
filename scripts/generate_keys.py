#!/usr/bin/env python3
"""Script to generate local development RSA key pair (2048-bit) for RS256 JWT signing.

ADR-002: RS256 asymmetric cryptographic signing
- jwt_private.pem: 2048-bit RSA private key (exclusive to auth service)
- jwt_public.pem: RSA public key (shared with Gateway and profile)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_key_pair(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate an RSA private and public key pair in PEM format."""
    if key_size < 2048:
        raise ValueError(f"Key size {key_size} is less than minimum 2048 bits required by ADR-002.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate local RSA 2048-bit key pair for Conecta Nexus RS256 JWT authentication."
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("certs"),
        help="Directory to save PEM files (default: certs/)",
    )
    parser.add_argument(
        "--key-size",
        "-s",
        type=int,
        default=2048,
        help="RSA key size in bits (default: 2048)",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite existing keys if they already exist",
    )

    args = parser.parse_args()

    output_dir: Path = args.output_dir.resolve()
    private_path = output_dir / "jwt_private.pem"
    public_path = output_dir / "jwt_public.pem"

    if (private_path.exists() or public_path.exists()) and not args.force:
        print(
            f"ERROR: Key file(s) already exist in {output_dir}.\n"
            f"  Private: {private_path} (exists={private_path.exists()})\n"
            f"  Public:  {public_path} (exists={public_path.exists()})\n"
            "Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating {args.key_size}-bit RSA key pair...")
    private_pem, public_pem = generate_rsa_key_pair(args.key_size)

    # Write private key with restricted permissions (0600)
    private_path.write_bytes(private_pem)
    os.chmod(private_path, 0o600)

    # Write public key (0644)
    public_path.write_bytes(public_pem)
    os.chmod(public_path, 0o644)

    print("RSA Key pair generated successfully:")
    print(f"  [Private] {private_path} (mode: 0600)")
    print(f"  [Public]  {public_path} (mode: 0644)")
    print("NOTE: These files are excluded from Git via .gitignore. Do not commit private keys.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
