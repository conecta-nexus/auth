#!/usr/bin/env bash
set -e

# Generate RSA 2048-bit key pair if neither JWT_PRIVATE_KEY nor key files are present
if [ -z "${JWT_PRIVATE_KEY:-}" ] && [ ! -f "certs/jwt_private.pem" ]; then
    echo "[auth-entrypoint] No RSA keys found in environment or certs/. Auto-generating..."
    mkdir -p certs
    python scripts/generate_keys.py --output-dir certs
fi

# Run database migrations
echo "[auth-entrypoint] Applying Alembic database migrations..."
if alembic upgrade head; then
    echo "[auth-entrypoint] Database migrations applied successfully."
else
    echo "[auth-entrypoint] WARNING: Alembic migrations failed or database connection is pending. Continuing startup..."
fi

exec "$@"
