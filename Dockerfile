FROM python:3.12-slim

# Install uv from official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Environment settings
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT="/venv" \
    PATH="/venv/bin:$PATH" \
    DATABASE_URL="postgresql+asyncpg://postgres:postgrespassword@postgres:5432/db_auth" \
    DB_ECHO="false" \
    APP_ENV="development"

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY pyproject.toml uv.lock* ./

# Install project dependencies
RUN uv sync --frozen --no-install-project --no-dev || uv sync --no-install-project --no-dev

# Copy application source code
COPY . .

# Final project sync
RUN uv sync --frozen --no-dev || uv sync --no-dev

EXPOSE 8000

CMD ["uvicorn", "src.auth.main:app", "--host", "0.0.0.0", "--port", "8000"]
