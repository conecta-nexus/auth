import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

# Ensure service root is in sys.path when executing directly
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.routers.auth import router as auth_router
from src.routers.password_reset import router as password_reset_router
from src.routers.users import router as users_router

app = FastAPI(
    title="Conecta Nexus - Auth Service",
    description="Authentication and Authorization Microservice",
    version="0.1.0",
    docs_url="/api/v1/auth/docs",
    redoc_url="/api/v1/auth/redoc",
    openapi_url="/api/v1/auth/openapi.json",
)

# CORS middleware for direct development and cross-origin security
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-User-Id", "X-User-Email", "X-User-Role", "X-User-Scopes"],
)

app.include_router(auth_router)
app.include_router(password_reset_router)
app.include_router(users_router)


@app.get("/", include_in_schema=False)
def read_root():
    return {
        "service": "auth",
        "status": "running",
        "framework": "fastapi",
    }


@app.get("/docs", include_in_schema=False)
def redirect_docs():
    return RedirectResponse(url="/api/v1/auth/docs")


@app.get("/openapi.json", include_in_schema=False)
def redirect_openapi():
    return RedirectResponse(url="/api/v1/auth/openapi.json")


@app.get("/health", tags=["health"])
@app.get("/api/v1/auth/health", tags=["health"])
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.auth.main:app", host="0.0.0.0", port=8000, reload=True)
