import sys
from pathlib import Path
from fastapi import FastAPI

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
)

app.include_router(auth_router)
app.include_router(password_reset_router)
app.include_router(users_router)


@app.get("/")
def read_root():
    return {
        "service": "auth",
        "status": "running",
        "framework": "fastapi",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.auth.main:app", host="0.0.0.0", port=8000, reload=True)
