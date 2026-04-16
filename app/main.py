from __future__ import annotations
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from .config import settings
from .database import engine
from .models import Base  # noqa: F401
from .auth.router import router as auth_router
from .oauth.router import router as oauth_router
from .admin.router import router as admin_router

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Schema is managed by Alembic — run `alembic upgrade head` before starting
    logger.info("Base ID started — %s", settings.base_url)
    yield
    await engine.dispose()


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan,
              docs_url="/api/docs", redoc_url="/api/redoc")

app.include_router(auth_router)
app.include_router(oauth_router)
app.include_router(admin_router)


@app.get("/")
async def root():
    return RedirectResponse(url="/auth/login")


@app.get("/health")
async def health():
    return {"status": "ok", "service": settings.app_name}
