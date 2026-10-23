import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import audits, auth, health, projects, targets
from app.core.config import get_settings
from app.core.database import get_sessionmaker
from app.services import audit_service, live_audit_service

logger = logging.getLogger("secureagent.api")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    try:
        async with get_sessionmaker()() as db:
            swept = await audit_service.fail_interrupted(db)
            swept += await live_audit_service.fail_interrupted(db)
        if swept:
            logger.warning("marked %d interrupted audit(s) as failed", swept)
    except Exception:  # noqa: BLE001 - never block startup on the sweep (e.g. DB not ready)
        logger.exception("startup audit sweep failed")
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="SecureAgent API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(audits.router, prefix="/api")
    app.include_router(projects.router, prefix="/api")
    app.include_router(targets.router, prefix="/api")
    return app


app = create_app()
