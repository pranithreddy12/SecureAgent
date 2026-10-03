from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "demo_mode": settings.demo_mode,
        "llm_configured": bool(settings.llm_api_key),
    }
