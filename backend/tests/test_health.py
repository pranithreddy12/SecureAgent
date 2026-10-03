from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import app


def test_health() -> None:
    res = TestClient(app).get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_allowlist_parsed_from_csv(monkeypatch) -> None:
    monkeypatch.setenv("TARGET_ALLOWLIST", " Example.com, ,juice-shop ")
    assert Settings().target_allowlist == ["example.com", "juice-shop"]
