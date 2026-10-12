"""Source projects and their authorization / restrictions (ADR-016, phases 4-5)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.audits import get_launcher
from app.core.config import get_settings
from app.core.enums import AuditStatus
from app.models import SecurityAudit, SourceAuthorization, User
from app.services.audit_service import run_source_audit

pytestmark = pytest.mark.anyio

APP = "import hashlib\nhashlib.md5(b'x')\n"


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "workspace"
    for name in ("shop", "blog", "api"):
        (root / name).mkdir(parents=True)
        (root / name / "app.py").write_text(APP, encoding="utf-8")
    monkeypatch.setenv("SOURCE_ROOTS", str(root))
    get_settings.cache_clear()
    yield root
    get_settings.cache_clear()


@pytest.fixture
async def inline_runner(db_session: AsyncSession) -> AsyncIterator[None]:
    from app.main import app

    async def factory() -> Callable[[uuid.UUID], Awaitable[None]]:
        async def launch(audit_id: uuid.UUID) -> None:
            await run_source_audit(db_session, audit_id)

        return launch

    app.dependency_overrides[get_launcher] = factory
    yield
    app.dependency_overrides.pop(get_launcher, None)


async def login(client: AsyncClient, email: str) -> None:
    body = {"name": "Dev", "email": email, "password": "correct-horse-battery"}
    assert (await client.post("/api/auth/register", json=body)).status_code == 201
    res = await client.post("/api/auth/login", json={"email": email, "password": body["password"]})
    assert res.status_code == 200


async def make(client: AsyncClient, path: Path, name: str = "Shop") -> dict:
    res = await client.post("/api/projects", json={"name": name, "path": str(path)})
    assert res.status_code == 201, res.text
    return res.json()


async def test_auth_required(client: AsyncClient) -> None:
    assert (await client.get("/api/projects")).status_code == 401
    res = await client.post("/api/projects", json={"name": "x", "path": "/x"})
    assert res.status_code == 401


async def test_create_list_get_delete(
    client: AsyncClient, workspace: Path, inline_runner: None
) -> None:
    await login(client, "a@example.com")
    project = await make(client, workspace / "shop")
    assert project["authorization_confirmed"] is False
    assert Path(project["path"]) == (workspace / "shop").resolve()

    assert [p["id"] for p in (await client.get("/api/projects")).json()] == [project["id"]]
    detail = (await client.get(f"/api/projects/{project['id']}")).json()
    assert detail["audit_count"] == 0 and detail["authorization_history"] == []

    assert (await client.delete(f"/api/projects/{project['id']}")).status_code == 204
    assert (await client.get(f"/api/projects/{project['id']}")).status_code == 404


async def test_path_restrictions(client: AsyncClient, workspace: Path, tmp_path: Path) -> None:
    await login(client, "a@example.com")
    outside = tmp_path / "secrets"
    outside.mkdir()
    for bad in (outside, workspace / ".." / "secrets", workspace / "shop" / "app.py"):
        res = await client.post("/api/projects", json={"name": "x", "path": str(bad)})
        assert res.status_code == 400, bad
    assert (await client.get("/api/projects")).json() == []


async def test_disabled_without_source_roots(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SOURCE_ROOTS", "")
    get_settings.cache_clear()
    await login(client, "a@example.com")
    res = await client.post("/api/projects", json={"name": "x", "path": str(tmp_path)})
    assert res.status_code == 503
    get_settings.cache_clear()


async def test_duplicate_path_and_per_user_limit(
    client: AsyncClient, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MAX_TARGETS_PER_USER", "2")
    get_settings.cache_clear()
    await login(client, "a@example.com")
    await make(client, workspace / "shop", "one")
    dup = await client.post(
        "/api/projects", json={"name": "again", "path": str(workspace / "shop")}
    )
    assert dup.status_code == 409
    await make(client, workspace / "blog", "two")
    over = await client.post(
        "/api/projects", json={"name": "three", "path": str(workspace / "api")}
    )
    assert over.status_code == 409 and "limit" in over.json()["detail"].lower()
    get_settings.cache_clear()


async def test_audit_requires_a_current_authorization(
    client: AsyncClient, workspace: Path, inline_runner: None, db_session: AsyncSession
) -> None:
    await login(client, "a@example.com")
    pid = (await make(client, workspace / "shop"))["id"]

    blocked = await client.post(f"/api/projects/{pid}/audits", json={})
    assert blocked.status_code == 403

    assert (
        await client.post(f"/api/projects/{pid}/authorize", json={"confirmed": False})
    ).status_code == 400
    ok = await client.post(f"/api/projects/{pid}/authorize", json={"confirmed": True})
    assert ok.status_code == 200 and ok.json()["confirmed"] is True

    started = await client.post(f"/api/projects/{pid}/audits", json={})
    assert started.status_code == 202, started.text
    audit = (await client.get(f"/api/audits/{started.json()['id']}")).json()
    assert audit["status"] == "completed"
    assert audit["source_label"] == "Shop"
    row = await db_session.get(SecurityAudit, uuid.UUID(started.json()["id"]))
    assert str(row.source_project_id) == pid
    assert "authorized" in (row.authorization_statement or "")

    # revocation wins immediately
    assert (await client.post(f"/api/projects/{pid}/revoke")).status_code == 200
    assert (await client.post(f"/api/projects/{pid}/audits", json={})).status_code == 403

    history = (await client.get(f"/api/projects/{pid}")).json()["authorization_history"]
    assert [h["confirmed"] for h in history] == [False, True]  # append-only trail, newest first
    trail = (await db_session.scalars(select(SourceAuthorization))).all()
    assert len(trail) == 2

    listed = (await client.get(f"/api/projects/{pid}/audits")).json()
    assert [a["id"] for a in listed] == [started.json()["id"]]


async def test_owner_isolation(client: AsyncClient, workspace: Path, inline_runner: None) -> None:
    await login(client, "a@example.com")
    pid = (await make(client, workspace / "shop"))["id"]
    client.cookies.clear()
    await login(client, "b@example.com")
    for method, suffix in (
        ("get", ""),
        ("delete", ""),
        ("post", "/authorize"),
        ("post", "/revoke"),
        ("post", "/audits"),
        ("get", "/audits"),
    ):
        kwargs = {"json": {"confirmed": True} if suffix == "/authorize" else {}}
        if method in {"get", "delete"}:
            kwargs = {}
        res = await getattr(client, method)(f"/api/projects/{pid}{suffix}", **kwargs)
        assert res.status_code == 404, (method, suffix)
    assert (await client.get("/api/projects")).json() == []


async def test_concurrent_audit_limit(
    client: AsyncClient,
    workspace: Path,
    inline_runner: None,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "1")
    get_settings.cache_clear()
    await login(client, "a@example.com")
    pid = (await make(client, workspace / "shop"))["id"]
    await client.post(f"/api/projects/{pid}/authorize", json={"confirmed": True})
    user = await db_session.scalar(select(User))
    db_session.add(SecurityAudit(user_id=user.id, audit_type="source", status=AuditStatus.RUNNING))
    await db_session.flush()

    res = await client.post(f"/api/projects/{pid}/audits", json={})
    assert res.status_code == 429
    adhoc = await client.post(
        "/api/audits/source",
        json={"path": str(workspace / "blog"), "authorization_confirmed": True},
    )
    assert adhoc.status_code == 429
    get_settings.cache_clear()


async def test_path_is_reconfined_when_the_audit_starts(
    client: AsyncClient, workspace: Path, inline_runner: None, tmp_path: Path
) -> None:
    await login(client, "a@example.com")
    pid = (await make(client, workspace / "shop"))["id"]
    await client.post(f"/api/projects/{pid}/authorize", json={"confirmed": True})
    # The registered directory is replaced by a symlink pointing outside the allowed roots.
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    shop = workspace / "shop"
    for child in shop.iterdir():
        child.unlink()
    shop.rmdir()
    try:
        shop.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    res = await client.post(f"/api/projects/{pid}/audits", json={})
    assert res.status_code == 400 and "outside" in res.json()["detail"]


# ---------------------------------------------------------------- upload (ADR-019)


def _zip(entries: dict[str, str | bytes], *, symlink: str | None = None) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.create_system = 3
            info.external_attr = (0o120777) << 16
            zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


@pytest.fixture
def uploads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "uploads"
    monkeypatch.setenv("UPLOAD_DIR", str(root))
    monkeypatch.setenv("SOURCE_ROOTS", "")
    monkeypatch.setenv("MAX_UPLOAD_FILES", "20")
    monkeypatch.setenv("MAX_UPLOAD_UNPACKED_MB", "1")
    get_settings.cache_clear()
    yield root
    get_settings.cache_clear()


async def _upload(client: AsyncClient, body: bytes, name: str = "Zipped"):
    return await client.post(
        "/api/projects/upload",
        params={"name": name},
        content=body,
        headers={"content-type": "application/zip"},
    )


async def test_upload_creates_project_flattens_wrapper_and_audits(
    client: AsyncClient, uploads: Path, inline_runner: None
) -> None:
    await login(client, "u@example.com")
    res = await _upload(client, _zip({"proj-main/app.py": APP, "proj-main/pkg/x.py": "x = 1\n"}))
    assert res.status_code == 201, res.text
    project = res.json()
    assert project["path"] == "(uploaded archive)"  # the server location is not disclosed
    unpacked = [p for p in uploads.glob("*/*") if p.is_dir()]
    assert len(unpacked) == 1 and (unpacked[0] / "app.py").is_file()  # wrapper flattened
    path = unpacked[0]

    assert (await client.post(f"/api/projects/{project['id']}/audits", json={})).status_code == 403
    await client.post(f"/api/projects/{project['id']}/authorize", json={"confirmed": True})
    audit = (await client.post(f"/api/projects/{project['id']}/audits", json={})).json()
    done = (await client.get(f"/api/audits/{audit['id']}")).json()
    assert done["status"] == "completed" and done["total_findings"] >= 1

    assert (await client.delete(f"/api/projects/{project['id']}")).status_code == 204
    assert not path.exists()  # the unpacked code is deleted with the project


@pytest.mark.parametrize(
    "entries,kwargs",
    [
        ({"../evil.py": "x"}, {}),
        ({"/abs.py": "x"}, {}),
        ({r"a\..\..\evil.py": "x"}, {}),
        ({"ok.py": "x"}, {"symlink": "link"}),
        ({}, {}),
        ({"/".join(["d"] * 60) + "/x.py": "x"}, {}),
        ({"n" * 300 + ".py": "x"}, {}),
    ],
)
async def test_upload_rejects_hostile_archives(
    client: AsyncClient, uploads: Path, entries: dict, kwargs: dict
) -> None:
    await login(client, "u@example.com")
    res = await _upload(client, _zip(entries, **kwargs))
    assert res.status_code == 400, res.text
    assert (await client.get("/api/projects")).json() == []
    assert not list(uploads.rglob("*.py"))  # nothing left behind, nothing escaped
    assert not (uploads.parent / "evil.py").exists()


async def test_upload_limits_and_not_a_zip(client: AsyncClient, uploads: Path) -> None:
    await login(client, "u@example.com")
    assert (await _upload(client, b"not a zip")).status_code == 400
    bomb = _zip({"big.txt": "A" * (3 * 1024 * 1024)})  # ~3 KB compressed, 3 MB unpacked
    assert len(bomb) < 20_000
    assert (await _upload(client, bomb)).status_code == 400
    many = _zip({f"f{i}.py": "x = 1\n" for i in range(25)})
    assert (await _upload(client, many)).status_code == 400
    assert list(uploads.glob("*/*")) == []


async def test_upload_disabled_and_not_registrable_by_path(
    client: AsyncClient, uploads: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    await login(client, "u@example.com")
    project = (await _upload(client, _zip({"app.py": APP}))).json()
    # another registration of the uploaded path through the normal endpoint is refused
    monkeypatch.setenv("SOURCE_ROOTS", str(uploads))
    get_settings.cache_clear()
    res = await client.post("/api/projects", json={"name": "x", "path": project["path"]})
    assert res.status_code == 400
    monkeypatch.setenv("UPLOAD_DIR", "")
    get_settings.cache_clear()
    assert (await _upload(client, _zip({"app.py": APP}))).status_code == 503
