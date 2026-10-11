"""Login throttling and the startup sweep for interrupted audits."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AuditStatus
from app.core.ratelimit import LoginLimiter, login_limiter
from app.models import SecurityAudit, User
from app.services.audit_service import fail_interrupted

pytestmark = pytest.mark.anyio


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_limiter_locks_after_max_failures_and_expires() -> None:
    clock = FakeClock()
    lim = LoginLimiter(max_failures=3, window=60, clock=clock)
    for _ in range(2):
        lim.record_failure("k")
    assert lim.retry_after("k") == 0
    lim.record_failure("k")
    assert 0 < lim.retry_after("k") <= 61
    clock.now += 61
    assert lim.retry_after("k") == 0


def test_limiter_reset_and_key_isolation() -> None:
    lim = LoginLimiter(max_failures=1, window=60, clock=FakeClock())
    lim.record_failure("a")
    assert lim.retry_after("a") > 0
    assert lim.retry_after("b") == 0
    lim.reset("a")
    assert lim.retry_after("a") == 0


def test_limiter_memory_is_bounded() -> None:
    lim = LoginLimiter(max_failures=5, window=60, clock=FakeClock(), max_keys=10)
    for i in range(100):
        lim.record_failure(f"k{i}")
    assert len(lim._failures) <= 10


async def test_login_is_throttled_after_repeated_failures(client: AsyncClient) -> None:
    login_limiter.reset("test|victim@example.com")
    login_limiter._failures.clear()
    body = {"name": "V", "email": "victim@example.com", "password": "correct-horse-battery"}
    assert (await client.post("/api/auth/register", json=body)).status_code == 201
    bad = {"email": "victim@example.com", "password": "wrong-password-123"}
    codes = [(await client.post("/api/auth/login", json=bad)).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5
    assert codes[5] == 429
    locked = await client.post("/api/auth/login", json=bad)
    assert locked.status_code == 429 and int(locked.headers["retry-after"]) > 0
    # even the correct password is refused while locked (no oracle)
    good = {"email": "victim@example.com", "password": body["password"]}
    assert (await client.post("/api/auth/login", json=good)).status_code == 429
    login_limiter._failures.clear()
    assert (await client.post("/api/auth/login", json=good)).status_code == 200


async def test_successful_login_clears_failures(client: AsyncClient) -> None:
    login_limiter._failures.clear()
    body = {"name": "V", "email": "ok@example.com", "password": "correct-horse-battery"}
    await client.post("/api/auth/register", json=body)
    bad = {"email": "ok@example.com", "password": "nope-nope-nope-nope"}
    for _ in range(3):
        await client.post("/api/auth/login", json=bad)
    good = {"email": "ok@example.com", "password": body["password"]}
    assert (await client.post("/api/auth/login", json=good)).status_code == 200
    for _ in range(4):  # counter restarted: 4 more failures still do not lock
        assert (await client.post("/api/auth/login", json=bad)).status_code == 401
    login_limiter._failures.clear()


async def test_fail_interrupted_marks_only_unfinished_source_audits(
    db_session: AsyncSession,
) -> None:
    user = User(name="U", email="u@example.com", password_hash="x")
    db_session.add(user)
    await db_session.flush()
    rows = {
        status: SecurityAudit(user_id=user.id, audit_type="source", status=status)
        for status in (
            AuditStatus.QUEUED,
            AuditStatus.RUNNING,
            AuditStatus.COMPLETED,
            AuditStatus.FAILED,
        )
    }
    db_session.add_all(rows.values())
    await db_session.flush()

    assert await fail_interrupted(db_session) == 2
    for status in (AuditStatus.QUEUED, AuditStatus.RUNNING):
        a = rows[status]
        await db_session.refresh(a)
        assert a.status is AuditStatus.FAILED and "restart" in (a.error_message or "")
    await db_session.refresh(rows[AuditStatus.COMPLETED])
    assert rows[AuditStatus.COMPLETED].status is AuditStatus.COMPLETED
    assert await fail_interrupted(db_session) == 0  # idempotent
