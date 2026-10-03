import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import COOKIE_NAME, create_access_token, hash_password, verify_password
from app.models import User

pytestmark = pytest.mark.anyio

ALICE = {"name": "Alice", "email": "Alice@Example.com", "password": "correct-horse-battery"}


async def register(client: AsyncClient, **overrides) -> dict:
    res = await client.post("/api/auth/register", json={**ALICE, **overrides})
    assert res.status_code == 201, res.text
    return res.json()


async def login(client: AsyncClient, email=ALICE["email"], password=ALICE["password"]):
    return await client.post("/api/auth/login", json={"email": email, "password": password})


def test_password_hashing() -> None:
    h = hash_password("s3cret-password")
    assert h != "s3cret-password" and h.startswith("$argon2id$")
    assert verify_password("s3cret-password", h)
    assert not verify_password("wrong", h)
    assert not verify_password("anything", None)
    assert not verify_password("anything", "not-a-hash")


async def test_register_stores_hash_and_hides_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    body = await register(client)
    assert body["email"] == "alice@example.com"  # normalised
    assert body["role"] == "auditor"
    assert "password" not in str(body) and "hash" not in str(body)
    user = await db_session.scalar(select(User))
    assert user is not None and user.password_hash != ALICE["password"]


async def test_duplicate_email_case_insensitive(client: AsyncClient) -> None:
    await register(client)
    res = await client.post("/api/auth/register", json={**ALICE, "email": "ALICE@example.com"})
    assert res.status_code == 409


@pytest.mark.parametrize(
    "override",
    [{"password": "short"}, {"email": "not-an-email"}, {"name": "   "}, {"role": "admin"}],
)
async def test_register_validation(client: AsyncClient, override: dict) -> None:
    res = await client.post("/api/auth/register", json={**ALICE, **override})
    if "role" in override:  # extra field ignored: users cannot self-assign admin
        assert res.status_code == 201 and res.json()["role"] == "auditor"
    else:
        assert res.status_code == 422


async def test_login_sets_httponly_cookie_and_me_works(client: AsyncClient) -> None:
    await register(client)
    res = await login(client)
    assert res.status_code == 200
    cookie = res.headers["set-cookie"]
    assert f"{COOKIE_NAME}=" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    me = await client.get("/api/auth/me")  # cookie jar carries the token
    assert me.status_code == 200 and me.json()["email"] == "alice@example.com"


async def test_me_with_bearer_token(client: AsyncClient) -> None:
    await register(client)
    token = (await login(client)).json()["access_token"]
    client.cookies.clear()
    me = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200


async def test_login_failures_are_indistinguishable(client: AsyncClient) -> None:
    await register(client)
    wrong_pw = await login(client, password="wrong-password-123")
    unknown = await login(client, email="nobody@example.com")
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


def _forged(**claims) -> str:
    now = datetime.now(UTC)
    payload = {"sub": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(minutes=5)}
    payload.update(claims)
    return jwt.encode(payload, get_settings().secret_key, algorithm="HS256")


@pytest.mark.parametrize(
    "token",
    [
        "garbage",
        _forged(exp=datetime.now(UTC) - timedelta(seconds=1)),  # expired
        _forged(),  # valid signature, user does not exist
        jwt.encode({"sub": "x", "iat": 0, "exp": 9999999999}, "wrong-key" * 4, "HS256"),
        jwt.encode({"sub": str(uuid.uuid4())}, "", algorithm="none"),  # alg=none
    ],
)
async def test_bad_tokens_rejected(client: AsyncClient, token: str) -> None:
    res = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


async def test_me_requires_auth(client: AsyncClient) -> None:
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_logout_clears_cookie(client: AsyncClient) -> None:
    await register(client)
    await login(client)
    res = await client.post("/api/auth/logout")
    assert res.status_code == 204
    assert (
        f'{COOKIE_NAME}=""' in res.headers["set-cookie"] or "Max-Age=0" in res.headers["set-cookie"]
    )
    assert (await client.get("/api/auth/me")).status_code == 401


async def test_token_for_deleted_user_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user_id = uuid.UUID((await register(client))["id"])
    token = create_access_token(user_id)
    await db_session.delete(await db_session.get(User, user_id))
    await db_session.flush()
    res = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401
