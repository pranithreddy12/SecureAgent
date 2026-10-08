import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.models.enums import TargetStatus

AUTHORIZATION_STATEMENT = (
    "I confirm that I am authorized to perform security testing against this target."
)


def _check_url(url: HttpUrl) -> HttpUrl:
    # Syntax only (http/https enforced by HttpUrl). Network-level safety validation is
    # a separate step (docs/security-model.md §2) and gates auditing, not creation.
    if url.username or url.password:
        raise ValueError("Credentials in the URL are not allowed")
    if len(str(url)) > 2048:
        raise ValueError("URL is too long")
    return url


def _check_prefixes(prefixes: list[str] | None) -> list[str] | None:
    if prefixes is None:
        return None
    for p in prefixes:
        if not p.startswith("/") or len(p) > 512:
            raise ValueError("Each path prefix must start with '/' (max 512 chars)")
    return sorted(set(prefixes))


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: HttpUrl
    description: str | None = Field(default=None, max_length=2000)
    path_prefixes: list[str] | None = Field(default=None, max_length=20)

    _url = field_validator("url")(_check_url)
    _prefixes = field_validator("path_prefixes")(_check_prefixes)


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    url: HttpUrl | None = None
    description: str | None = Field(default=None, max_length=2000)
    path_prefixes: list[str] | None = Field(default=None, max_length=20)

    @field_validator("url")
    @classmethod
    def _url(cls, v: HttpUrl | None) -> HttpUrl | None:
        return _check_url(v) if v is not None else None

    _prefixes = field_validator("path_prefixes")(_check_prefixes)


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    url: str
    description: str | None
    status: TargetStatus
    scope: dict[str, Any]
    validation_message: str | None
    authorization_confirmed: bool
    authorization_timestamp: datetime | None
    created_at: datetime
    updated_at: datetime


class AuthorizeRequest(BaseModel):
    confirmed: bool


class AuthorizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    user_id: uuid.UUID
    confirmed: bool
    statement: str
    timestamp: datetime
    scope: dict[str, Any]


class AuditReadiness(BaseModel):
    auditable: bool
    reasons: list[str]
