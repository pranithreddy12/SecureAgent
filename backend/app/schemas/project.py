"""Source project (the source-only counterpart of a target) request/response models."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.audit import AUTHORIZATION_STATEMENT


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    path: str = Field(min_length=1, max_length=1024)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v


class AuthorizeRequest(BaseModel):
    confirmed: bool


class ProjectAudit(BaseModel):
    exclude: list[str] = Field(default_factory=list, max_length=50)
    ai_review: bool = False

    @field_validator("exclude")
    @classmethod
    def _short(cls, v: list[str]) -> list[str]:
        if any(not p or len(p) > 200 for p in v):
            raise ValueError("exclude patterns must be 1-200 characters")
        return v


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    path: str
    description: str | None
    authorization_confirmed: bool
    authorization_timestamp: datetime | None
    created_at: datetime


class AuthorizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    confirmed: bool
    statement: str
    timestamp: datetime


class ProjectDetail(ProjectOut):
    authorization_statement: str = AUTHORIZATION_STATEMENT
    authorization_history: list[AuthorizationOut] = []
    audit_count: int = 0
