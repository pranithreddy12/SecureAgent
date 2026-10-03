"""Import every model so Base.metadata is complete (Alembic, tests)."""

from app.models.audit import AuditLog, ReconnaissanceResult, SecurityAudit
from app.models.base import Base
from app.models.finding import Vulnerability
from app.models.report import SecurityReport
from app.models.target import AuthorizationRecord, Target
from app.models.user import User

__all__ = [
    "AuditLog",
    "AuthorizationRecord",
    "Base",
    "ReconnaissanceResult",
    "SecurityAudit",
    "SecurityReport",
    "Target",
    "User",
    "Vulnerability",
]
