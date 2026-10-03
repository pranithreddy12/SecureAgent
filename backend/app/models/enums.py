from enum import StrEnum


class UserRole(StrEnum):
    ADMIN = "admin"
    AUDITOR = "auditor"


class TargetStatus(StrEnum):
    PENDING = "pending"
    VALIDATED = "validated"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class AuditStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    SUSPICIOUS = "suspicious"
    FALSE_POSITIVE = "false_positive"
    INFORMATIONAL = "informational"


class LogStatus(StrEnum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
