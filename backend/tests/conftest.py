import os

# Test configuration; must be set before app modules read settings.
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-chars")
