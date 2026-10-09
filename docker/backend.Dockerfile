FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# Native libraries for WeasyPrint (PDF reports) + a font.
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Install the exact pinned set (backend/requirements.lock, generated on python:3.12-slim);
# requirements.txt documents the intended top-level dependencies.
COPY backend/requirements.txt backend/requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY backend/ .
RUN useradd --create-home appuser && mkdir -p /app/reports && chown appuser /app/reports
USER appuser

EXPOSE 8000
# Apply migrations, then serve. Single replica (ADR-005), so no migration race.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
