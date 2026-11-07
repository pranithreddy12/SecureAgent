FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# Native libraries for WeasyPrint (PDF reports) + a font.
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Nuclei (live pipeline), pinned and checksum-verified. Templates are fetched at build time so a
# scan does not download them on first use; rebuild the image to refresh them.
ARG NUCLEI_VERSION=3.4.2
ARG NUCLEI_SHA256=0dd53dfee3d6d0310705de13ac9ec88a10f4270d8d9068e502cbeb9257b42397
ADD https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip /tmp/nuclei.zip
RUN echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum -c - \
    && python -c "import zipfile; zipfile.ZipFile('/tmp/nuclei.zip').extract('nuclei', '/usr/local/bin')" \
    && chmod 755 /usr/local/bin/nuclei && rm /tmp/nuclei.zip

# Install the exact pinned set (backend/requirements.lock, generated on python:3.12-slim);
# requirements.txt documents the intended top-level dependencies.
COPY backend/requirements.txt backend/requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY backend/ .
RUN useradd --create-home appuser && mkdir -p /app/reports /app/uploads && chown appuser /app/reports /app/uploads
USER appuser
RUN nuclei -update-templates -silent || echo "nuclei templates not fetched; they download on first scan"

EXPOSE 8000
# Apply migrations, then serve. Single replica (ADR-005), so no migration race.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
