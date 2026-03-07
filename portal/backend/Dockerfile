# ============================================================
# Stage 1: Build / dependency install
# ============================================================
FROM python:3.12-slim AS builder

WORKDIR /app

# System packages needed for psycopg2-binary, pyzbar (libzbar), Pillow
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt


# ============================================================
# Stage 2: Runtime image
# ============================================================
FROM python:3.12-slim AS runtime

LABEL maintainer="SecureErase Pro <noreply@example.com>"
LABEL description="SecureErase Pro — Verification Portal Backend"

# Runtime system deps (libzbar for pyzbar, libpq for psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Migrations directory must be accessible for alembic upgrade head
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "modules.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
