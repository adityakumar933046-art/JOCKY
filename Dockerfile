# ==============================================================================
# JOCKY Central Forensic Platform - Multi-Stage Production Dockerfile
# Stage 1: Build the React 18 TypeScript frontend bundle
# Stage 2: Minimal hardened Python 3.12 runtime serving API and static assets
# ==============================================================================

# ------------------------------------------------------------------------------
# STAGE 1: Frontend Build
# ------------------------------------------------------------------------------
FROM node:22-alpine AS frontend-builder
WORKDIR /build

COPY frontend/package*.json ./
RUN npm ci --prefer-offline --no-audit

COPY frontend/ ./
RUN npm run build

# ------------------------------------------------------------------------------
# STAGE 2: Production Python Backend Runtime
# ------------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS production

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    ENVIRONMENT=production \
    DEBUG=false \
    PORT=8000

# Install minimal OS dependencies for network operations & security
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user for defensive security
RUN groupadd -g 10001 jocky && \
    useradd -u 10001 -g jocky -s /bin/bash -m jocky

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir psycopg2-binary gunicorn

# Copy application source code
COPY compiler/ ./compiler/
COPY runtime/ ./runtime/
COPY evidence/ ./evidence/
COPY detection/ ./detection/
COPY reports/ ./reports/
COPY server/ ./server/
COPY agent/ ./agent/
COPY forensics/ ./forensics/
COPY examples/ ./examples/
COPY scripts/init_production_db.py ./scripts/init_production_db.py
COPY cli.py .
COPY start.py .

# Copy compiled frontend from Stage 1 into /app/frontend/dist
COPY --from=frontend-builder /build/dist ./frontend/dist

# Secure file permissions
RUN chown -R jocky:jocky /app

USER jocky

EXPOSE 8000 10000

# Health check verifies the production health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT:-8000}/health || exit 1

# Launch production ASGI server via cloud bootloader
CMD ["python", "start.py"]
