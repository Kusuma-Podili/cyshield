# ==============================================================================
# CyberShield Enterprise - Production Multi-Stage Container Definition
# Hardened, non-root, privacy-first offline AI cybersecurity platform
# ==============================================================================

# Stage 1: Build & Dependency Wheel Builder
FROM python:3.10-slim-bullseye AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /install

# Install compile-time dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# Stage 2: Hardened Runtime Container
FROM python:3.10-slim-bullseye AS runner

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    APP_ENV=production

# Install runtime shared libraries only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged service user and group
RUN groupadd -g 10001 cybershield && \
    useradd -u 10001 -g cybershield -s /bin/bash -m -d /home/cybershield cybershield

WORKDIR /app

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source code and seed files
COPY --chown=cybershield:cybershield . /app

# Prepare storage directories with strict access permissions
RUN mkdir -p /app/data/models /app/data/backups /app/data/evidence && \
    chown -R cybershield:cybershield /app/data && \
    chmod -R 750 /app/data

USER cybershield

# Container liveness & readiness health probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/health || exit 1

EXPOSE 8000

ENTRYPOINT ["python", "run_cybershield.py"]
