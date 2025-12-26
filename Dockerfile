# =============================================================================
# CI/CD Webhook Server - Production Dockerfile
# =============================================================================
# Multi-stage build for minimal image size and security
# Python 3.12 + Gunicorn + Non-root user

FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Production Stage
# =============================================================================

FROM python:3.12-slim AS production

LABEL maintainer="DevOps Team"
LABEL description="CI/CD Webhook Server"
LABEL version="1.0.0"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    docker.io \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application files
COPY app.py deploy.py config.yml ./

# Create non-root user for security
RUN groupadd -r webhook && \
    useradd -r -g webhook -d /app -s /sbin/nologin webhook && \
    chown -R webhook:webhook /app

# Switch to non-root user
USER webhook

# Environment variables with secure defaults
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV HOST=0.0.0.0
ENV PORT=5000
ENV SCRIPT_TIMEOUT=300
ENV LOG_LEVEL=INFO

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Run with Gunicorn (production WSGI server)
# --workers: Number of worker processes (2-4 x CPU cores)
# --timeout: Worker timeout in seconds
# --access-logfile: Log access to stdout
# --error-logfile: Log errors to stderr
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--timeout", "600", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "app:create_app()"]
