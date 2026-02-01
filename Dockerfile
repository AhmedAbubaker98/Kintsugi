# Kintsugi - Multi-purpose Docker Image
# 
# This image can run as either the Web API or the Worker depending
# on the command passed at runtime.
#
# Usage:
#   Web API:  docker run kintsugi uvicorn app.main:app --host 0.0.0.0 --port 8000
#   Worker:   docker run kintsugi arq app.worker.WorkerSettings

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
# - git: Required for some Python packages and potential git operations
# - curl: For health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install Python dependencies first (for better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash kintsugi && \
    chown -R kintsugi:kintsugi /app
USER kintsugi

# Expose port for web service
EXPOSE 8000

# Health check for web service
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command (Web API)
# Override in docker-compose or CLI for Worker
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
