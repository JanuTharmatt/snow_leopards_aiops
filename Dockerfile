# Privacy-First Autonomous AIOps Platform — SNOW LEOPARDS
# SaaS Cloud Backend Service Dockerfile

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY saas_service/requirements.txt /app/saas_service/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/saas_service/requirements.txt

# Copy platform source tree
COPY . /app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "saas_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
