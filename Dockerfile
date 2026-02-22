# Stage 1: Build dependencies
FROM python:3.11-slim as builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt


# Stage 2: Final image
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIEM_DATA_DIR=/app/data \
    LOG_LEVEL=INFO

# Install gunicorn for production
RUN pip install --no-cache-dir gunicorn uvicorn

COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .
RUN pip install --no-cache-dir /wheels/*

# Copy application code
COPY . .

# Create data directories and set permissions
RUN mkdir -p /app/data/raw /app/data/normalized /app/data/aggregated /app/data/alerts /app/data/incidents /app/data/cmdb /app/data/simulator && \
    chmod -R 777 /app/data

# Create a non-root user
RUN adduser --disabled-password --gecos "" siemuser
USER siemuser

EXPOSE 8000

# Run with Gunicorn for better production stability
# Using $PORT environment variable if defined (standard for Render/Heroku)
CMD ["sh", "-c", "gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT:-8000}"]
