FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIEM_DATA_DIR=/app/data

# Create and set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . /app/

# Create data directories if they don't exist
RUN mkdir -p /app/data/raw /app/data/normalized /app/data/aggregated /app/data/alerts /app/data/incidents /app/data/cmdb

# Expose the API port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
