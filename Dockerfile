FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY detrackify_guard.py .
COPY wsgi.py .
COPY gunicorn.conf.py .
COPY guard/ ./guard/
COPY extras/docker-entrypoint.sh .
COPY templates/ ./templates/
COPY resources/ ./resources/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash detrackify && \
    chown -R detrackify:detrackify /app

# Make entrypoint script executable
RUN chmod +x docker-entrypoint.sh

# Switch to non-root user
USER detrackify

# Expose the default port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:9090/guard/health', timeout=5)" || exit 1

# Use entrypoint script to handle environment variables
ENTRYPOINT ["./docker-entrypoint.sh"] 