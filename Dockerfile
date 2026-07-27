FROM python:3.11-slim

LABEL maintainer="cors-scanner"
LABEL description="Fast CORS Misconfiguration Scanner"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY scanner.py .
COPY wordlists/ wordlists/

# Create output directory
RUN mkdir -p /app/output

# Set entrypoint
ENTRYPOINT ["python3", "scanner.py"]

# Default command (show help)
CMD ["--help"]
