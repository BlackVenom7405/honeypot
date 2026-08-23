FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir cryptography

# Copy codebase
COPY . .

# Ensure storage directories exist
RUN mkdir -p database logs uploads/quarantine

# Expose default ports
EXPOSE 443 8080
