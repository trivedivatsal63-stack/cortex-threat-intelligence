# Multi-stage build for production optimization
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.12-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs reports data

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Default command (can be overridden)
CMD ["python", "main.py"]

# Labels for container metadata
LABEL org.opencontainers.image.title="Cyber Threat Intelligence Platform"
LABEL org.opencontainers.image.description="AI-powered cybersecurity threat intelligence collection and analysis platform"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/yourusername/cyber-threat-intel"
