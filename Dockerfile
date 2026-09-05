FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for supervisor and build tools (for cryptography/rust)
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    gcc \
    g++ \
    make \
    rustc \
    cargo \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements-merged.txt .
RUN pip install --no-cache-dir -r requirements-merged.txt

# Copy both application files
COPY vertbacon_api.py .
COPY signer_service.py .

# Copy supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose ports
EXPOSE 8000 8099

# Environment variables (override as needed)
ENV PORT=8000
ENV LOGLEVEL=INFO
ENV CODEWORDS_API_KEY=your_api_key
ENV CODEWORDS_RUNTIME_URI=redis://localhost:6379
ENV SIGNER_SECRET=vertbacon-prod-signer-2026
ENV APEX_API_BASE=https://omni.apex.exchange
ENV SIGNER_URL=http://localhost:8099

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]