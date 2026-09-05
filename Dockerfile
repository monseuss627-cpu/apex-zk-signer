# Use a slim Python 3.11 base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for supervisor and any build tools (if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Copy combined requirements file
COPY requirements-merged.txt .
RUN pip install --no-cache-dir -r requirements-merged.txt

# Copy both application files
COPY vertbacon_api.py .
COPY signer_service.py .

# Copy supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose ports for both services
EXPOSE 8000 8099

# Environment variables (override as needed)
ENV PORT=8000
ENV LOGLEVEL=INFO
ENV CODEWORDS_API_KEY=your_api_key
ENV CODEWORDS_RUNTIME_URI=redis://localhost:6379   # adjust if Redis is separate
ENV SIGNER_SECRET=vertbacon-signer-key-change-me
ENV APEX_API_BASE=https://omni.apex.exchange
ENV SIGNER_URL=http://localhost:8099   # bot will talk to signer via localhost

# Run supervisor to manage both processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]