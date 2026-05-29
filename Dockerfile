FROM python:3.11

WORKDIR /app

# Install system dependencies for cryptography and websockets
RUN apt-get update && apt-get install -y gcc g++ && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install core dependencies + all required packages for all three services
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
        ecdsa \
        mpmath \
        sympy \
        eth-account \
        python-multipart \
        apexpro \
        apexomni \
        supervisor

# Test imports (do not break the build)
RUN python -c "from apexpro import zklink_sdk; print('✅ apexpro SDK ready')" 2>&1 || \
    echo "⚠️ apexpro SDK not available"
RUN python -c "from apexomni import HttpPrivateSign; print('✅ apexomni SDK ready')" 2>&1 || \
    echo "⚠️ apexomni SDK not available – falling back to pure Python ZK signing"

# Copy all application source files
COPY signer_service.py silverveil_trading.py silverveil_backend.py supervisord.conf ./

# Environment variables (kept from original)
ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-prod-signer-2026
ENV RUN_MODE=supervisor

# Possible RUN_MODE values: trading, backend, signer, supervisor
# Supervisor runs both signer_service and silverveil_trading

EXPOSE 8099

# Entrypoint script to choose which service(s) to run
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]