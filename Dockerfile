FROM python:3.11

WORKDIR /app

# Install system dependencies for cryptography and websockets
RUN apt-get update && apt-get install -y gcc g++ && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install core dependencies + both SDKs (apexpro + apexomni)
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
        ecdsa \
        mpmath \
        sympy \
        eth-account \
        python-multipart \
        apexpro \
        apexomni

# Test imports (do not break the build)
RUN python -c "from apexpro import zklink_sdk; print('✅ apexpro SDK ready')" 2>&1 || \
    echo "⚠️ apexpro SDK not available"
RUN python -c "from apexomni import HttpPrivateSign; print('✅ apexomni SDK ready')" 2>&1 || \
    echo "⚠️ apexomni SDK not available – falling back to pure Python ZK signing"

# Copy only the required application files
COPY signer_service.py silverveil_nutraider.py ./

# Environment variables (adjust as needed)
ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-prod-signer-2026

EXPOSE 8099

# Run the unified trading terminal (includes signer logic)
CMD ["python", "silverveil_nutraider.py"]