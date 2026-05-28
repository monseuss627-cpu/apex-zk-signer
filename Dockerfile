FROM python:3.11

WORKDIR /app

# Install Python dependencies from requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir ecdsa mpmath sympy eth-account

# Test import but don't fail the build (kept from original)
RUN python -c "from apexpro import zklink_sdk; print('OK')" 2>&1 || echo "SDK import failed at build - will retry at runtime"

# Copy both service files
COPY signer_service.py silverveil_backend.py .

# Environment variables (adjust as needed for silverveil_backend)
ENV PORT=8099
ENV SIGNER_SECRET=vertbacon-signer-key-change-me

EXPOSE 8099

# Run the main application backend
CMD ["python", "silverveil_backend.py"]